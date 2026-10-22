import math
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.deps import require_login
from app.services import query, sources
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])

VIEWS = ("lines", "top", "count")
WINDOWS = ((1 / 12, "5 minutes"), (0.25, "15 minutes"), (0.5, "30 minutes"), (1, "1 hour"), (2, "2 hours"), (6, "6 hours"), (12, "12 hours"), (24, "24 hours"), (72, "3 days"), (168, "7 days"), (336, "14 days"))
ZONES = sorted(available_timezones())  # for the timezone box on the Sources page


@router.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/logs", status_code=303)


@router.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request):
    config, error = sources.get_config()
    ctx = {"error": error, "statuses": sources.all_statuses(config) if config else [], "tz": config.tz.key if config else sources.DEFAULT_TZ, "zones": ZONES, "flash_error": request.session.pop("sources_error", ""), "flash_ok": request.session.pop("sources_ok", "")}
    return templates.TemplateResponse(request, "sources.html", ctx)


@router.get("/logs", response_class=HTMLResponse)
def logs_page(
    request: Request,
    source: str = "",
    view: str = "lines",
    hours: float = 24,
    ago: float = 0,
    q: str = "",
    include: str = "",
    exclude: str = "",
    pattern: str = "",
    limit: int = 200,
):
    """The log viewer: the same queries the API offers, as a page. It is a GET form, so a search is a link."""
    config, config_error = sources.get_config()
    ctx = {"config_error": config_error, "view": view if view in VIEWS else "lines", "hours": hours, "ago": ago, "q": q, "include": include, "exclude": exclude, "pattern": pattern, "limit": limit, "windows": WINDOWS, "names": [], "source": source, "result": None, "error": None}
    if config is None:
        return templates.TemplateResponse(request, "logs.html", ctx)
    ctx["names"] = [s.name for s in config.sources.values()]
    src = config.by_name(source) or (next(iter(config.sources.values())) if config.sources else None)
    if src is None:
        return templates.TemplateResponse(request, "logs.html", ctx)
    ctx["source"] = src.name
    hours = min(max(hours, query.MIN_HOURS), query.MAX_HOURS) if math.isfinite(hours) else 24
    ago = min(max(ago, 0), query.MAX_AGO) if math.isfinite(ago) else 0
    ctx["hours"], ctx["ago"] = hours, ago
    files = sources.discover().get(src.ip, [])
    try:
        flt = query.Filter(q, include, exclude)
        if ctx["view"] == "lines":
            ctx["result"] = query.lines(config, src.name, files, hours, ago, flt, limit)
        elif ctx["view"] == "top":
            ctx["result"] = query.top(config, src.name, files, hours, ago, flt, 50)
        else:
            ctx["result"] = query.count(config, src.name, files, hours, ago, flt, pattern, 50) if pattern else None
    except query.QueryError as exc:
        ctx["error"] = str(exc)
    return templates.TemplateResponse(request, "logs.html", ctx, status_code=400 if ctx["error"] else 200)
