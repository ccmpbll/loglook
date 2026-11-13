import math
from urllib.parse import urlencode
from zoneinfo import available_timezones

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.deps import require_login
from app.services import dockerlogs, query, sources
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])

VIEWS = ("lines", "top", "count")
WINDOWS = ((1 / 12, "5 minutes"), (0.25, "15 minutes"), (0.5, "30 minutes"), (1, "1 hour"), (2, "2 hours"), (6, "6 hours"), (12, "12 hours"), (24, "24 hours"), (72, "3 days"), (168, "7 days"), (336, "14 days"))
ZONES = sorted(available_timezones())  # for the timezone box on the Sources page


VIEW_LABELS = (("lines", "Lines"), ("top", "Top patterns"), ("count", "Count by value"))


def _logs_response(request: Request, ctx: dict, status_code: int = 200):
    """The Logs page. Its three views are tabs, and each tab keeps the search you have typed."""
    keep = {k: ctx[k] for k in ("source", "hours", "ago", "q", "include", "exclude", "pattern", "limit") if ctx[k] not in ("", None)}
    ctx["tabs"] = [(v, label, "/logs?" + urlencode({**keep, "view": v})) for v, label in VIEW_LABELS]
    return templates.TemplateResponse(request, "logs.html", ctx, status_code=status_code)


@router.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/logs", status_code=303)


@router.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request):
    config, error = sources.get_config()
    containers, docker_error = dockerlogs.containers()
    ctx = {"containers": containers, "docker_error": docker_error, "error": error, "statuses": sources.all_statuses(config) if config else [], "tz": config.tz.key if config else sources.DEFAULT_TZ, "zones": ZONES, "flash_error": request.session.pop("sources_error", ""), "flash_ok": request.session.pop("sources_ok", "")}
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
        return _logs_response(request, ctx)
    docker = dockerlogs.containers()
    ctx["names"] = sources.pickable(config, docker[0])
    src, files = sources.lookup(config, source, docker)
    if src is None and source.startswith(dockerlogs.PREFIX):  # say why, rather than showing some other source's lines
        ctx["error"] = docker[1] or f"No container named {source[len(dockerlogs.PREFIX):]!r}."
        return _logs_response(request, ctx, 502 if docker[1] else 404)
    if src is None and ctx["names"]:  # an unknown name shows the first source instead
        src, files = sources.lookup(config, ctx["names"][0], docker)
    if src is None:
        return _logs_response(request, ctx)
    ctx["source"] = src.name
    hours = min(max(hours, query.MIN_HOURS), query.MAX_HOURS) if math.isfinite(hours) else 24
    ago = min(max(ago, 0), query.MAX_AGO) if math.isfinite(ago) else 0
    ctx["hours"], ctx["ago"] = hours, ago
    status = 200
    try:
        flt = query.Filter(q, include, exclude)
        if ctx["view"] == "lines":
            ctx["result"] = query.lines(config, src.name, files, hours, ago, flt, limit)
        elif ctx["view"] == "top":
            ctx["result"] = query.top(config, src.name, files, hours, ago, flt, 50)
        else:
            ctx["result"] = query.count(config, src.name, files, hours, ago, flt, pattern, 50) if pattern else None
    except query.QueryError as exc:
        ctx["error"], status = str(exc), 400
    except dockerlogs.DockerError as exc:
        ctx["error"], status = str(exc), 502
    return _logs_response(request, ctx, status)
