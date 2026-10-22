from fastapi import APIRouter, Depends, HTTPException, Query

from app.config import VERSION
from app.deps import require_token
from app.services import clock, query, sources

# Read-only JSON for callers with a token (the nightly sweep, Claude). Nothing here changes anything.
router = APIRouter(prefix="/v1", dependencies=[Depends(require_token)])

Hours = Query(24.0, ge=0.25, le=query.MAX_HOURS, description="how long the window is, in hours")
Ago = Query(0.0, ge=0, le=query.MAX_AGO, description="how many hours before now the window ends")


def config_or_503():
    config, error = sources.get_config()
    if config is None:
        raise HTTPException(503, f"sources.yml is not usable: {error}")
    return config, error


def resolve(name: str):
    """The config, the named source and its files; 404 for a name that is not configured."""
    config, _ = config_or_503()
    source = config.by_name(name)
    if source is None:
        raise HTTPException(404, f"No source named {name!r}")
    return config, source, sources.discover().get(source.ip, [])


def run(fn, *args):
    try:
        return fn(*args)
    except query.QueryError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/health")
def health():
    config, error = sources.get_config()
    return {"status": "ok" if config and not error else "degraded", "version": VERSION, "config_error": error or None, "sources": len(config.sources) if config else 0, "time": clock.now().isoformat(timespec="seconds")}


@router.get("/sources")
def list_sources():
    """Every source with a file in the log folder or an entry in sources.yml: when it last wrote, how much."""
    config, error = config_or_503()
    statuses = sources.all_statuses(config)
    return {"config_error": error or None, "quiet": [s["name"] for s in statuses if s["quiet"]], "unmapped": [s["ip"] for s in statuses if not s["mapped"]], "sources": statuses}


@router.get("/lines")
def lines(source: str, hours: float = Hours, ago: float = Ago, q: str = "", include: str = "", exclude: str = "", limit: int = Query(100, ge=1, le=query.LINES_MAX)):
    config, src, files = resolve(source)
    return run(lambda: query.lines(config, src.name, files, hours, ago, query.Filter(q, include, exclude), limit))


@router.get("/top")
def top(source: str, hours: float = Hours, ago: float = Ago, q: str = "", include: str = "", exclude: str = "", top: int = Query(15, ge=1, le=100)):
    config, src, files = resolve(source)
    return run(lambda: query.top(config, src.name, files, hours, ago, query.Filter(q, include, exclude), top))


@router.get("/count")
def count(source: str, pattern: str, hours: float = Hours, ago: float = Ago, q: str = "", include: str = "", exclude: str = "", top: int = Query(15, ge=1, le=100)):
    config, src, files = resolve(source)
    return run(lambda: query.count(config, src.name, files, hours, ago, query.Filter(q, include, exclude), pattern, top))
