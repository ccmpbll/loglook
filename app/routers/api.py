from fastapi import APIRouter, Depends, HTTPException, Query

from app.config import VERSION
from app.deps import require_token
from app.services import clock, dockerlogs, query, sources

# Read-only JSON for callers with a token (the nightly sweep, Claude). Nothing here changes anything.
router = APIRouter(prefix="/v1", dependencies=[Depends(require_token)])

Hours = Query(24.0, ge=query.MIN_HOURS, le=query.MAX_HOURS, description="how long the window is, in hours")
Ago = Query(0.0, ge=0, le=query.MAX_AGO, description="how many hours before now the window ends")


def config_or_503():
    config, error = sources.get_config()
    if config is None:
        raise HTTPException(503, f"sources.yml is not usable: {error}")
    return config, error


def resolve(name: str):
    """The config, the source and its files; 404 for a name that is nothing we read."""
    config, _ = config_or_503()
    docker = dockerlogs.containers() if name.startswith(dockerlogs.PREFIX) else None
    source, files = sources.lookup(config, name, docker)
    if source is None:
        if docker and docker[1]:  # Docker could not be asked: not the same as "no such container", so a caller can retry
            raise HTTPException(502, docker[1])
        raise HTTPException(404, f"No source named {name!r}")
    return config, source, files


def run(fn, *args):
    try:
        return fn(*args)
    except query.QueryError as exc:
        raise HTTPException(400, str(exc)) from None
    except dockerlogs.DockerError as exc:  # Docker, not the request, is the problem: 502, so a caller can retry
        raise HTTPException(502, str(exc)) from None


@router.get("/health")
def health():
    config, error = sources.get_config()
    docker_error = dockerlogs.containers()[1]  # "" when Docker is off or fine
    return {"status": "ok" if config and not error and not docker_error else "degraded", "version": VERSION, "config_error": error or None, "docker_error": docker_error or None, "sources": len(config.sources) if config else 0, "time": clock.now().isoformat(timespec="seconds")}


@router.get("/sources")
def list_sources():
    """Every syslog source with a file in the log folder or an entry in sources.yml: when it last wrote, how much. Containers are listed apart."""
    config, error = config_or_503()
    statuses = sources.all_statuses(config)
    found, docker_error = dockerlogs.containers()
    containers = [{"source": c.name, "container": c.container, "id": c.id[:12], "state": c.state, "status": c.status} for c in found]
    return {"config_error": error or None, "docker_error": docker_error or None, "quiet": [s["name"] for s in statuses if s["quiet"]], "unmapped": [s["ip"] for s in statuses if not s["mapped"]], "sources": statuses, "containers": containers}


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
