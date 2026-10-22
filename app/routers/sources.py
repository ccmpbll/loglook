import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from app.auth import current_user
from app.config import CONFIG_PATH
from app.deps import require_login
from app.services import sources

# Names the devices: cookie login only. The change is written to sources.yml.
router = APIRouter(prefix="/sources", dependencies=[Depends(require_login)])
logger = logging.getLogger("loglook")


def _apply(request: Request, saved: str, change, *args) -> RedirectResponse:
    try:
        change(*args)
    except sources.ConfigError as exc:
        request.session["sources_error"] = str(exc)
    except OSError as exc:
        request.session["sources_error"] = f"Could not write {CONFIG_PATH}: {exc.strerror}. Is the Config folder writable?"
    else:
        request.session["sources_ok"] = saved
        logger.info("admin %s: %s", current_user(request).username, saved)
    return RedirectResponse("/sources", status_code=303)


@router.post("/add")
def add_source(request: Request, ip: str = Form(...), name: str = Form(...), quiet_after: str = Form("")):
    return _apply(request, f"Added {name.strip()} ({ip.strip()}).", sources.add, ip, name, quiet_after)


@router.post("/timezone")
def set_timezone(request: Request, tz: str = Form(...)):
    return _apply(request, f"Timezone is now {tz.strip()}.", sources.set_timezone, tz)


@router.post("/{ip}/update")
def update_source(request: Request, ip: str, name: str = Form(...), quiet_after: str = Form("")):
    return _apply(request, f"Saved {name.strip()} ({ip}).", sources.update, ip, name, quiet_after)


@router.post("/{ip}/remove")
def remove_source(request: Request, ip: str):
    return _apply(request, f"Removed {ip}.", sources.remove, ip)
