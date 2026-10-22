import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from app.config import CONFIG_PATH
from app.deps import require_login
from app.services import sources

# Names the devices: cookie login only. The change is written to sources.yml.
router = APIRouter(prefix="/sources", dependencies=[Depends(require_login)])
logger = logging.getLogger("loglook")


def _apply(request: Request, user, saved: str, change, *args) -> RedirectResponse:
    try:
        change(*args)
    except sources.ConfigError as exc:
        request.session["sources_error"] = str(exc)[:300]  # the session is a cookie: keep it small
    except OSError as exc:
        request.session["sources_error"] = f"Could not write {CONFIG_PATH}: {exc.strerror}. The Config folder must be mounted writable, as a folder rather than a single file."
    else:
        request.session["sources_ok"] = saved
        logger.info("admin %s: %s", user.username, saved)
    return RedirectResponse("/sources", status_code=303)


@router.post("/add")
def add_source(request: Request, ip: str = Form(...), name: str = Form(...), quiet_after: str = Form(""), user=Depends(require_login)):
    return _apply(request, user, f"Added {name.strip()} ({ip.strip()}).", sources.add, ip, name, quiet_after)


@router.post("/timezone")
def set_timezone(request: Request, tz: str = Form(...), user=Depends(require_login)):
    return _apply(request, user, f"Timezone is now {tz.strip()}.", sources.set_timezone, tz)


@router.post("/{ip}/update")
def update_source(request: Request, ip: str, name: str = Form(...), quiet_after: str = Form(""), user=Depends(require_login)):
    return _apply(request, user, f"Saved {name.strip()} ({ip}).", sources.update, ip, name, quiet_after)


@router.post("/{ip}/remove")
def remove_source(request: Request, ip: str, user=Depends(require_login)):
    return _apply(request, user, f"Removed {ip}.", sources.remove, ip)
