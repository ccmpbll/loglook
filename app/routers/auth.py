from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session

from app.auth import any_user_exists, create_user, current_user, get_user_by_username, hash_password, verify_password
from app.database import engine
from app.deps import require_login
from app.models import User
from app.templating import templates

router = APIRouter()

MIN_PASSWORD = 8


def _safe_next(value: str) -> str:
    """Where to go after signing in: a path on this site, never another site."""
    return value if value.startswith("/") and not value.startswith(("//", "/\\")) and value.isprintable() else "/"


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    if any_user_exists():
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", {"error": None})


@router.post("/setup", response_class=HTMLResponse)
def setup_submit(request: Request, username: str = Form(...), password: str = Form(...), password_confirm: str = Form(...)):
    if any_user_exists():
        return RedirectResponse("/login", status_code=303)
    error = None
    if not username.strip():
        error = "Enter a username."
    elif len(password) < MIN_PASSWORD:
        error = f"Use at least {MIN_PASSWORD} characters."
    elif password != password_confirm:
        error = "Passwords do not match."
    if error:
        return templates.TemplateResponse(request, "setup.html", {"error": error}, status_code=400)
    user = create_user(username.strip(), password)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = ""):
    if not any_user_exists():
        return RedirectResponse("/setup", status_code=303)
    if current_user(request):
        return RedirectResponse(_safe_next(next), status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None, "next": _safe_next(next)})


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("")):
    user = get_user_by_username(username.strip())
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid username or password.", "next": _safe_next(next)}, status_code=400)
    request.session["user_id"] = user.id
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user=Depends(require_login)):
    return templates.TemplateResponse(request, "account.html", {"error": request.session.pop("flash_error", ""), "ok": request.session.pop("flash_ok", "")})


@router.post("/account/password")
def change_password(request: Request, current_password: str = Form(...), new_password: str = Form(...), new_password_confirm: str = Form(...), user=Depends(require_login)):
    if not verify_password(current_password, user.password_hash):
        request.session["flash_error"] = "Current password is incorrect."
    elif len(new_password) < MIN_PASSWORD:
        request.session["flash_error"] = f"Use at least {MIN_PASSWORD} characters."
    elif new_password != new_password_confirm:
        request.session["flash_error"] = "New passwords do not match."
    else:
        with Session(engine) as session:
            row = session.get(User, user.id)
            row.password_hash = hash_password(new_password)
            session.add(row)
            session.commit()
        request.session["flash_ok"] = "Password updated."
    return RedirectResponse("/account", status_code=303)
