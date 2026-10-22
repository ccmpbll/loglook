from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.deps import require_login
from app.services import tokens
from app.templating import templates

# Admin side of the API tokens: cookie login only. A token can never open this page.
router = APIRouter(dependencies=[Depends(require_login)])


def _page(request: Request, error: str | None = None, new_token: tuple[str, str] | None = None):
    return templates.TemplateResponse(
        request,
        "tokens.html",
        {"tokens": tokens.list_all(), "error": error, "new_token": new_token},
        status_code=400 if error else 200,
        # The page holding a plaintext token must not be kept by a browser or proxy cache.
        headers={"Cache-Control": "no-store"} if new_token else None,
    )


@router.get("/tokens", response_class=HTMLResponse)
def tokens_page(request: Request):
    return _page(request)


@router.post("/tokens", response_class=HTMLResponse)
def create_token(request: Request, name: str = Form(...), note: str = Form(""), expires_days: str = Form(""), user=Depends(require_login)):
    try:
        days = int(expires_days) if expires_days.strip() else None
        row, token = tokens.create(name, note, days)
    except ValueError as exc:
        text = str(exc)
        return _page(request, error="Expiry must be a whole number of days." if text.startswith("invalid literal") else text)
    tokens.admin_audit(user.username, "create token", f"{row.name}" + (f", expires in {days} days" if days else ""))
    # Rendered directly (not redirected) so the token is shown once and never ends up in a URL or history.
    return _page(request, new_token=(row.name, token))


@router.post("/tokens/{token_id}/toggle")
def toggle_token(token_id: int, user=Depends(require_login)):
    tokens.toggle(token_id)
    tokens.admin_audit(user.username, "toggle token", f"token id {token_id}")
    return RedirectResponse("/tokens", status_code=303)


@router.post("/tokens/{token_id}/delete")
def delete_token(token_id: int, user=Depends(require_login)):
    tokens.delete_token(token_id)
    tokens.admin_audit(user.username, "delete token", f"token id {token_id}")
    return RedirectResponse("/tokens", status_code=303)
