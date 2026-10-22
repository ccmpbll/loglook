from urllib.parse import quote

from fastapi import HTTPException, Request

from app.auth import current_user
from app.models import ApiToken
from app.services import tokens


def require_login(request: Request):
    user = current_user(request)
    if user is None:
        # A page opened from a link comes back to itself after signing in.
        dest = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        back = f"/login?next={quote(dest, safe='')}" if request.method == "GET" and dest != "/" else "/login"
        raise HTTPException(status_code=303, headers={"Location": back})
    return user


def require_token(request: Request) -> ApiToken:
    """Bearer-token auth for /v1. Separate from the cookie login on purpose: a token can never open
    an admin page and a logged-in browser is not accepted here. The caller only ever sees a generic
    401; the reason is left on request.state for the access log."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        request.state.token_name, request.state.reason = None, "missing bearer token"
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    row, reason = tokens.authenticate(token)
    request.state.token_name, request.state.reason = (row.name if row else None), reason
    if reason:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return row
