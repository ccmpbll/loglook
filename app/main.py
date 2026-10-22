import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import SECRET_KEY, SECURE_COOKIES
from app.database import init_db
from app.routers import api, auth, pages, tokens

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("loglook")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="loglook", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def log_api(request: Request, call_next):
    """One line per /v1 request: which token, what, and the status actually returned."""
    if not request.url.path.startswith("/v1"):
        return await call_next(request)
    started, status = time.monotonic(), 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        name = getattr(request.state, "token_name", None) or "-"
        reason = getattr(request.state, "reason", "")
        logger.info("api token=%s %s %s -> %s in %.0f ms%s", name, request.method, request.url.path, status, (time.monotonic() - started) * 1000, f" ({reason})" if reason else "")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=SECURE_COOKIES)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(api.router)
app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(tokens.router)
