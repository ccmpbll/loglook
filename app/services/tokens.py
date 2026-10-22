import hashlib
import re
import secrets
from datetime import timedelta

from sqlmodel import Session, delete, select

from app.database import engine
from app.models import ApiToken, utcnow
from app.services import clock

TOKEN_PREFIX = "loglook_"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
MAX_EXPIRY_DAYS = 3650
LAST_USED_REFRESH = timedelta(minutes=1)


def hash_token(token: str) -> str:
    # 256 bits of randomness, so a plain sha256 is enough (nothing to brute-force), and it lets
    # us look a token up by its hash instead of scanning and comparing.
    return hashlib.sha256(token.encode()).hexdigest()


def create(name: str, note: str = "", expires_days: int | None = None) -> tuple[ApiToken, str]:
    """Create a token and return it with its plaintext (the only time the plaintext exists here)."""
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("Name must be 1-40 characters: letters, digits, '.', '_' or '-'.")
    if expires_days is not None and not 1 <= expires_days <= MAX_EXPIRY_DAYS:
        raise ValueError(f"Expiry must be between 1 and {MAX_EXPIRY_DAYS} days.")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with Session(engine) as session:
        if session.exec(select(ApiToken).where(ApiToken.name == name)).first():
            raise ValueError(f"A token named {name!r} already exists.")
        row = ApiToken(
            name=name,
            note=note.strip()[:200],
            token_hash=hash_token(token),
            expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row, token


def authenticate(token: str) -> tuple[ApiToken | None, str]:
    """Resolve a bearer token to an enabled, unexpired token row. Returns (row, "") on success or
    (row or None, reason): the reason is for the log only and is never sent to the caller."""
    with Session(engine) as session:
        row = session.exec(select(ApiToken).where(ApiToken.token_hash == hash_token(token))).first()
        if row is None:
            return None, "unknown token"
        if not row.enabled:
            return row, "token disabled"
        now = clock.now().replace(tzinfo=None)  # SQLite hands datetimes back naive; they are UTC
        if row.expires_at is not None and row.expires_at <= now:
            return row, "token expired"
        # Not on every request: that would be a write per call.
        if row.last_used_at is None or now - row.last_used_at > LAST_USED_REFRESH:
            row.last_used_at = now
            session.add(row)
            session.commit()
            session.refresh(row)
        return row, ""


def list_all() -> list[ApiToken]:
    with Session(engine) as session:
        return list(session.exec(select(ApiToken).order_by(ApiToken.name)).all())


def toggle(token_id: int) -> None:
    with Session(engine) as session:
        row = session.get(ApiToken, token_id)
        if row is not None:
            row.enabled = not row.enabled
            session.add(row)
            session.commit()


def delete_token(token_id: int) -> None:
    with Session(engine) as session:
        session.exec(delete(ApiToken).where(ApiToken.id == token_id))
        session.commit()
