from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)


class ApiToken(SQLModel, table=True):
    """A caller of /v1 (the nightly sweep, Claude). Only the sha256 of the token is stored; the
    token itself is shown once, when it is created. Every token is read-only: loglook has no
    endpoint that changes anything."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    token_hash: str = Field(unique=True, index=True)
    note: str = ""
    enabled: bool = True
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = None


class AdminAudit(SQLModel, table=True):
    """Changes made on the Tokens page, kept apart from anything an API caller can write."""

    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow)
    admin: str = ""
    action: str = ""
    detail: str = ""
