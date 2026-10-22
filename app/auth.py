import hashlib
from typing import Optional

import bcrypt
from fastapi import Request
from sqlmodel import Session, select

from app.database import engine
from app.models import User


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def _fingerprint(user: User) -> str:
    return hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]


def sign_in(request: Request, user: User) -> None:
    """Start a session. It carries a fingerprint of the password hash, so changing the password
    ends every other session (a signed cookie cannot be revoked any other way)."""
    request.session["user_id"] = user.id
    request.session["pw"] = _fingerprint(user)


def any_user_exists() -> bool:
    with Session(engine) as session:
        return session.exec(select(User)).first() is not None


def get_user_by_username(username: str) -> Optional[User]:
    with Session(engine) as session:
        return session.exec(select(User).where(User.username == username)).first()


def create_user(username: str, password: str) -> User:
    with Session(engine) as session:
        user = User(username=username, password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def current_user(request: Request) -> Optional[User]:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    with Session(engine) as session:
        user = session.get(User, user_id)
    return user if user and request.session.get("pw") == _fingerprint(user) else None
