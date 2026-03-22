"""
FastAPI dependencies shared across routers.
"""

from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database.db import SessionLocal
from database.models import User
from core.security import decode_access_token

# ── DB Session ────────────────────────────────────────────────────────────────
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Auth Bearer scheme ────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)


def _get_user_from_token(
    credentials: Optional[HTTPAuthorizationCredentials],
    db: Session,
) -> Optional[User]:
    if credentials is None:
        return None
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        return None
    user_id = payload.get("sub")
    if user_id is None:
        return None
    try:
        return db.query(User).filter(User.id == int(user_id), User.is_active == True).first()
    except (ValueError, TypeError):
        return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Require a valid JWT. Raises 401 if missing or invalid."""
    user = _get_user_from_token(credentials, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated or token expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Return User if JWT is valid, otherwise None (no error)."""
    return _get_user_from_token(credentials, db)
