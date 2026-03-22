"""
Database engine and session factory.
Uses SQLite stored at <backend_root>/websecuity.db
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os

# Place the DB file next to main.py
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'websecuity.db')}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # required for SQLite + FastAPI
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db():
    """Create all tables if they don't exist yet."""
    from database import models  # noqa: F401  — import ensures models are registered
    Base.metadata.create_all(bind=engine)
