"""
SQLAlchemy ORM models: User and ScanResult.
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanResult", back_populates="owner", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    target_url = Column(String(512), nullable=False)
    modules_run = Column(Text, nullable=True)   # JSON-encoded list e.g. '["sqli","xss"]'
    result_json = Column(Text, nullable=True)   # full scan result JSON
    risk_level = Column(String(20), nullable=True)  # critical / high / medium / low / info
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    scan_duration = Column(Integer, nullable=True)  # seconds
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="scans")
