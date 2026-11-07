"""
Database layer for SIEM Anomaly Detector.

Provides SQLAlchemy models, connection management, and CRUD operations.
"""

from __future__ import annotations

from backend.db.database import close_db, get_db, init_db
from backend.db.models import Alert, Anomaly, Feedback, Log

__all__ = [
    "Anomaly",
    "Log",
    "Feedback",
    "Alert",
    "get_db",
    "init_db",
    "close_db",
]
