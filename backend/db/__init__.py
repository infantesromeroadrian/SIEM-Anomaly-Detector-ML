"""
Database layer for SIEM Anomaly Detector.

Provides SQLAlchemy models, connection management, and CRUD operations.
"""

from __future__ import annotations

from backend.db.models import Anomaly, Log, Feedback, Alert
from backend.db.database import get_db, init_db, close_db

__all__ = [
    "Anomaly",
    "Log",
    "Feedback",
    "Alert",
    "get_db",
    "init_db",
    "close_db",
]
