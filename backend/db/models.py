"""
SQLAlchemy models for SIEM Anomaly Detector.

Models:
- Anomaly: Detected anomalies
- Log: Processed logs
- Feedback: User feedback (false positives/negatives)
- Alert: Generated alerts
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Anomaly(Base):
    """
    Detected anomaly record.

    Stores ML model predictions and analysis results.
    """

    __tablename__ = "anomalies"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    log_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Source information
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    destination_port: Mapped[int | None] = mapped_column(Integer)

    # User/Event information
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # ML Prediction
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium, low, normal
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high

    # Model scores (individual)
    isolation_forest_score: Mapped[float] = mapped_column(Float, nullable=False)
    dbscan_score: Mapped[float] = mapped_column(Float, nullable=False)
    gmm_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Features (JSON)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Reasons (JSON array)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    # Action
    recommended_action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # BLOCK_IP, REQUIRE_MFA, etc.
    action_taken: Mapped[str | None] = mapped_column(String(50))
    action_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Raw log
    raw_log: Mapped[str] = mapped_column(Text, nullable=False)
    log_source: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # syslog, nginx, auth, firewall

    # Processing
    processing_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Status
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    false_positive: Mapped[bool | None] = mapped_column(Boolean)

    # Relationships
    feedback: Mapped[list["Feedback"]] = relationship(
        "Feedback", back_populates="anomaly", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert", back_populates="anomaly", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("idx_anomaly_created_at", "created_at"),
        Index("idx_anomaly_risk_score", "risk_score"),
        Index("idx_anomaly_source_ip", "source_ip"),
        Index("idx_anomaly_event_type", "event_type"),
        Index("idx_anomaly_is_anomaly", "is_anomaly"),
        Index("idx_anomaly_reviewed", "reviewed"),
    )

    def __repr__(self) -> str:
        return (
            f"<Anomaly(id={self.id}, risk_score={self.risk_score:.3f}, "
            f"source_ip={self.source_ip}, event_type={self.event_type})>"
        )


class Log(Base):
    """
    Processed log record.

    Stores all processed logs (not just anomalies).
    """

    __tablename__ = "logs"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    log_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Source information
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    destination_port: Mapped[int | None] = mapped_column(Integer)

    # Event information
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    hostname: Mapped[str | None] = mapped_column(String(255))

    # Status
    status_code: Mapped[int | None] = mapped_column(Integer)
    success: Mapped[bool | None] = mapped_column(Boolean)

    # Raw log
    raw_log: Mapped[str] = mapped_column(Text, nullable=False)
    log_source: Mapped[str] = mapped_column(String(50), nullable=False)

    # Parsed fields (JSON)
    parsed_fields: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # ML score (all logs get scored)
    risk_score: Mapped[float | None] = mapped_column(Float)

    # Indexes
    __table_args__ = (
        Index("idx_log_created_at", "created_at"),
        Index("idx_log_timestamp", "log_timestamp"),
        Index("idx_log_source_ip", "source_ip"),
        Index("idx_log_event_type", "event_type"),
    )

    def __repr__(self) -> str:
        return f"<Log(id={self.id}, source_ip={self.source_ip}, event_type={self.event_type})>"


class Feedback(Base):
    """
    User feedback on anomaly detection.

    Used to improve model accuracy (false positives/negatives).
    """

    __tablename__ = "feedback"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key
    anomaly_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("anomalies.id"), nullable=False, index=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Feedback
    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_false_negative: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # User information
    user_id: Mapped[str | None] = mapped_column(String(255))
    user_role: Mapped[str | None] = mapped_column(String(50))

    # Comment
    comment: Mapped[str | None] = mapped_column(Text)

    # Corrected values (if applicable)
    corrected_risk_level: Mapped[str | None] = mapped_column(String(20))
    corrected_event_type: Mapped[str | None] = mapped_column(String(100))

    # Relationships
    anomaly: Mapped["Anomaly"] = relationship("Anomaly", back_populates="feedback")

    def __repr__(self) -> str:
        return (
            f"<Feedback(id={self.id}, anomaly_id={self.anomaly_id}, "
            f"is_false_positive={self.is_false_positive})>"
        )


class Alert(Base):
    """
    Generated alert for anomalies.

    Tracks alert notifications (Slack, email, PagerDuty, etc.).
    """

    __tablename__ = "alerts"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key
    anomaly_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("anomalies.id"), nullable=False, index=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Alert details
    alert_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # slack, email, pagerduty, webhook
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # critical, high, medium
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Recipients
    recipients: Mapped[list[str]] = mapped_column(
        JSON, nullable=False
    )  # emails, slack channels, etc.

    # Status
    sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(255))

    # Delivery status
    delivery_status: Mapped[str | None] = mapped_column(
        String(50)
    )  # pending, sent, failed, acknowledged
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    anomaly: Mapped["Anomaly"] = relationship("Anomaly", back_populates="alerts")

    # Indexes
    __table_args__ = (
        Index("idx_alert_created_at", "created_at"),
        Index("idx_alert_sent", "sent"),
        Index("idx_alert_acknowledged", "acknowledged"),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, anomaly_id={self.anomaly_id}, "
            f"alert_type={self.alert_type}, sent={self.sent})>"
        )
