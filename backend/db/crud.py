"""
CRUD operations for database models.

Provides async functions to create, read, update, delete records.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Alert, Anomaly, Feedback, Log


# ============================================================================
# Anomaly CRUD
# ============================================================================
async def create_anomaly(session: AsyncSession, anomaly_data: dict[str, Any]) -> Anomaly:
    """Create new anomaly record."""
    anomaly = Anomaly(**anomaly_data)
    session.add(anomaly)
    await session.flush()
    await session.refresh(anomaly)
    return anomaly


async def get_anomaly_by_id(session: AsyncSession, anomaly_id: int) -> Anomaly | None:
    """Get anomaly by ID."""
    result = await session.execute(select(Anomaly).where(Anomaly.id == anomaly_id))
    return result.scalar_one_or_none()


async def get_anomalies(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    min_risk_score: float | None = None,
    risk_level: str | None = None,
    source_ip: str | None = None,
    hours: int = 24,
) -> list[Anomaly]:
    """
    Get anomalies with filtering and pagination.

    Args:
        session: Database session
        limit: Max results per page
        offset: Pagination offset
        min_risk_score: Minimum risk score filter
        risk_level: Risk level filter (critical, high, medium, low)
        source_ip: Source IP filter
        hours: Look back X hours

    Returns:
        List of Anomaly objects
    """
    query = select(Anomaly)

    # Time filter
    time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = query.where(Anomaly.created_at >= time_threshold)

    # Risk score filter
    if min_risk_score is not None:
        query = query.where(Anomaly.risk_score >= min_risk_score)

    # Risk level filter
    if risk_level is not None:
        query = query.where(Anomaly.risk_level == risk_level)

    # Source IP filter
    if source_ip is not None:
        query = query.where(Anomaly.source_ip == source_ip)

    # Only anomalies
    query = query.where(Anomaly.is_anomaly == True)  # noqa: E712

    # Order by created_at descending
    query = query.order_by(desc(Anomaly.created_at))

    # Pagination
    query = query.limit(limit).offset(offset)

    result = await session.execute(query)
    return list(result.scalars().all())


async def count_anomalies(
    session: AsyncSession,
    hours: int = 24,
    min_risk_score: float | None = None,
) -> int:
    """Count anomalies in time window."""
    query = select(func.count(Anomaly.id))

    time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = query.where(Anomaly.created_at >= time_threshold)
    query = query.where(Anomaly.is_anomaly == True)  # noqa: E712

    if min_risk_score is not None:
        query = query.where(Anomaly.risk_score >= min_risk_score)

    result = await session.execute(query)
    return result.scalar_one()


async def update_anomaly(
    session: AsyncSession,
    anomaly_id: int,
    update_data: dict[str, Any],
) -> Anomaly | None:
    """Update anomaly record."""
    anomaly = await get_anomaly_by_id(session, anomaly_id)
    if anomaly is None:
        return None

    for key, value in update_data.items():
        setattr(anomaly, key, value)

    await session.flush()
    await session.refresh(anomaly)
    return anomaly


# ============================================================================
# Log CRUD
# ============================================================================
async def create_log(session: AsyncSession, log_data: dict[str, Any]) -> Log:
    """Create new log record."""
    log = Log(**log_data)
    session.add(log)
    await session.flush()
    await session.refresh(log)
    return log


async def get_logs(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    source_ip: str | None = None,
    hours: int = 24,
) -> list[Log]:
    """Get logs with filtering and pagination."""
    query = select(Log)

    # Time filter
    time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = query.where(Log.created_at >= time_threshold)

    # Source IP filter
    if source_ip is not None:
        query = query.where(Log.source_ip == source_ip)

    # Order by created_at descending
    query = query.order_by(desc(Log.created_at))

    # Pagination
    query = query.limit(limit).offset(offset)

    result = await session.execute(query)
    return list(result.scalars().all())


# ============================================================================
# Feedback CRUD
# ============================================================================
async def create_feedback(session: AsyncSession, feedback_data: dict[str, Any]) -> Feedback:
    """Create new feedback record."""
    feedback = Feedback(**feedback_data)
    session.add(feedback)
    await session.flush()
    await session.refresh(feedback)
    return feedback


async def get_feedback_for_anomaly(
    session: AsyncSession,
    anomaly_id: int,
) -> list[Feedback]:
    """Get all feedback for an anomaly."""
    result = await session.execute(select(Feedback).where(Feedback.anomaly_id == anomaly_id))
    return list(result.scalars().all())


# ============================================================================
# Alert CRUD
# ============================================================================
async def create_alert(session: AsyncSession, alert_data: dict[str, Any]) -> Alert:
    """Create new alert record."""
    alert = Alert(**alert_data)
    session.add(alert)
    await session.flush()
    await session.refresh(alert)
    return alert


async def get_alerts(
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    sent: bool | None = None,
    acknowledged: bool | None = None,
) -> list[Alert]:
    """Get alerts with filtering and pagination."""
    query = select(Alert)

    if sent is not None:
        query = query.where(Alert.sent == sent)

    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)

    query = query.order_by(desc(Alert.created_at))
    query = query.limit(limit).offset(offset)

    result = await session.execute(query)
    return list(result.scalars().all())


async def update_alert(
    session: AsyncSession,
    alert_id: int,
    update_data: dict[str, Any],
) -> Alert | None:
    """Update alert record."""
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        return None

    for key, value in update_data.items():
        setattr(alert, key, value)

    await session.flush()
    await session.refresh(alert)
    return alert


# ============================================================================
# Statistics
# ============================================================================
async def get_anomaly_stats(
    session: AsyncSession,
    hours: int = 24,
) -> dict[str, Any]:
    """
    Get anomaly statistics.

    Returns:
        Dictionary with stats (total, by_risk_level, by_event_type, etc.)
    """
    time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Total anomalies
    total_query = select(func.count(Anomaly.id)).where(
        Anomaly.created_at >= time_threshold,
        Anomaly.is_anomaly == True,  # noqa: E712
    )
    total_result = await session.execute(total_query)
    total_anomalies = total_result.scalar_one()

    # By risk level
    risk_level_query = (
        select(Anomaly.risk_level, func.count(Anomaly.id))
        .where(
            Anomaly.created_at >= time_threshold,
            Anomaly.is_anomaly == True,  # noqa: E712
        )
        .group_by(Anomaly.risk_level)
    )
    risk_level_result = await session.execute(risk_level_query)
    by_risk_level = dict(risk_level_result.all())

    # By event type (top 10)
    event_type_query = (
        select(Anomaly.event_type, func.count(Anomaly.id))
        .where(
            Anomaly.created_at >= time_threshold,
            Anomaly.is_anomaly == True,  # noqa: E712
        )
        .group_by(Anomaly.event_type)
        .order_by(desc(func.count(Anomaly.id)))
        .limit(10)
    )
    event_type_result = await session.execute(event_type_query)
    by_event_type = dict(event_type_result.all())

    # Top source IPs (top 10)
    source_ip_query = (
        select(Anomaly.source_ip, func.count(Anomaly.id))
        .where(
            Anomaly.created_at >= time_threshold,
            Anomaly.is_anomaly == True,  # noqa: E712
        )
        .group_by(Anomaly.source_ip)
        .order_by(desc(func.count(Anomaly.id)))
        .limit(10)
    )
    source_ip_result = await session.execute(source_ip_query)
    top_source_ips = dict(source_ip_result.all())

    # Average risk score
    avg_risk_query = select(func.avg(Anomaly.risk_score)).where(
        Anomaly.created_at >= time_threshold,
        Anomaly.is_anomaly == True,  # noqa: E712
    )
    avg_risk_result = await session.execute(avg_risk_query)
    avg_risk_score = avg_risk_result.scalar_one() or 0.0

    return {
        "total_anomalies": total_anomalies,
        "by_risk_level": by_risk_level,
        "by_event_type": by_event_type,
        "top_source_ips": top_source_ips,
        "avg_risk_score": float(avg_risk_score),
        "time_window_hours": hours,
    }
