"""
Statistics endpoints for SIEM Anomaly Detector.

Provides system statistics and metrics.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.config import settings
from backend.db.database import get_db
from backend.ml.model_loader import get_model_loader

logger = structlog.get_logger(__name__)

router = APIRouter()


# ============================================================================
# Response Models
# ============================================================================
class ModelStats(BaseModel):
    """ML model statistics."""

    contamination: float
    n_estimators: int | None = None
    accuracy: float | None = None


class SystemStats(BaseModel):
    """System statistics response."""

    logs_analyzed_24h: int = Field(..., description="Logs analyzed in last 24h")
    anomalies_detected_24h: int = Field(..., description="Anomalies detected in last 24h")
    anomaly_rate: float = Field(..., description="Anomaly rate (0.0-1.0)")
    model_version: str = Field(..., description="Current model version")
    last_retrain: datetime | None = Field(None, description="Last retraining timestamp, if known")
    models: dict[str, ModelStats] = Field(..., description="Per-model statistics")


# ============================================================================
# Endpoints
# ============================================================================
@router.get(
    "/stats",
    response_model=SystemStats,
    status_code=status.HTTP_200_OK,
    summary="System Statistics",
    description="Get overall system statistics and metrics",
)
async def get_stats() -> SystemStats:
    """
    Get system statistics.

    Returns:
        SystemStats with metrics for last 24 hours
    """
    logger.info("fetching_system_stats")

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        async with get_db() as session:
            from sqlalchemy import func, select

            from backend.db.models import Anomaly, Log

            logs_total = (
                await session.execute(
                    select(func.count()).select_from(Log).where(Log.created_at >= since)
                )
            ).scalar_one()
            anomalies_total = (
                await session.execute(
                    select(func.count()).select_from(Anomaly).where(Anomaly.created_at >= since)
                )
            ).scalar_one()
    except Exception as e:
        logger.error("stats_query_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable"
        ) from e

    loader = get_model_loader()
    meta = loader.metadata if loader.is_loaded() else {}
    return SystemStats(
        logs_analyzed_24h=logs_total,
        anomalies_detected_24h=anomalies_total,
        anomaly_rate=(anomalies_total / logs_total) if logs_total else 0.0,
        model_version=str(meta.get("training_date", "unloaded")),
        last_retrain=None,
        models={
            "isolation_forest": ModelStats(
                contamination=settings.model_contamination,
                n_estimators=settings.model_n_estimators,
            ),
            "dbscan": ModelStats(contamination=settings.model_contamination),
            "gmm": ModelStats(contamination=settings.model_contamination),
        },
    )


# ============================================================================
# Time Series Endpoints
# ============================================================================
class TimeSeriesDataPoint(BaseModel):
    """Single data point in time series."""

    timestamp: datetime = Field(..., description="Timestamp for this data point")
    hour_label: str = Field(..., description="Human-readable hour label (e.g., '14h')")
    anomalies: int = Field(..., description="Number of anomalies in this interval")
    logs: int = Field(..., description="Number of logs in this interval")


class TimeSeriesResponse(BaseModel):
    """Time series response."""

    start_time: datetime = Field(..., description="Start of time range")
    end_time: datetime = Field(..., description="End of time range")
    interval_hours: int = Field(..., description="Requested interval in hours")
    data_points: list[TimeSeriesDataPoint] = Field(..., description="Time series data")
    total_anomalies: int = Field(..., description="Total anomalies in range")
    total_logs: int = Field(..., description="Total logs in range")


@router.get(
    "/stats/timeseries",
    response_model=TimeSeriesResponse,
    status_code=status.HTTP_200_OK,
    summary="Anomaly Time Series",
    description="Get anomaly counts over time with configurable intervals",
)
async def get_anomaly_timeseries(
    hours: int = Query(24, ge=1, le=168, description="Time range in hours (max 1 week)"),
) -> TimeSeriesResponse:
    """
    Get time series data for anomalies and logs.

    Query anomalies table grouped by hour to provide trend data.

    Args:
        hours: Number of hours to look back (1-168)

    Returns:
        TimeSeriesResponse with hourly aggregated data
    """
    logger.info("fetching_timeseries", hours=hours)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    # Query database for real data
    try:
        async with get_db() as session:
            # PostgreSQL query to group by hour
            from sqlalchemy import text

            # Count anomalies per hour
            anomaly_query = text("""
                SELECT
                    date_trunc('hour', created_at) AS hour,
                    COUNT(*) as count
                FROM anomalies
                WHERE created_at >= :start_time AND created_at <= :end_time
                GROUP BY date_trunc('hour', created_at)
                ORDER BY hour
            """)

            # Count logs per hour
            log_query = text("""
                SELECT
                    date_trunc('hour', created_at) AS hour,
                    COUNT(*) as count
                FROM logs
                WHERE created_at >= :start_time AND created_at <= :end_time
                GROUP BY date_trunc('hour', created_at)
                ORDER BY hour
            """)

            anomaly_result = await session.execute(
                anomaly_query, {"start_time": start_time, "end_time": end_time}
            )
            log_result = await session.execute(
                log_query, {"start_time": start_time, "end_time": end_time}
            )

            # Convert to dicts for easier lookup
            anomaly_counts = {row.hour: row.count for row in anomaly_result}
            log_counts = {row.hour: row.count for row in log_result}

            # Generate data points for all hours (fill gaps with 0)
            data_points = []
            current_time = start_time.replace(minute=0, second=0, microsecond=0)
            total_anomalies = 0
            total_logs = 0

            while current_time <= end_time:
                anomaly_count = anomaly_counts.get(current_time, 0)
                log_count = log_counts.get(current_time, 0)

                total_anomalies += anomaly_count
                total_logs += log_count

                # Format hour label (e.g., "14h" or "Jan 14 14h" for longer ranges)
                if hours <= 24:
                    hour_label = f"{current_time.hour}h"
                else:
                    hour_label = current_time.strftime("%b %d %Hh")

                data_points.append(
                    TimeSeriesDataPoint(
                        timestamp=current_time,
                        hour_label=hour_label,
                        anomalies=anomaly_count,
                        logs=log_count,
                    )
                )

                current_time += timedelta(hours=1)

            logger.info(
                "timeseries_fetched",
                data_points=len(data_points),
                total_anomalies=total_anomalies,
                total_logs=total_logs,
            )

            return TimeSeriesResponse(
                start_time=start_time,
                end_time=end_time,
                interval_hours=hours,
                data_points=data_points,
                total_anomalies=total_anomalies,
                total_logs=total_logs,
            )

    except Exception as e:
        logger.error("timeseries_query_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable"
        ) from e
