"""
Alerts endpoints for SIEM Anomaly Detector.

Retrieve and manage detected anomalies.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field

from backend.api.routes.analysis import AnalysisResult, RiskLevel, RecommendedAction

logger = structlog.get_logger(__name__)

router = APIRouter()


# ============================================================================
# Response Models
# ============================================================================
class AnomaliesResponse(BaseModel):
    """Response model for anomalies list."""

    total: int = Field(..., description="Total anomalies found")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Items per page")
    anomalies: list[AnalysisResult] = Field(..., description="Anomalies list")


class AnomalyDetail(BaseModel):
    """Detailed anomaly information."""

    anomaly: AnalysisResult = Field(..., description="Anomaly data")
    context: dict[str, Any] = Field(..., description="Additional context")
    related_logs: list[str] = Field(..., description="Related log IDs")


# ============================================================================
# Endpoints
# ============================================================================
@router.get(
    "/anomalies",
    response_model=AnomaliesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Anomalies",
    description="Retrieve detected anomalies with filtering and pagination",
)
async def get_anomalies(
    limit: int = Query(default=10, ge=1, le=100, description="Results per page"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    hours: int = Query(default=24, ge=1, le=168, description="Time window in hours"),
    min_risk_score: float = Query(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Minimum risk score",
    ),
    risk_level: RiskLevel | None = Query(default=None, description="Filter by risk level"),
) -> AnomaliesResponse:
    """
    Retrieve anomalies with filtering.

    Args:
        limit: Number of results per page
        offset: Pagination offset
        hours: Look back X hours
        min_risk_score: Minimum risk score filter
        risk_level: Filter by risk level

    Returns:
        AnomaliesResponse with filtered anomalies
    """
    logger.info(
        "fetching_anomalies",
        limit=limit,
        offset=offset,
        hours=hours,
        min_risk_score=min_risk_score,
    )

    # Query database for anomalies
    from backend.db.database import get_db
    from backend.db.models import Anomaly
    from sqlalchemy import select, func

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    async with get_db() as session:
        # Count total matching anomalies
        count_stmt = (
            select(func.count())
            .select_from(Anomaly)
            .where(
                Anomaly.created_at >= since,
                Anomaly.risk_score >= min_risk_score,
            )
        )
        if risk_level:
            count_stmt = count_stmt.where(Anomaly.risk_level == risk_level.value)

        total_result = await session.execute(count_stmt)
        total = total_result.scalar() or 0

        # Query anomalies with pagination
        stmt = select(Anomaly).where(
            Anomaly.created_at >= since,
            Anomaly.risk_score >= min_risk_score,
        )
        if risk_level:
            stmt = stmt.where(Anomaly.risk_level == risk_level.value)

        stmt = stmt.order_by(Anomaly.created_at.desc()).limit(limit).offset(offset)

        result = await session.execute(stmt)
        db_anomalies = result.scalars().all()

        # Convert to AnalysisResult format
        anomalies = [
            AnalysisResult(
                log_id=str(anomaly.id),
                is_anomaly=True,
                risk_score=anomaly.risk_score,
                risk_level=RiskLevel(anomaly.risk_level),
                confidence=anomaly.confidence,
                features=anomaly.features or {},
                reasons=anomaly.reasons or [],
                recommended_action=RecommendedAction(anomaly.recommended_action)
                if anomaly.recommended_action
                else RecommendedAction.MONITOR,
                similar_anomalies=0,  # TODO: Calculate similar anomalies
                model_scores={
                    "isolation_forest": anomaly.isolation_forest_score or 0.0,
                    "dbscan": anomaly.dbscan_score or 0.0,
                    "gmm": anomaly.gmm_score or 0.0,
                },
                processing_time_ms=anomaly.processing_time_ms or 0.0,
                timestamp=anomaly.created_at,
            )
            for anomaly in db_anomalies
        ]

    return AnomaliesResponse(
        total=total,
        page=offset // limit + 1,
        page_size=limit,
        anomalies=anomalies,
    )


@router.get(
    "/anomalies/{anomaly_id}",
    response_model=AnomalyDetail,
    status_code=status.HTTP_200_OK,
    summary="Get Anomaly Detail",
    description="Get detailed information about a specific anomaly",
)
async def get_anomaly_detail(anomaly_id: str) -> AnomalyDetail:
    """
    Get detailed anomaly information.

    Args:
        anomaly_id: Anomaly identifier

    Returns:
        AnomalyDetail with full context
    """
    logger.info("fetching_anomaly_detail", anomaly_id=anomaly_id)

    # Query database for specific anomaly
    from backend.db.database import get_db
    from backend.db.models import Anomaly
    from sqlalchemy import select
    from fastapi import HTTPException

    async with get_db() as session:
        stmt = select(Anomaly).where(Anomaly.id == int(anomaly_id))
        result = await session.execute(stmt)
        anomaly = result.scalar_one_or_none()

        if not anomaly:
            raise HTTPException(status_code=404, detail=f"Anomaly {anomaly_id} not found")

        # Build context from anomaly data
        context = {
            "source_ip": anomaly.source_ip,
            "username": anomaly.username,
            "hostname": anomaly.hostname,
            "event_type": anomaly.event_type,
            "raw_log": anomaly.raw_log,
            "log_source": anomaly.log_source,
        }

        # Convert to AnalysisResult
        anomaly_result = AnalysisResult(
            log_id=str(anomaly.id),
            is_anomaly=True,
            risk_score=anomaly.risk_score,
            risk_level=RiskLevel(anomaly.risk_level),
            confidence=anomaly.confidence,
            features=anomaly.features or {},
            reasons=anomaly.reasons or [],
            recommended_action=RecommendedAction(anomaly.recommended_action)
            if anomaly.recommended_action
            else RecommendedAction.MONITOR,
            similar_anomalies=0,
            model_scores={
                "isolation_forest": anomaly.isolation_forest_score or 0.0,
                "dbscan": anomaly.dbscan_score or 0.0,
                "gmm": anomaly.gmm_score or 0.0,
            },
            processing_time_ms=anomaly.processing_time_ms or 0.0,
            timestamp=anomaly.created_at,
        )

    return AnomalyDetail(
        anomaly=anomaly_result,
        context=context,
        related_logs=[],  # TODO: Query related logs based on IP/user
    )
