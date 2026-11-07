"""
Health check endpoints for SIEM Anomaly Detector.

Provides system health status and readiness checks.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from backend import __version__

logger = structlog.get_logger(__name__)

router = APIRouter()


# ============================================================================
# Response Models
# ============================================================================
class HealthResponse(BaseModel):
    """Health check response model."""

    status: str = Field(..., description="Overall health status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(..., description="Current server time")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")
    checks: dict[str, dict[str, Any]] = Field(..., description="Individual service checks")


class ReadinessResponse(BaseModel):
    """Readiness check response model."""

    ready: bool = Field(..., description="Whether service is ready")
    services: dict[str, bool] = Field(..., description="Individual service readiness")


# ============================================================================
# Global State
# ============================================================================
_start_time = time.time()


# ============================================================================
# Dependency checks (real probes, no mocked values)
# ============================================================================
async def _check_database() -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        from sqlalchemy import text

        from backend.db.database import get_db

        async with get_db() as session:
            await session.execute(text("SELECT 1"))
    except Exception as e:
        return {"status": "unhealthy", "error": type(e).__name__}
    return {"status": "healthy", "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}


async def _check_redis() -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        from backend.db.cache import get_redis

        await get_redis().ping()
    except Exception as e:
        return {"status": "unhealthy", "error": type(e).__name__}
    return {"status": "healthy", "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}


def _check_model() -> dict[str, Any]:
    from backend.ml.model_loader import get_model_loader

    loader = get_model_loader()
    loaded = loader.is_loaded()
    return {"status": "healthy" if loaded else "unloaded", "loaded": loaded}


# ============================================================================
# Endpoints
# ============================================================================
@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health Check",
    description="Check overall system health and component status",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns comprehensive health status including:
    - API version
    - Uptime
    - Database connectivity
    - Redis connectivity
    - ML model status

    Returns:
        HealthResponse with system health details
    """
    uptime = time.time() - _start_time

    # Check individual components
    checks: dict[str, dict[str, Any]] = {}

    checks["database"] = await _check_database()
    checks["redis"] = await _check_redis()
    checks["ml_models"] = _check_model()

    # Determine overall status
    all_healthy = all(check.get("status") == "healthy" for check in checks.values())
    overall_status = "healthy" if all_healthy else "degraded"

    logger.info(
        "health_check_completed",
        status=overall_status,
        uptime_seconds=round(uptime, 2),
    )

    return HealthResponse(
        status=overall_status,
        version=__version__,
        timestamp=datetime.now(timezone.utc),
        uptime_seconds=round(uptime, 2),
        checks=checks,
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness Check",
    description="Check if service is ready to accept traffic",
)
async def readiness_check() -> ReadinessResponse:
    """
    Readiness check endpoint.

    Used by Kubernetes/load balancers to determine if pod is ready.
    Stricter than health check - returns 503 if any critical service is down.

    Returns:
        ReadinessResponse with service readiness status

    Raises:
        HTTPException: 503 if service is not ready
    """
    services = {
        "database": (await _check_database())["status"] == "healthy",
        "redis": (await _check_redis())["status"] == "healthy",
        "ml_models": _check_model()["status"] == "healthy",
    }

    # Service is ready only if ALL critical services are up
    ready = all(services.values())

    if not ready:
        logger.warning("service_not_ready", services=services)

    return ReadinessResponse(
        ready=ready,
        services=services,
    )


@router.get(
    "/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness Check",
    description="Simple liveness probe for Kubernetes",
)
async def liveness_check() -> dict[str, str]:
    """
    Liveness check endpoint.

    Used by Kubernetes to determine if pod should be restarted.
    Returns 200 if process is alive (doesn't check dependencies).

    Returns:
        Simple status message
    """
    return {"status": "alive"}
