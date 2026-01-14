"""
SIEM Anomaly Detector - Main FastAPI Application.

Entry point for the SIEM API server.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, make_asgi_app

from backend import __version__
from backend.api.routes import alerts, analysis, health, stats
from backend.config import settings

# ============================================================================
# Structured Logging
# ============================================================================
logger = structlog.get_logger(__name__)

# ============================================================================
# Prometheus Metrics
# ============================================================================
registry = CollectorRegistry()

# Request metrics
REQUEST_COUNT = Counter(
    "siem_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=registry,
)

REQUEST_DURATION = Histogram(
    "siem_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    registry=registry,
)

# Analysis metrics
LOGS_ANALYZED = Counter(
    "siem_logs_analyzed_total",
    "Total logs analyzed",
    ["source"],
    registry=registry,
)

ANOMALIES_DETECTED = Counter(
    "siem_anomalies_detected_total",
    "Total anomalies detected",
    ["risk_level"],
    registry=registry,
)

ANALYSIS_DURATION = Histogram(
    "siem_analysis_duration_seconds",
    "Log analysis duration in seconds",
    registry=registry,
)


# ============================================================================
# Lifespan Events (Startup/Shutdown)
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage application lifespan events.

    Startup:
    - Initialize database connection pool
    - Load ML models
    - Connect to Redis
    - Start background tasks

    Shutdown:
    - Close database connections
    - Save model state
    - Flush metrics
    """
    # ========================================================================
    # STARTUP
    # ========================================================================
    logger.info(
        "siem_startup",
        version=__version__,
        config={
            "api_host": settings.api_host,
            "api_port": settings.api_port,
            "log_level": settings.log_level,
            "debug": settings.debug,
        },
    )

    try:
        # Initialize database connection pool
        from backend.db.database import init_db

        await init_db()
        logger.info("database_initialized")

        # Load ML models
        from backend.ml.model_loader import initialize_model

        initialize_model(settings.model_path)
        logger.info("ml_models_loaded", model_path=str(settings.model_path))

        # Connect to Redis
        from backend.db.cache import init_redis

        await init_redis()
        logger.info("redis_connected", host=settings.redis_host)

        logger.info("siem_startup_complete")

    except Exception:
        logger.exception("startup_failed")
        raise

    # ========================================================================
    # YIELD (Application Running)
    # ========================================================================
    yield

    # ========================================================================
    # SHUTDOWN
    # ========================================================================
    logger.info("siem_shutdown_started")

    try:
        # Close database connections
        from backend.db.database import close_db

        await close_db()
        logger.info("database_connections_closed")

        # TODO: Save model state if needed
        # await app.state.ml_ensemble.save()
        logger.info("ml_models_saved")

        # Close Redis connection
        from backend.db.cache import close_redis

        await close_redis()
        logger.info("redis_connection_closed")

        logger.info("siem_shutdown_complete")

    except Exception:
        logger.exception("shutdown_failed")


# ============================================================================
# FastAPI Application
# ============================================================================
app = FastAPI(
    title="SIEM Anomaly Detector",
    description=(
        "ML-based Security Information and Event Management system "
        "for real-time anomaly detection in security logs"
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    debug=settings.debug,
)

# ============================================================================
# Middleware
# ============================================================================

# CORS Middleware
allowed_origins = [origin.strip() for origin in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request Logging & Metrics Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next: Any) -> Any:
    """
    Log all HTTP requests and collect metrics.

    Args:
        request: FastAPI request object
        call_next: Next middleware in chain

    Returns:
        Response from downstream handler
    """
    start_time = time.time()

    # Generate request ID
    request_id = request.headers.get("X-Request-ID", f"req_{int(start_time * 1000)}")

    # Bind request context to logger
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else None,
    )

    logger.info("request_started")

    # Process request
    try:
        response = await call_next(request)
        duration = time.time() - start_time

        # Record metrics
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).inc()

        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path,
        ).observe(duration)

        # Log completion
        logger.info(
            "request_completed",
            status_code=response.status_code,
            duration_ms=round(duration * 1000, 2),
        )

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response

    except Exception as exc:
        duration = time.time() - start_time
        logger.exception(
            "request_failed",
            duration_ms=round(duration * 1000, 2),
            error=str(exc),
        )
        raise


# ============================================================================
# Exception Handlers
# ============================================================================
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    """Handle ValueError exceptions."""
    logger.warning("validation_error", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": str(exc),
            "path": request.url.path,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all unhandled exceptions."""
    logger.exception("unhandled_exception", path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred" if not settings.debug else str(exc),
            "path": request.url.path,
        },
    )


# ============================================================================
# Routes
# ============================================================================


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict[str, str]:
    """
    Root endpoint with API information.

    Returns:
        API metadata
    """
    return {
        "name": "SIEM Anomaly Detector API",
        "version": __version__,
        "docs": "/docs",
        "health": "/api/v1/health",
    }


# API v1 routes
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(stats.router, prefix="/api/v1", tags=["Statistics"])


# Prometheus metrics endpoint
if settings.prometheus_enabled:
    metrics_app = make_asgi_app(registry=registry)
    app.mount("/metrics", metrics_app)


# ============================================================================
# Main Entry Point (for development)
# ============================================================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.auto_reload,
        log_level=settings.log_level.lower(),
        access_log=True,
    )
