"""
Redis connection management.

Features are computed in-process (``backend.ml.features.WindowedAggregator``), so Redis is
currently only a connectivity dependency (health/readiness probes). A shared Redis-backed
aggregator is required before running more than one API worker; see README "Limitations".
"""

from __future__ import annotations

import redis.asyncio as redis
import structlog

from backend.config import settings

logger = structlog.get_logger(__name__)

# Global Redis client
_redis_client: redis.Redis | None = None


async def init_redis() -> redis.Redis:
    """
    Initialize Redis connection pool.

    Returns:
        Redis client instance

    Raises:
        redis.ConnectionError: If connection fails
    """
    global _redis_client

    if _redis_client is not None:
        logger.warning("redis_already_initialized")
        return _redis_client

    logger.info(
        "initializing_redis",
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
    )

    try:
        _redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password if settings.redis_password else None,
            max_connections=settings.redis_max_connections,
            socket_timeout=settings.redis_socket_timeout,
            decode_responses=True,  # Auto-decode bytes to str
        )

        # Test connection
        await _redis_client.ping()

        logger.info("redis_initialized")
        return _redis_client

    except redis.ConnectionError as e:
        logger.exception("redis_connection_failed", error=str(e))
        raise


async def close_redis() -> None:
    """Close Redis connection pool."""
    global _redis_client

    if _redis_client is None:
        return

    logger.info("closing_redis_connections")

    await _redis_client.aclose()
    _redis_client = None

    logger.info("redis_connections_closed")


def get_redis() -> redis.Redis:
    """
    Get Redis client instance.

    Returns:
        Redis client

    Raises:
        RuntimeError: If Redis not initialized
    """
    if _redis_client is None:
        msg = "Redis not initialized. Call init_redis() first."
        raise RuntimeError(msg)

    return _redis_client
