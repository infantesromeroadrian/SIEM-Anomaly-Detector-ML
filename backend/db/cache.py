"""
Redis cache for feature aggregation.

Provides real-time counters and aggregations for ML features.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

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


# ============================================================================
# Feature Caching Operations
# ============================================================================


async def record_login_attempt(
    source_ip: str,
    success: bool,
    timestamp: datetime | None = None,
) -> None:
    """
    Record login attempt for feature aggregation.

    Args:
        source_ip: Source IP address
        success: Whether login succeeded
        timestamp: Login timestamp (defaults to now)
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())

    # Store in sorted set with timestamp as score
    key_all = f"login_attempts:{source_ip}"
    await redis_client.zadd(key_all, {timestamp_seconds: timestamp_seconds})

    # Store failed attempts separately
    if not success:
        key_failed = f"login_attempts:failed:{source_ip}"
        await redis_client.zadd(key_failed, {timestamp_seconds: timestamp_seconds})

    # Set expiry (7 days)
    await redis_client.expire(key_all, 604800)  # 7 days in seconds
    if not success:
        await redis_client.expire(key_failed, 604800)


async def get_login_attempts_rate(
    source_ip: str,
    window_seconds: int = 60,
    timestamp: datetime | None = None,
) -> float:
    """
    Get login attempts rate (per minute).

    Args:
        source_ip: Source IP address
        window_seconds: Time window in seconds
        timestamp: Reference timestamp (defaults to now)

    Returns:
        Login attempts per minute
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())
    window_start = timestamp_seconds - window_seconds

    key = f"login_attempts:{source_ip}"

    try:
        # Count entries in time window
        count = await redis_client.zcount(key, window_start, timestamp_seconds)

        # Convert to per-minute rate
        return count / (window_seconds / 60)

    except redis.RedisError:
        logger.exception("redis_error_login_attempts", source_ip=source_ip)
        return 0.0


async def get_failed_auth_rate(
    source_ip: str,
    window_seconds: int = 300,
    timestamp: datetime | None = None,
) -> float:
    """
    Get failed authentication rate (0.0-1.0).

    Args:
        source_ip: Source IP address
        window_seconds: Time window in seconds
        timestamp: Reference timestamp (defaults to now)

    Returns:
        Failure rate (0.0 = all success, 1.0 = all failures)
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())
    window_start = timestamp_seconds - window_seconds

    key_all = f"login_attempts:{source_ip}"
    key_failed = f"login_attempts:failed:{source_ip}"

    try:
        total = await redis_client.zcount(key_all, window_start, timestamp_seconds)
        failed = await redis_client.zcount(key_failed, window_start, timestamp_seconds)

        if total == 0:
            return 0.0

        return failed / total

    except redis.RedisError:
        logger.exception("redis_error_failed_auth_rate", source_ip=source_ip)
        return 0.0


async def record_request(
    source_ip: str,
    endpoint: str,
    timestamp: datetime | None = None,
) -> None:
    """
    Record HTTP request for rate tracking.

    Args:
        source_ip: Source IP address
        endpoint: Request endpoint
        timestamp: Request timestamp (defaults to now)
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())

    # Store requests in sorted set
    key_requests = f"requests:{source_ip}"
    await redis_client.zadd(key_requests, {timestamp_seconds: timestamp_seconds})

    # Store unique endpoints in set (expires after 1 hour)
    key_endpoints = f"endpoints:{source_ip}"
    await redis_client.sadd(key_endpoints, endpoint)
    await redis_client.expire(key_endpoints, 3600)  # 1 hour

    # Expire requests after 1 hour
    await redis_client.expire(key_requests, 3600)


async def get_requests_per_second(
    source_ip: str,
    window_seconds: int = 60,
    timestamp: datetime | None = None,
) -> float:
    """
    Get request rate (per second).

    Args:
        source_ip: Source IP address
        window_seconds: Time window in seconds
        timestamp: Reference timestamp (defaults to now)

    Returns:
        Requests per second
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())
    window_start = timestamp_seconds - window_seconds

    key = f"requests:{source_ip}"

    try:
        count = await redis_client.zcount(key, window_start, timestamp_seconds)
        return count / window_seconds

    except redis.RedisError:
        logger.exception("redis_error_requests_per_second", source_ip=source_ip)
        return 0.0


async def get_unique_endpoints_accessed(
    source_ip: str,
) -> int:
    """
    Get number of unique endpoints accessed in last hour.

    Args:
        source_ip: Source IP address

    Returns:
        Number of unique endpoints
    """
    redis_client = get_redis()

    key = f"endpoints:{source_ip}"

    try:
        count = await redis_client.scard(key)
        return count

    except redis.RedisError:
        logger.exception("redis_error_unique_endpoints", source_ip=source_ip)
        return 0


async def get_unique_ips_last_hour() -> int:
    """
    Get number of unique source IPs in last hour.

    Returns:
        Number of unique IPs
    """
    redis_client = get_redis()

    key = "unique_ips"

    try:
        count = await redis_client.scard(key)
        return count

    except redis.RedisError:
        logger.exception("redis_error_unique_ips")
        return 0


async def record_ip_activity(source_ip: str) -> None:
    """
    Record IP activity (for unique IP tracking).

    Args:
        source_ip: Source IP address
    """
    redis_client = get_redis()

    key = "unique_ips"

    await redis_client.sadd(key, source_ip)
    await redis_client.expire(key, 3600)  # 1 hour


async def get_time_since_last_activity(
    source_ip: str,
    timestamp: datetime | None = None,
) -> float:
    """
    Get seconds since last activity from this IP.

    Args:
        source_ip: Source IP address
        timestamp: Current timestamp (defaults to now)

    Returns:
        Seconds since last activity (0 if no previous activity)
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    redis_client = get_redis()

    timestamp_seconds = int(timestamp.timestamp())

    key = f"requests:{source_ip}"

    try:
        # Get most recent activity (highest score in sorted set)
        recent = await redis_client.zrevrange(key, 0, 0, withscores=True)

        if not recent:
            return 0.0

        last_timestamp = int(recent[0][1])
        return float(timestamp_seconds - last_timestamp)

    except redis.RedisError:
        logger.exception("redis_error_last_activity", source_ip=source_ip)
        return 0.0


# ============================================================================
# Session Management
# ============================================================================


async def create_session(
    source_ip: str,
    session_id: str,
    session_data: dict[str, Any],
    ttl_seconds: int = 3600,
) -> None:
    """
    Create user session.

    Args:
        source_ip: Source IP address
        session_id: Unique session ID
        session_data: Session data (will be JSON-encoded)
        ttl_seconds: Time-to-live in seconds
    """
    redis_client = get_redis()

    key = f"session:{source_ip}:{session_id}"

    await redis_client.setex(
        key,
        ttl_seconds,
        json.dumps(session_data),
    )


async def get_session(
    source_ip: str,
    session_id: str,
) -> dict[str, Any] | None:
    """
    Get session data.

    Args:
        source_ip: Source IP address
        session_id: Session ID

    Returns:
        Session data or None if not found
    """
    redis_client = get_redis()

    key = f"session:{source_ip}:{session_id}"

    try:
        data = await redis_client.get(key)

        if data is None:
            return None

        return json.loads(data)

    except redis.RedisError:
        logger.exception("redis_error_get_session", session_id=session_id)
        return None
