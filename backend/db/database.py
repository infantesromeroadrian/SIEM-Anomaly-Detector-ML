"""
Database connection management.

Provides async connection pool and session management.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.config import settings
from backend.db.models import Base

logger = structlog.get_logger(__name__)

# Global engine and session factory
_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """
    Initialize database connection pool.

    Creates async engine and session factory.
    Should be called at application startup.
    """
    global _engine, _async_session_factory

    if _engine is not None:
        logger.warning("database_already_initialized")
        return

    logger.info(
        "initializing_database",
        host=settings.postgres_host,
        database=settings.postgres_db,
    )

    # Create async engine
    _engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_size=settings.postgres_pool_size,
        max_overflow=settings.postgres_max_overflow,
        pool_timeout=settings.postgres_pool_timeout,
        pool_pre_ping=True,  # Verify connections before using
    )

    # Create session factory
    _async_session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create tables (if they don't exist)
    # In production, use Alembic migrations instead
    if settings.debug:
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("database_tables_created")

    logger.info("database_initialized")


async def close_db() -> None:
    """
    Close database connection pool.

    Should be called at application shutdown.
    """
    global _engine, _async_session_factory

    if _engine is None:
        return

    logger.info("closing_database_connections")

    await _engine.dispose()
    _engine = None
    _async_session_factory = None

    logger.info("database_connections_closed")


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get async database session.

    Usage:
        async with get_db() as session:
            result = await session.execute(select(Anomaly))
            anomalies = result.scalars().all()

    Yields:
        AsyncSession for database operations

    Raises:
        RuntimeError: If database not initialized
    """
    if _async_session_factory is None:
        msg = "Database not initialized. Call init_db() first."
        raise RuntimeError(msg)

    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Get session factory.

    For FastAPI dependency injection.

    Returns:
        async_sessionmaker instance

    Raises:
        RuntimeError: If database not initialized
    """
    if _async_session_factory is None:
        msg = "Database not initialized. Call init_db() first."
        raise RuntimeError(msg)

    return _async_session_factory
