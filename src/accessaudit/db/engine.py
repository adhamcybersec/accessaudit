"""Database engine and session management."""

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine | None:
    """Get the async engine singleton. Returns None when DATABASE_URL is unset."""
    return _engine


async def init_db(database_url: str | None = None) -> AsyncEngine | None:
    """Initialize the database engine and session factory.

    Args:
        database_url: Database connection URL. Falls back to DATABASE_URL env var.

    Returns:
        AsyncEngine if configured, None otherwise.
    """
    global _engine, _session_factory

    url = database_url or os.environ.get("DATABASE_URL")
    if not url:
        return None

    _engine = create_async_engine(
        url,
        echo=False,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


async def close_db() -> None:
    """Close the database engine and release connections."""
    global _engine, _session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async generator yielding a database session. For use with FastAPI Depends."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Set DATABASE_URL or call init_db().")
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
