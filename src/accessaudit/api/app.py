"""FastAPI application factory."""

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from accessaudit.api.routes import (
    dashboard,
    findings,
    health,
    notifications,
    reports,
    rules,
    scans,
    schedules,
)
from accessaudit.auth.routes import router as auth_router
from accessaudit.services.storage import InMemoryStorage

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize and teardown DB, Redis, storage."""
    database_url = os.environ.get("DATABASE_URL")
    redis_url = os.environ.get("REDIS_URL")

    # Initialize database if configured
    if database_url:
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from accessaudit.db.engine import init_db

        engine = await init_db(database_url)
        if engine:
            from sqlalchemy.ext.asyncio import AsyncSession

            app.state.session_factory = async_sessionmaker(engine, expire_on_commit=False)
            app.state.db_available = True
            logger.info("Database initialized")
        else:
            app.state.db_available = False
    else:
        app.state.db_available = False
        app.state.session_factory = None

    # Initialize Redis if configured
    cache_service = None
    if redis_url:
        from accessaudit.db.cache import CacheService, get_redis

        redis_client = await get_redis()
        if redis_client:
            cache_service = CacheService(redis_client)
            app.state.redis_available = True
            logger.info("Redis initialized")
        else:
            app.state.redis_available = False
    else:
        app.state.redis_available = False

    # Set up storage backend
    if app.state.db_available and app.state.session_factory:
        from accessaudit.services.storage import DatabaseStorage

        app.state.storage = DatabaseStorage(app.state.session_factory, cache_service)
        app.state.storage_mode = "database"
    else:
        app.state.storage = InMemoryStorage()
        app.state.storage_mode = "memory"

    logger.info("Storage mode: %s", app.state.storage_mode)

    # Initialize scheduler
    from accessaudit.scheduling.service import SchedulerService

    scheduler = SchedulerService()
    app.state.scheduler = scheduler
    await scheduler.start()

    yield

    # Stop scheduler
    await scheduler.stop()

    # Teardown
    if app.state.db_available:
        from accessaudit.db.engine import close_db

        await close_db()

    if redis_url:
        from accessaudit.db.cache import close_redis

        await close_redis()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI app instance with all routes registered
        and storage initialized via lifespan.
    """
    app = FastAPI(
        title="AccessAudit",
        description="IAM Access Review Automation API",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Legacy in-memory stores for backward compatibility in tests
    # that directly manipulate app.state.scans/analyses
    app.state.scans = {}
    app.state.analyses = {}

    # Register routers
    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(rules.router)
    app.include_router(auth_router)
    app.include_router(notifications.router)
    app.include_router(schedules.router)
    app.include_router(dashboard.router)

    return app
