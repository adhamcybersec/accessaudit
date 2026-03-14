"""Health check endpoint."""

from typing import Any

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health")
async def health_check(request: Request) -> dict[str, Any]:
    """Return service health status with component checks."""
    components: dict[str, str] = {}

    # Database health
    db_available = getattr(request.app.state, "db_available", False)
    components["database"] = "connected" if db_available else "not_configured"

    # Redis health
    redis_available = getattr(request.app.state, "redis_available", False)
    components["redis"] = "connected" if redis_available else "not_configured"

    # Storage mode
    storage_mode = getattr(request.app.state, "storage_mode", "memory")
    components["storage"] = storage_mode

    return {"status": "ok", "components": components}
