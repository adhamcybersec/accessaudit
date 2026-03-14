"""Redis cache service with graceful degradation."""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_redis_client: Any = None

_DEFAULT_TTL = 3600  # 1 hour


async def get_redis() -> Any:
    """Get Redis client. Returns None if REDIS_URL is unset or connection fails."""
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    url = os.environ.get("REDIS_URL")
    if not url:
        return None

    try:
        import redis.asyncio as aioredis

        _redis_client = aioredis.from_url(url, decode_responses=True)
        await _redis_client.ping()
        return _redis_client
    except Exception:
        logger.warning("Redis connection failed, caching disabled")
        _redis_client = None
        return None


async def close_redis() -> None:
    """Close Redis connection."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None


class CacheService:
    """Cache service wrapping Redis with graceful degradation.

    All methods no-op when Redis is unavailable.
    Key pattern: accessaudit:{entity}:{id}
    """

    def __init__(self, redis_client: Any = None):
        self.redis = redis_client

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Get cached scan data."""
        if self.redis is None:
            return None
        try:
            data = await self.redis.get(f"accessaudit:scan:{scan_id}")
            if data:
                return json.loads(data)  # type: ignore[no-any-return]
        except Exception:
            logger.debug("Cache read failed for scan %s", scan_id)
        return None

    async def set_scan(self, scan_id: str, data: dict[str, Any], ttl: int = _DEFAULT_TTL) -> None:
        """Cache scan data."""
        if self.redis is None:
            return
        try:
            await self.redis.set(
                f"accessaudit:scan:{scan_id}", json.dumps(data, default=str), ex=ttl
            )
        except Exception:
            logger.debug("Cache write failed for scan %s", scan_id)

    async def invalidate_scan(self, scan_id: str) -> None:
        """Remove scan from cache."""
        if self.redis is None:
            return
        try:
            await self.redis.delete(f"accessaudit:scan:{scan_id}")
        except Exception:
            logger.debug("Cache invalidate failed for scan %s", scan_id)

    async def get_analysis(self, scan_id: str) -> dict[str, Any] | None:
        """Get cached analysis data."""
        if self.redis is None:
            return None
        try:
            data = await self.redis.get(f"accessaudit:analysis:{scan_id}")
            if data:
                return json.loads(data)  # type: ignore[no-any-return]
        except Exception:
            logger.debug("Cache read failed for analysis %s", scan_id)
        return None

    async def set_analysis(
        self, scan_id: str, data: dict[str, Any], ttl: int = _DEFAULT_TTL
    ) -> None:
        """Cache analysis data."""
        if self.redis is None:
            return
        try:
            await self.redis.set(
                f"accessaudit:analysis:{scan_id}", json.dumps(data, default=str), ex=ttl
            )
        except Exception:
            logger.debug("Cache write failed for analysis %s", scan_id)

    async def invalidate_analysis(self, scan_id: str) -> None:
        """Remove analysis from cache."""
        if self.redis is None:
            return
        try:
            await self.redis.delete(f"accessaudit:analysis:{scan_id}")
        except Exception:
            logger.debug("Cache invalidate failed for analysis %s", scan_id)
