"""Tests for Redis cache service."""

import pytest

from accessaudit.db.cache import CacheService


@pytest.fixture
def cache_no_redis():
    """CacheService with no Redis (graceful degradation)."""
    return CacheService(redis_client=None)


async def test_get_scan_no_redis(cache_no_redis):
    result = await cache_no_redis.get_scan("test-id")
    assert result is None


async def test_set_scan_no_redis(cache_no_redis):
    # Should not raise
    await cache_no_redis.set_scan("test-id", {"scan_id": "test-id"})


async def test_invalidate_scan_no_redis(cache_no_redis):
    # Should not raise
    await cache_no_redis.invalidate_scan("test-id")


async def test_get_analysis_no_redis(cache_no_redis):
    result = await cache_no_redis.get_analysis("test-id")
    assert result is None


async def test_set_analysis_no_redis(cache_no_redis):
    # Should not raise
    await cache_no_redis.set_analysis("test-id", {"scan_id": "test-id"})


async def test_invalidate_analysis_no_redis(cache_no_redis):
    # Should not raise
    await cache_no_redis.invalidate_analysis("test-id")


class FakeRedis:
    """Minimal fake Redis for testing cache operations."""

    def __init__(self):
        self._store = {}

    async def get(self, key):
        return self._store.get(key)

    async def set(self, key, value, ex=None):
        self._store[key] = value

    async def delete(self, key):
        self._store.pop(key, None)


@pytest.fixture
def cache_with_redis():
    return CacheService(redis_client=FakeRedis())


async def test_set_and_get_scan(cache_with_redis):
    data = {"scan_id": "scan-1", "provider": "aws"}
    await cache_with_redis.set_scan("scan-1", data)
    result = await cache_with_redis.get_scan("scan-1")
    assert result is not None
    assert result["scan_id"] == "scan-1"


async def test_invalidate_scan(cache_with_redis):
    data = {"scan_id": "scan-1"}
    await cache_with_redis.set_scan("scan-1", data)
    await cache_with_redis.invalidate_scan("scan-1")
    result = await cache_with_redis.get_scan("scan-1")
    assert result is None


async def test_set_and_get_analysis(cache_with_redis):
    data = {"scan_id": "scan-1", "finding_count": 5}
    await cache_with_redis.set_analysis("scan-1", data)
    result = await cache_with_redis.get_analysis("scan-1")
    assert result is not None
    assert result["finding_count"] == 5
