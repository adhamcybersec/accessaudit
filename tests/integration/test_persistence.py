"""Integration test: full flow with persistence.

Requires DATABASE_URL and REDIS_URL environment variables.
"""

import os

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set (integration test)",
)


@pytest.fixture
async def client():
    """Create test client with real DB/Redis backends."""
    from accessaudit.api.app import create_app

    app = create_app()

    # Trigger lifespan manually
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


async def test_health_shows_db_connected(client):
    """Health endpoint shows database as connected."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["components"]["database"] == "connected"
    assert data["components"]["storage"] == "database"


async def test_full_persistence_flow(client):
    """Register → login → trigger scan → verify persisted."""
    # Register
    reg = await client.post(
        "/api/v1/auth/register",
        json={"email": "integration@test.com", "password": "test123"},
    )
    assert reg.status_code == 201
    api_key = reg.json()["api_key"]

    headers = {"X-API-Key": api_key}

    # Trigger scan (will fail without real AWS, but creates record)
    scan = await client.post(
        "/api/v1/scans",
        json={"provider": "aws", "config": {}},
        headers=headers,
    )
    assert scan.status_code == 202
    scan_id = scan.json()["scan_id"]

    # List scans should include our scan
    scans = await client.get("/api/v1/scans", headers=headers)
    assert scans.status_code == 200
    scan_ids = [s["scan_id"] for s in scans.json()]
    assert scan_id in scan_ids
