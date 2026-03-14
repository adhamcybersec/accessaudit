"""Integration test: scheduled scan lifecycle."""

import pytest
from httpx import ASGITransport, AsyncClient

from accessaudit.api.app import create_app


@pytest.fixture
async def client():
    app = create_app()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


async def test_schedule_crud(client):
    """Create → list → get → disable → delete schedule."""
    # Create
    resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Test AWS Scan",
            "provider": "aws",
            "cron_expression": "0 2 * * *",
        },
    )
    assert resp.status_code == 201
    schedule = resp.json()
    schedule_id = schedule["id"]
    assert schedule["name"] == "Test AWS Scan"
    assert schedule["enabled"] is True

    # List
    resp = await client.get("/api/v1/schedules")
    assert resp.status_code == 200
    assert any(s["id"] == schedule_id for s in resp.json())

    # Get
    resp = await client.get(f"/api/v1/schedules/{schedule_id}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "Test AWS Scan"

    # Disable
    resp = await client.post(f"/api/v1/schedules/{schedule_id}/disable")
    assert resp.status_code == 200

    # Verify disabled
    resp = await client.get(f"/api/v1/schedules/{schedule_id}")
    assert resp.json()["enabled"] is False

    # Delete
    resp = await client.delete(f"/api/v1/schedules/{schedule_id}")
    assert resp.status_code == 204


async def test_invalid_cron_rejected(client):
    """Creating schedule with invalid cron returns 400."""
    resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Bad Schedule",
            "provider": "aws",
            "cron_expression": "invalid",
        },
    )
    assert resp.status_code == 400
