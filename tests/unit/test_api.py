"""Tests for the FastAPI REST API."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from accessaudit.api.app import create_app
from accessaudit.core.scanner import ScanResult


@pytest.fixture
def app():
    """Create a test app instance."""
    return create_app()


@pytest.fixture
async def client(app):
    """Create an async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_health_check(client):
    """GET /api/v1/health returns 200 with status ok."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


async def test_list_scans_empty(client):
    """GET /api/v1/scans returns empty list when no scans exist."""
    response = await client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert data == []


async def test_trigger_scan(client, app):
    """POST /api/v1/scans returns 202 with scan_id."""
    mock_result = ScanResult(
        scan_id="test1234",
        provider="aws",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        status="completed",
    )

    with patch("accessaudit.api.routes.scans.Scanner") as MockScanner:
        instance = MockScanner.return_value
        instance.scan = AsyncMock(return_value=mock_result)

        response = await client.post(
            "/api/v1/scans",
            json={"provider": "aws", "config": {}},
        )

    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "pending"

    # Give background task time to run
    await asyncio.sleep(0.2)


async def test_get_scan_not_found(client):
    """GET /api/v1/scans/nonexistent returns 404."""
    response = await client.get("/api/v1/scans/nonexistent")
    assert response.status_code == 404


async def test_get_scan_found(client, app):
    """GET /api/v1/scans/{id} returns scan data when it exists."""
    scan_result = ScanResult(
        scan_id="found123",
        provider="aws",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        status="completed",
    )
    app.state.scans["found123"] = scan_result

    response = await client.get("/api/v1/scans/found123")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "found123"
    assert data["provider"] == "aws"


async def test_get_scan_findings_not_found(client):
    """GET /api/v1/scans/{id}/findings returns 404 when scan doesn't exist."""
    response = await client.get("/api/v1/scans/nonexistent/findings")
    assert response.status_code == 404


async def test_list_rules(client):
    """GET /api/v1/rules returns 200 with rules list."""
    response = await client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


async def test_validate_rules(client):
    """POST /api/v1/rules/validate returns validation result."""
    response = await client.post(
        "/api/v1/rules/validate",
        json={"policy": "package test\ndeny[msg] { msg := \"test\" }"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data


async def test_analyze_scan_not_found(client):
    """POST /api/v1/analyze/{scan_id} returns 404 when scan doesn't exist."""
    response = await client.post("/api/v1/analyze/nonexistent")
    assert response.status_code == 404


async def test_get_report_scan_not_found(client):
    """GET /api/v1/reports/{scan_id} returns 404 when scan doesn't exist."""
    response = await client.get("/api/v1/reports/nonexistent")
    assert response.status_code == 404


async def test_list_scans_after_adding(client, app):
    """GET /api/v1/scans returns scans after they've been added."""
    scan_result = ScanResult(
        scan_id="list1234",
        provider="aws",
        started_at=datetime.now(),
        status="completed",
    )
    app.state.scans["list1234"] = scan_result

    response = await client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert any(s["scan_id"] == "list1234" for s in data)
