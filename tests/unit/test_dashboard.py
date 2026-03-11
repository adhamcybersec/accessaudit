"""Tests for the HTMX dashboard routes."""

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


async def test_dashboard_home(client):
    """GET / returns 200 with HTML containing AccessAudit branding."""
    response = await client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "AccessAudit" in text
    assert "htmx" in text.lower() or "htmx.org" in text
    assert "tailwindcss" in text.lower() or "cdn.tailwindcss.com" in text


async def test_scans_page(client):
    """GET /scans returns 200 with HTML showing scans interface."""
    response = await client.get("/scans")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "Scans" in text or "scans" in text
    # Should have navigation links
    assert 'href="/"' in text or 'href="/' in text


async def test_findings_page(client):
    """GET /findings returns 200 with HTML showing findings interface."""
    response = await client.get("/findings")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "Findings" in text or "findings" in text


async def test_reports_page(client):
    """GET /reports returns 200 with HTML showing reports interface."""
    response = await client.get("/reports")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "Reports" in text or "reports" in text


async def test_rules_page(client):
    """GET /rules-dashboard returns 200 with HTML showing rules interface."""
    response = await client.get("/rules-dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "Rules" in text or "rules" in text


async def test_dashboard_shows_scan_data(client, app):
    """Dashboard home shows scan data when scans exist."""
    scan = ScanResult(
        scan_id="dash-test-1",
        provider="aws",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        status="completed",
    )
    app.state.scans["dash-test-1"] = scan

    response = await client.get("/")
    assert response.status_code == 200
    assert "dash-test-1" in response.text or "1" in response.text


async def test_scans_page_with_data(client, app):
    """Scans page displays existing scan entries."""
    scan = ScanResult(
        scan_id="scan-abc",
        provider="azure",
        started_at=datetime.now(),
        status="running",
    )
    app.state.scans["scan-abc"] = scan

    response = await client.get("/scans")
    assert response.status_code == 200
    assert "scan-abc" in response.text


async def test_dashboard_nav_links(client):
    """Dashboard includes navigation links to all main pages."""
    response = await client.get("/")
    text = response.text
    assert "/scans" in text
    assert "/findings" in text
    assert "/reports" in text
