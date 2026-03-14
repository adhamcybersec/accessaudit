"""Integration test: remediation workflow."""

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from accessaudit.api.app import create_app
from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.scanner import ScanResult
from accessaudit.models import Finding, FindingCategory, FindingSeverity


@pytest.fixture
async def client():
    app = create_app()
    async with app.router.lifespan_context(app):
        # Seed with a completed scan and analysis
        storage = app.state.storage
        scan = ScanResult(
            scan_id="rem-scan-001",
            provider="aws",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            status="completed",
        )
        await storage.save_scan(scan)
        app.state.scans["rem-scan-001"] = scan

        analysis = AnalysisResult(
            scan_id="rem-scan-001",
            analyzed_at=datetime.now(),
            findings=[
                Finding(
                    id="f-dormant-1",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.DORMANT_ACCOUNT,
                    account_id="user-dormant",
                    title="Dormant account detected",
                    description="Account inactive for 120 days",
                    remediation="Disable the account",
                    detected_at=datetime.now(),
                ),
                Finding(
                    id="f-mfa-1",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.MISSING_MFA,
                    account_id="user-nomfa",
                    title="MFA not enabled for admin",
                    description="Admin account lacks MFA",
                    remediation="Enable MFA",
                    detected_at=datetime.now(),
                ),
            ],
            summary={"total_findings": 2},
        )
        await storage.save_analysis(analysis)
        app.state.analyses["rem-scan-001"] = analysis

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


async def test_suggest_approve_execute(client):
    """Suggest → approve → execute remediation workflow."""
    # Suggest
    resp = await client.post("/api/v1/remediations/suggest/rem-scan-001")
    assert resp.status_code == 200
    suggestions = resp.json()
    assert len(suggestions) == 2
    assert all(s["status"] == "pending" for s in suggestions)

    action_id = suggestions[0]["id"]

    # Get specific action
    resp = await client.get(f"/api/v1/remediations/{action_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    # Approve
    resp = await client.post(
        f"/api/v1/remediations/{action_id}/approve",
        json={"approved_by": "admin@test.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"

    # Execute
    resp = await client.post(f"/api/v1/remediations/{action_id}/execute")
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


async def test_reject_remediation(client):
    """Suggest → reject workflow."""
    resp = await client.post("/api/v1/remediations/suggest/rem-scan-001")
    suggestions = resp.json()
    action_id = suggestions[0]["id"]

    resp = await client.post(f"/api/v1/remediations/{action_id}/reject")
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"
