"""Integration tests for the FastAPI API workflow.

Exercises the full HTTP workflow:
  POST /api/v1/scans  ->  GET /api/v1/scans  ->  GET /api/v1/scans/{id}
  ->  POST /api/v1/analyze/{scan_id}  ->  GET /api/v1/scans/{id}/findings
  ->  GET /api/v1/reports/{scan_id}

The Scanner is mocked at the class level (not the connector) because we are
testing the API layer, not the cloud connectors.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from accessaudit.api.app import create_app
from accessaudit.core.scanner import ScanResult, Scanner
from accessaudit.models import (
    Account,
    AccountStatus,
    Permission,
    PermissionScope,
    Policy,
)


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------


def _build_scan_result(scan_id: str) -> ScanResult:
    """Build a realistic completed ScanResult for testing."""
    accounts = [
        Account(
            id="arn:aws:iam::123456789012:user/test-admin",
            username="test-admin",
            provider="aws",
            status=AccountStatus.ACTIVE,
            mfa_enabled=False,
            has_admin_role=True,
            groups=["admins"],
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 1, tzinfo=timezone.utc),
        ),
        Account(
            id="arn:aws:iam::123456789012:user/test-dev",
            username="test-dev",
            provider="aws",
            status=AccountStatus.ACTIVE,
            mfa_enabled=True,
            has_admin_role=False,
            groups=["developers"],
            created_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 10, tzinfo=timezone.utc),
        ),
    ]

    admin_id = accounts[0].id
    dev_id = accounts[1].id

    permissions = {
        admin_id: [
            Permission(
                id="perm-admin-1",
                account_id=admin_id,
                resource_type="iam",
                resource_arn="*",
                actions=["*"],
                effect="Allow",
                scope=PermissionScope.ADMIN,
                source_policy="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
        ],
        dev_id: [
            Permission(
                id="perm-dev-1",
                account_id=dev_id,
                resource_type="s3",
                resource_arn="arn:aws:s3:::bucket/*",
                actions=["s3:GetObject"],
                effect="Allow",
                scope=PermissionScope.READ,
                source_policy="arn:aws:iam::aws:policy/S3ReadOnly",
            ),
        ],
    }

    policies = [
        Policy(
            id="arn:aws:iam::aws:policy/AdministratorAccess",
            name="AdministratorAccess",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            provider="aws",
            policy_type="managed",
            document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
            attached_to=[admin_id],
            is_aws_managed=True,
        ),
    ]

    return ScanResult(
        scan_id=scan_id,
        provider="aws",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        accounts=accounts,
        permissions=permissions,
        policies=policies,
        status="completed",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Create a fresh FastAPI app for each test."""
    return create_app()


@pytest.fixture
def client(app):
    """Provide an httpx.AsyncClient bound to the test app."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAPIWorkflow:
    """End-to-end API workflow tests."""

    async def test_full_workflow(self, client: httpx.AsyncClient, app):
        """POST scan -> list scans -> get scan -> analyze -> findings -> report.

        The /scans POST endpoint fires a background task that calls Scanner.scan().
        We patch Scanner.scan for the entire duration so the background task picks
        up the mock, then give it a moment to complete.
        """

        async def mock_scan(self_scanner, provider, provider_config=None):
            result = _build_scan_result("temp")
            result.provider = provider
            return result

        # Keep the patch active long enough for the background task to run.
        with patch.object(Scanner, "scan", new=mock_scan):
            # ------- 1. Trigger a scan -------
            resp = await client.post(
                "/api/v1/scans",
                json={"provider": "aws", "config": {}},
            )

            assert resp.status_code == 202
            data = resp.json()
            assert "scan_id" in data
            scan_id = data["scan_id"]

            # Allow the background task to finish inside the patch scope.
            await asyncio.sleep(0.5)

        # ------- 2. List scans -------
        resp = await client.get("/api/v1/scans")
        assert resp.status_code == 200
        scans = resp.json()
        assert isinstance(scans, list)
        assert len(scans) >= 1
        scan_ids = [s["scan_id"] for s in scans]
        assert scan_id in scan_ids

        # ------- 3. Get scan details -------
        resp = await client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        scan_detail = resp.json()
        assert scan_detail["scan_id"] == scan_id
        assert scan_detail["provider"] == "aws"
        assert scan_detail["status"] == "completed"

        # ------- 4. Run analysis -------
        resp = await client.post(f"/api/v1/analyze/{scan_id}")
        assert resp.status_code == 200
        analysis = resp.json()
        assert analysis["scan_id"] == scan_id
        assert "findings" in analysis
        assert analysis["finding_count"] > 0

        # ------- 5. Get findings -------
        resp = await client.get(f"/api/v1/scans/{scan_id}/findings")
        assert resp.status_code == 200
        findings = resp.json()
        assert findings["finding_count"] > 0

        # ------- 6. Get JSON report -------
        resp = await client.get(f"/api/v1/reports/{scan_id}?format=json")
        assert resp.status_code == 200
        report = resp.json()
        assert "scan" in report
        assert "findings" in report
        assert "accounts" in report
        assert "recommendations" in report

    async def test_scan_not_found(self, client: httpx.AsyncClient):
        """GET /scans/{id} returns 404 for unknown scan."""
        resp = await client.get("/api/v1/scans/nonexistent")
        assert resp.status_code == 404

    async def test_analyze_requires_completed_scan(self, client: httpx.AsyncClient, app):
        """POST /analyze/{id} returns 400 when scan is not completed."""
        # Insert a pending scan directly
        from accessaudit.core.scanner import ScanResult

        pending = ScanResult(
            scan_id="pending-1",
            provider="aws",
            started_at=datetime.now(),
            status="pending",
        )
        app.state.scans["pending-1"] = pending

        resp = await client.post("/api/v1/analyze/pending-1")
        assert resp.status_code == 400
        assert "not completed" in resp.json()["detail"]

    async def test_findings_require_analysis(self, client: httpx.AsyncClient, app):
        """GET /scans/{id}/findings returns 404 when no analysis exists."""
        completed = ScanResult(
            scan_id="completed-no-analysis",
            provider="aws",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            status="completed",
        )
        app.state.scans["completed-no-analysis"] = completed

        resp = await client.get("/api/v1/scans/completed-no-analysis/findings")
        assert resp.status_code == 404
        assert "No analysis found" in resp.json()["detail"]

    async def test_report_requires_analysis(self, client: httpx.AsyncClient, app):
        """GET /reports/{id} returns 404 when no analysis exists."""
        completed = ScanResult(
            scan_id="completed-no-report",
            provider="aws",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            status="completed",
        )
        app.state.scans["completed-no-report"] = completed

        resp = await client.get("/api/v1/reports/completed-no-report?format=json")
        assert resp.status_code == 404

    async def test_direct_analyze_and_report(self, client: httpx.AsyncClient, app):
        """Inject a completed scan directly, then analyze and generate report."""
        scan_result = _build_scan_result("direct-1")
        app.state.scans["direct-1"] = scan_result

        # Analyze
        resp = await client.post("/api/v1/analyze/direct-1")
        assert resp.status_code == 200
        analysis = resp.json()
        assert analysis["finding_count"] > 0

        # Report
        resp = await client.get("/api/v1/reports/direct-1?format=json")
        assert resp.status_code == 200
        report = resp.json()
        assert report["findings"]["total"] > 0
        assert len(report["accounts"]) == 2
