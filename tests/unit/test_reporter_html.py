"""Tests for HTML and PDF report generation."""

from datetime import datetime

import pytest

from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.scanner import ScanResult
from accessaudit.models.finding import Finding, FindingCategory, FindingSeverity


def _make_scan_result() -> ScanResult:
    """Create a minimal ScanResult for testing."""
    return ScanResult(
        scan_id="test-scan-001",
        provider="aws",
        started_at=datetime(2026, 3, 11, 10, 0, 0),
        completed_at=datetime(2026, 3, 11, 10, 5, 0),
    )


def _make_analysis_result() -> AnalysisResult:
    """Create an AnalysisResult with sample findings for testing."""
    findings = [
        Finding(
            id="f-001",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.EXCESSIVE_PERMISSIONS,
            account_id="arn:aws:iam::123456789012:user/admin",
            title="Admin has wildcard permissions",
            description="User admin has full wildcard (*:*) permissions.",
            remediation="Remove AdministratorAccess and apply least-privilege.",
        ),
        Finding(
            id="f-002",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.MISSING_MFA,
            account_id="arn:aws:iam::123456789012:user/dev",
            title="MFA not enabled for privileged user",
            description="User dev has elevated permissions but no MFA.",
            remediation="Enable MFA on this account.",
        ),
        Finding(
            id="f-003",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.DORMANT_ACCOUNT,
            account_id="arn:aws:iam::123456789012:user/old",
            title="Dormant account with active credentials",
            description="Account old has not logged in for 180 days.",
            remediation="Disable or remove the dormant account.",
        ),
        Finding(
            id="f-004",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.OVERPRIVILEGED_ROLE,
            account_id="arn:aws:iam::123456789012:role/deploy",
            title="Overprivileged deployment role",
            description="Role deploy has more permissions than needed.",
            remediation="Scope down the role permissions.",
        ),
    ]
    return AnalysisResult(
        scan_id="test-scan-001",
        analyzed_at=datetime(2026, 3, 11, 10, 6, 0),
        findings=findings,
        summary={
            "total_accounts": 10,
            "total_permissions": 50,
            "total_policies": 15,
            "total_findings": 4,
            "total_risk_score": 250,
            "average_risk_score": 62.5,
            "findings_by_severity": {
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "top_findings": [
                {
                    "severity": "critical",
                    "title": "Admin has wildcard permissions",
                    "account": "admin",
                },
                {
                    "severity": "high",
                    "title": "MFA not enabled for privileged user",
                    "account": "dev",
                },
            ],
        },
    )


class TestHTMLReportGeneration:
    """Tests for HTML report generation."""

    @pytest.mark.asyncio
    async def test_generate_html_report_executive(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        html = await reporter.generate_html_report(
            scan_result, analysis_result, template="executive"
        )

        assert isinstance(html, str)
        assert "<html" in html.lower()
        assert "AccessAudit" in html

    @pytest.mark.asyncio
    async def test_generate_soc2_html(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        html = await reporter.generate_html_report(scan_result, analysis_result, template="soc2")

        assert isinstance(html, str)
        assert "SOC 2" in html or "CC6" in html

    @pytest.mark.asyncio
    async def test_generate_iso27001_html(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        html = await reporter.generate_html_report(
            scan_result, analysis_result, template="iso27001"
        )

        assert isinstance(html, str)
        assert "ISO 27001" in html or "A.9" in html

    @pytest.mark.asyncio
    async def test_generate_html_report_writes_to_file(self, tmp_path):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()
        output_path = tmp_path / "report.html"

        html = await reporter.generate_html_report(
            scan_result, analysis_result, template="executive", output_path=output_path
        )

        assert output_path.exists()
        content = output_path.read_text()
        assert "<html" in content.lower()
        assert html == content

    @pytest.mark.asyncio
    async def test_generate_pdf_report(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        try:
            import weasyprint  # noqa: F401
        except ImportError:
            pytest.skip("weasyprint not installed")

        pdf_bytes = await reporter.generate_pdf_report(
            scan_result, analysis_result, template="executive"
        )

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        # PDF files start with %PDF
        assert pdf_bytes[:5] == b"%PDF-"

    @pytest.mark.asyncio
    async def test_generate_html_executive_contains_severity_info(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        html = await reporter.generate_html_report(
            scan_result, analysis_result, template="executive"
        )

        # Should contain severity information
        assert "critical" in html.lower() or "Critical" in html

    @pytest.mark.asyncio
    async def test_generate_soc2_html_contains_control_info(self):
        from accessaudit.core.reporter import Reporter

        reporter = Reporter()
        scan_result = _make_scan_result()
        analysis_result = _make_analysis_result()

        html = await reporter.generate_html_report(scan_result, analysis_result, template="soc2")

        # Should mention specific controls
        assert "CC6.1" in html
        assert "pass" in html.lower() or "fail" in html.lower()
