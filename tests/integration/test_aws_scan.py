"""Integration tests for AWS IAM scanning.

These tests require real AWS credentials or LocalStack.
Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.

To run with LocalStack:
    docker run -d --name localstack -p 4566:4566 localstack/localstack
    export AWS_ENDPOINT_URL=http://localhost:4566
    pytest tests/integration/ -v
"""

import os

import pytest

from accessaudit.connectors.aws import AWSConnector
from accessaudit.core.analyzer import Analyzer
from accessaudit.core.reporter import Reporter
from accessaudit.core.scanner import Scanner


# Skip tests if no AWS credentials
HAS_AWS_CREDENTIALS = bool(
    os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")
)


@pytest.mark.skipif(not HAS_AWS_CREDENTIALS, reason="AWS credentials not configured")
class TestAWSIntegration:
    """Integration tests for AWS IAM scanning."""

    @pytest.fixture
    def aws_config(self):
        """AWS configuration from environment."""
        return {
            "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            "access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
            "secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        }

    @pytest.mark.asyncio
    async def test_aws_connection(self, aws_config):
        """Test AWS IAM connection."""
        connector = AWSConnector(aws_config)
        result = await connector.test_connection()
        assert result is True

    @pytest.mark.asyncio
    async def test_aws_list_accounts(self, aws_config):
        """Test listing AWS IAM users."""
        connector = AWSConnector(aws_config)
        await connector.connect()

        accounts = await connector.list_accounts()

        assert isinstance(accounts, list)
        # Should have at least one user (the one running the test)
        # Note: This depends on your AWS account setup

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_full_scan(self, aws_config):
        """Test full AWS IAM scan."""
        scanner = Scanner()
        scan_result = await scanner.scan("aws", aws_config)

        assert scan_result.status in ["completed", "running"]
        assert scan_result.provider == "aws"
        assert isinstance(scan_result.accounts, list)
        assert isinstance(scan_result.permissions, dict)

    @pytest.mark.asyncio
    async def test_scan_and_analyze(self, aws_config):
        """Test scan followed by analysis."""
        scanner = Scanner()
        scan_result = await scanner.scan("aws", aws_config)

        analyzer = Analyzer()
        analysis_result = await analyzer.analyze(scan_result)

        assert analysis_result.scan_id == scan_result.scan_id
        assert isinstance(analysis_result.findings, list)
        assert "total_findings" in analysis_result.summary

    @pytest.mark.asyncio
    async def test_full_pipeline(self, aws_config, tmp_path):
        """Test full scan -> analyze -> report pipeline."""
        # Scan
        scanner = Scanner()
        scan_result = await scanner.scan("aws", aws_config)

        # Analyze
        analyzer = Analyzer()
        analysis_result = await analyzer.analyze(scan_result)

        # Report
        reporter = Reporter()
        report_path = tmp_path / "report.json"
        report = await reporter.generate_json_report(
            scan_result, analysis_result, report_path
        )

        assert report_path.exists()
        assert "scan" in report
        assert "analysis" in report
        assert "findings" in report
        assert "recommendations" in report


@pytest.mark.skipif(not HAS_AWS_CREDENTIALS, reason="AWS credentials not configured")
class TestAWSFindingsIntegration:
    """Integration tests for AWS findings."""

    @pytest.fixture
    def aws_config(self):
        """AWS configuration from environment."""
        return {
            "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        }

    @pytest.mark.asyncio
    async def test_findings_structure(self, aws_config):
        """Test findings have correct structure."""
        scanner = Scanner()
        scan_result = await scanner.scan("aws", aws_config)

        analyzer = Analyzer()
        analysis_result = await analyzer.analyze(scan_result)

        for finding in analysis_result.findings:
            assert finding.id is not None
            assert finding.severity is not None
            assert finding.category is not None
            assert finding.title is not None
            assert finding.description is not None
            assert finding.remediation is not None
