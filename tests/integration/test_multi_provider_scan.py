"""Integration tests for multi-provider scan -> analyze -> report pipeline.

These tests mock at the connector level (not Scanner/Analyzer) to exercise the
full pipeline with realistic data from multiple providers.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from accessaudit.connectors.aws import AWSConnector
from accessaudit.connectors.azure import AzureConnector
from accessaudit.connectors.gcp import GCPConnector
from accessaudit.core.analyzer import Analyzer
from accessaudit.core.reporter import Reporter
from accessaudit.core.scanner import Scanner
from accessaudit.models import (
    Account,
    AccountStatus,
    Permission,
    PermissionScope,
    Policy,
)


# ---------------------------------------------------------------------------
# Shared test data factories
# ---------------------------------------------------------------------------

def _aws_accounts() -> list[Account]:
    return [
        Account(
            id="arn:aws:iam::123456789012:user/admin-user",
            username="admin-user",
            provider="aws",
            status=AccountStatus.ACTIVE,
            mfa_enabled=False,
            has_admin_role=True,
            groups=["admins"],
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 1, tzinfo=timezone.utc),
        ),
        Account(
            id="arn:aws:iam::123456789012:user/dev-user",
            username="dev-user",
            provider="aws",
            status=AccountStatus.ACTIVE,
            mfa_enabled=True,
            has_admin_role=False,
            groups=["developers"],
            created_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 10, tzinfo=timezone.utc),
        ),
        Account(
            id="arn:aws:iam::123456789012:user/dormant-user",
            username="dormant-user",
            provider="aws",
            status=AccountStatus.ACTIVE,
            mfa_enabled=False,
            has_admin_role=False,
            groups=[],
            created_at=datetime(2023, 1, 1, tzinfo=timezone.utc),
            last_activity=datetime(2023, 6, 1, tzinfo=timezone.utc),
        ),
    ]


def _aws_permissions() -> dict[str, list[Permission]]:
    admin_id = "arn:aws:iam::123456789012:user/admin-user"
    dev_id = "arn:aws:iam::123456789012:user/dev-user"
    dormant_id = "arn:aws:iam::123456789012:user/dormant-user"
    return {
        admin_id: [
            Permission(
                id="perm-aws-admin-1",
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
                id="perm-aws-dev-1",
                account_id=dev_id,
                resource_type="s3",
                resource_arn="arn:aws:s3:::my-bucket/*",
                actions=["s3:GetObject", "s3:ListBucket"],
                effect="Allow",
                scope=PermissionScope.READ,
                source_policy="arn:aws:iam::aws:policy/S3ReadOnly",
            ),
        ],
        dormant_id: [
            Permission(
                id="perm-aws-dormant-1",
                account_id=dormant_id,
                resource_type="ec2",
                resource_arn="*",
                actions=["ec2:Describe*"],
                effect="Allow",
                scope=PermissionScope.READ,
                source_policy="arn:aws:iam::aws:policy/EC2ReadOnly",
            ),
        ],
    }


def _aws_policies() -> list[Policy]:
    return [
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
            attached_to=["arn:aws:iam::123456789012:user/admin-user"],
            is_aws_managed=True,
        ),
        Policy(
            id="arn:aws:iam::aws:policy/S3ReadOnly",
            name="S3ReadOnly",
            arn="arn:aws:iam::aws:policy/S3ReadOnly",
            provider="aws",
            policy_type="managed",
            document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    }
                ],
            },
            attached_to=["arn:aws:iam::123456789012:user/dev-user"],
            is_aws_managed=True,
        ),
    ]


def _azure_accounts() -> list[Account]:
    return [
        Account(
            id="azure-user-001",
            username="admin@contoso.onmicrosoft.com",
            email="admin@contoso.onmicrosoft.com",
            provider="azure",
            status=AccountStatus.ACTIVE,
            mfa_enabled=True,
            has_admin_role=True,
            groups=["Global Administrators"],
            created_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 9, tzinfo=timezone.utc),
        ),
        Account(
            id="azure-user-002",
            username="dev@contoso.onmicrosoft.com",
            email="dev@contoso.onmicrosoft.com",
            provider="azure",
            status=AccountStatus.ACTIVE,
            mfa_enabled=False,
            has_admin_role=False,
            groups=["Developers"],
            created_at=datetime(2024, 2, 20, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 11, tzinfo=timezone.utc),
        ),
    ]


def _azure_permissions() -> dict[str, list[Permission]]:
    admin_id = "azure-user-001"
    dev_id = "azure-user-002"
    return {
        admin_id: [
            Permission(
                id="perm-azure-admin-1",
                account_id=admin_id,
                resource_type="directory",
                resource_arn="/directory/roles/global-admin",
                actions=["directory:Global Administrator"],
                effect="Allow",
                source_policy="DirectoryRole:Global Administrator",
            ),
        ],
        dev_id: [
            Permission(
                id="perm-azure-dev-1",
                account_id=dev_id,
                resource_type="subscription",
                resource_arn="/subscriptions/sub-123",
                actions=["rbac:Reader"],
                effect="Allow",
                source_policy="RBAC:Reader",
            ),
        ],
    }


def _azure_policies() -> list[Policy]:
    return [
        Policy(
            id="azure-role-owner",
            name="Owner",
            arn="azure-role-owner",
            provider="azure",
            policy_type="builtin",
            document={
                "permissions": [{"actions": ["*"], "notActions": []}],
            },
            is_aws_managed=False,
        ),
    ]


def _gcp_accounts() -> list[Account]:
    return [
        Account(
            id="sa-admin@my-project.iam.gserviceaccount.com",
            username="sa-admin@my-project.iam.gserviceaccount.com",
            email="sa-admin@my-project.iam.gserviceaccount.com",
            provider="gcp",
            status=AccountStatus.ACTIVE,
            mfa_enabled=False,
            has_admin_role=True,
            groups=[],
            created_at=datetime(2024, 1, 10, tzinfo=timezone.utc),
            last_activity=datetime(2024, 3, 5, tzinfo=timezone.utc),
        ),
    ]


def _gcp_permissions() -> dict[str, list[Permission]]:
    sa_id = "sa-admin@my-project.iam.gserviceaccount.com"
    return {
        sa_id: [
            Permission(
                id="perm-gcp-sa-1",
                account_id=sa_id,
                resource_type="project",
                resource_arn="projects/my-project",
                actions=["roles/owner"],
                effect="Allow",
                source_policy="roles/owner",
            ),
        ],
    }


def _gcp_policies() -> list[Policy]:
    return [
        Policy(
            id="roles/owner",
            name="Owner",
            arn="roles/owner",
            provider="gcp",
            policy_type="predefined",
            document={"includedPermissions": ["*"]},
            is_aws_managed=False,
        ),
    ]


# ---------------------------------------------------------------------------
# Helper: patch a connector class so that connect/disconnect are noops and
# list_accounts / get_account_permissions / list_policies return test data.
# ---------------------------------------------------------------------------

def _mock_connector(connector_cls, accounts, permissions, policies):
    """Return a patched connector whose async methods return canned data."""
    instance = AsyncMock(spec=connector_cls)
    instance.connect = AsyncMock()
    instance.disconnect = AsyncMock()
    instance.list_accounts = AsyncMock(return_value=accounts)
    instance.list_policies = AsyncMock(return_value=policies)

    async def _get_perms(account_id):
        return permissions.get(account_id, [])

    instance.get_account_permissions = AsyncMock(side_effect=_get_perms)
    return instance


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMultiProviderScanPipeline:
    """Full scan -> analyze -> report pipeline with mocked providers."""

    async def test_aws_pipeline(self, tmp_path):
        """Test full pipeline with mocked AWS connector."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )

        with patch.object(Scanner, "_create_connector", return_value=mock_aws):
            scanner = Scanner()
            scan_result = await scanner.scan("aws")

        assert scan_result.status == "completed"
        assert len(scan_result.accounts) == 3
        assert len(scan_result.policies) == 2

        # Analyze
        analyzer = Analyzer()
        analysis = await analyzer.analyze(scan_result)

        assert analysis.scan_id == scan_result.scan_id
        assert len(analysis.findings) > 0
        assert "total_findings" in analysis.summary
        assert analysis.summary["total_accounts"] == 3

        # Report
        reporter = Reporter()
        report = await reporter.generate_json_report(
            scan_result, analysis, tmp_path / "aws_report.json"
        )

        assert (tmp_path / "aws_report.json").exists()
        assert "scan" in report
        assert "findings" in report
        assert report["findings"]["total"] > 0
        assert "recommendations" in report

    async def test_azure_pipeline(self, tmp_path):
        """Test full pipeline with mocked Azure connector."""
        mock_azure = _mock_connector(
            AzureConnector, _azure_accounts(), _azure_permissions(), _azure_policies()
        )

        with patch.object(Scanner, "_create_connector", return_value=mock_azure):
            scanner = Scanner()
            scan_result = await scanner.scan("azure")

        assert scan_result.status == "completed"
        assert scan_result.provider == "azure"
        assert len(scan_result.accounts) == 2

        analyzer = Analyzer()
        analysis = await analyzer.analyze(scan_result)

        assert len(analysis.findings) > 0

        reporter = Reporter()
        report = await reporter.generate_json_report(
            scan_result, analysis, tmp_path / "azure_report.json"
        )

        assert (tmp_path / "azure_report.json").exists()
        assert report["findings"]["total"] > 0

    async def test_aws_plus_azure_multi_provider(self, tmp_path):
        """Test scanning two providers concurrently and merging results."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )
        mock_azure = _mock_connector(
            AzureConnector, _azure_accounts(), _azure_permissions(), _azure_policies()
        )

        def _pick_connector(provider, _config):
            if provider == "aws":
                return mock_aws
            if provider == "azure":
                return mock_azure
            raise ValueError(f"Unknown provider: {provider}")

        with patch.object(Scanner, "_create_connector", side_effect=_pick_connector):
            scanner = Scanner()
            results = await scanner.scan_multiple(["aws", "azure"])

        assert "aws" in results
        assert "azure" in results

        aws_result = results["aws"]
        azure_result = results["azure"]

        assert aws_result.status == "completed"
        assert azure_result.status == "completed"
        assert len(aws_result.accounts) == 3
        assert len(azure_result.accounts) == 2

        # Analyze both
        analyzer = Analyzer()
        aws_analysis = await analyzer.analyze(aws_result)
        azure_analysis = await analyzer.analyze(azure_result)

        total_findings = len(aws_analysis.findings) + len(azure_analysis.findings)
        assert total_findings > 0

        # Generate reports for both
        reporter = Reporter()
        aws_report = await reporter.generate_json_report(
            aws_result, aws_analysis, tmp_path / "aws_report.json"
        )
        azure_report = await reporter.generate_json_report(
            azure_result, azure_analysis, tmp_path / "azure_report.json"
        )

        assert aws_report["findings"]["total"] > 0
        assert azure_report["findings"]["total"] > 0

    async def test_aws_plus_gcp_multi_provider(self, tmp_path):
        """Test scanning AWS + GCP providers concurrently."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )
        mock_gcp = _mock_connector(
            GCPConnector, _gcp_accounts(), _gcp_permissions(), _gcp_policies()
        )

        def _pick_connector(provider, _config):
            if provider == "aws":
                return mock_aws
            if provider == "gcp":
                return mock_gcp
            raise ValueError(f"Unknown provider: {provider}")

        with patch.object(Scanner, "_create_connector", side_effect=_pick_connector):
            scanner = Scanner()
            results = await scanner.scan_multiple(["aws", "gcp"])

        assert "aws" in results
        assert "gcp" in results
        assert results["aws"].status == "completed"
        assert results["gcp"].status == "completed"

    async def test_findings_have_correct_structure(self):
        """Verify every finding produced by the pipeline has required fields."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )

        with patch.object(Scanner, "_create_connector", return_value=mock_aws):
            scanner = Scanner()
            scan_result = await scanner.scan("aws")

        analyzer = Analyzer()
        analysis = await analyzer.analyze(scan_result)

        for finding in analysis.findings:
            assert finding.id, "finding must have an id"
            assert finding.severity is not None
            assert finding.category is not None
            assert finding.title
            assert finding.description
            assert finding.remediation
            assert finding.account_id

    async def test_report_contains_all_sections(self, tmp_path):
        """Verify JSON report contains every expected top-level section."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )

        with patch.object(Scanner, "_create_connector", return_value=mock_aws):
            scanner = Scanner()
            scan_result = await scanner.scan("aws")

        analyzer = Analyzer()
        analysis = await analyzer.analyze(scan_result)

        reporter = Reporter()
        report = await reporter.generate_json_report(scan_result, analysis)

        required_keys = {"report_metadata", "scan", "analysis", "findings", "accounts", "recommendations"}
        assert required_keys.issubset(report.keys())

        # Scan section
        assert report["scan"]["provider"] == "aws"
        assert report["scan"]["status"] == "completed"

        # Findings section
        assert "by_severity" in report["findings"]
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in report["findings"]["by_severity"]

        # Accounts list
        assert len(report["accounts"]) == 3

    async def test_summary_report_text(self):
        """Verify text summary report is generated correctly."""
        mock_aws = _mock_connector(
            AWSConnector, _aws_accounts(), _aws_permissions(), _aws_policies()
        )

        with patch.object(Scanner, "_create_connector", return_value=mock_aws):
            scanner = Scanner()
            scan_result = await scanner.scan("aws")

        analyzer = Analyzer()
        analysis = await analyzer.analyze(scan_result)

        reporter = Reporter()
        text = await reporter.generate_summary_report(scan_result, analysis)

        assert "AccessAudit Security Report" in text
        assert "AWS" in text
        assert scan_result.scan_id in text
