"""Unit tests for ML anomaly detection."""

from datetime import UTC, datetime, timedelta

from accessaudit.analysis.anomaly import AnomalyDetector
from accessaudit.models import Account, AccountStatus, Permission, PermissionScope
from accessaudit.models.finding import FindingCategory


def _make_account(
    account_id: str,
    groups: list[str] | None = None,
    mfa_enabled: bool = False,
    has_admin_role: bool = False,
) -> Account:
    """Helper to create Account fixtures."""
    return Account(
        id=account_id,
        provider="aws",
        username=account_id,
        email=f"{account_id}@example.com",
        created_at=datetime(2024, 1, 1, tzinfo=UTC),
        last_login=datetime.now(UTC) - timedelta(days=5),
        last_activity=datetime.now(UTC) - timedelta(days=1),
        status=AccountStatus.ACTIVE,
        mfa_enabled=mfa_enabled,
        has_admin_role=has_admin_role,
        groups=groups or [],
    )


def _make_permission(
    account_id: str,
    resource_type: str = "s3",
    scope: PermissionScope = PermissionScope.READ,
    source_policy: str = "policy-1",
    actions: list[str] | None = None,
    perm_suffix: str = "",
) -> Permission:
    """Helper to create Permission fixtures."""
    return Permission(
        id=f"perm-{account_id}-{resource_type}-{scope.value}{perm_suffix}",
        account_id=account_id,
        resource_type=resource_type,
        resource_arn=f"arn:aws:{resource_type}:::*",
        actions=actions or [f"{resource_type}:GetObject"],
        effect="Allow",
        scope=scope,
        source_policy=source_policy,
    )


class TestAnomalyDetector:
    """Tests for AnomalyDetector."""

    def test_init_default_config(self):
        """AnomalyDetector uses default config: min_group_size=10, contamination=0.1."""
        detector = AnomalyDetector()
        assert detector.min_group_size == 10
        assert detector.contamination == 0.1

    def test_init_custom_config(self):
        """AnomalyDetector accepts custom configuration."""
        detector = AnomalyDetector(min_group_size=5, contamination=0.2)
        assert detector.min_group_size == 5
        assert detector.contamination == 0.2

    def test_skips_small_groups(self):
        """Groups smaller than min_group_size should produce no findings."""
        detector = AnomalyDetector(min_group_size=10)
        # Create 5 accounts in a group (below threshold of 10)
        accounts = [_make_account(f"user-{i}", groups=["small-team"]) for i in range(5)]
        permissions = {a.id: [_make_permission(a.id, "s3", PermissionScope.READ)] for a in accounts}

        findings = detector.detect(accounts, permissions)
        assert findings == []

    def test_detects_outlier_in_large_group(self):
        """Outlier with wildcard perms detected among normal accounts."""
        detector = AnomalyDetector(min_group_size=5, contamination=0.15)

        # 14 normal accounts with 3 s3:GetObject permissions each
        normal_accounts = []
        permissions: dict[str, list[Permission]] = {}
        for i in range(14):
            acct = _make_account(f"dev-{i}", groups=["developers"])
            normal_accounts.append(acct)
            permissions[acct.id] = [
                _make_permission(acct.id, "s3", PermissionScope.READ, perm_suffix=f"-{j}")
                for j in range(3)
            ]

        # 1 outlier with 50 iam:* wildcard permissions
        outlier = _make_account("dev-outlier", groups=["developers"], has_admin_role=True)
        normal_accounts.append(outlier)
        permissions[outlier.id] = [
            _make_permission(
                outlier.id,
                "iam",
                PermissionScope.ADMIN,
                actions=["iam:*"],
                perm_suffix=f"-{j}",
            )
            for j in range(50)
        ]

        findings = detector.detect(normal_accounts, permissions)

        # Should detect at least one anomaly
        assert len(findings) >= 1

        # The outlier account should be flagged
        flagged_ids = [f.account_id for f in findings]
        assert "dev-outlier" in flagged_ids

    def test_findings_have_anomaly_category(self):
        """All findings from anomaly detector have ANOMALY category."""
        detector = AnomalyDetector(min_group_size=5, contamination=0.15)

        # Same setup: 14 normal + 1 outlier
        accounts = []
        permissions: dict[str, list[Permission]] = {}
        for i in range(14):
            acct = _make_account(f"dev-{i}", groups=["developers"])
            accounts.append(acct)
            permissions[acct.id] = [
                _make_permission(acct.id, "s3", PermissionScope.READ, perm_suffix=f"-{j}")
                for j in range(3)
            ]

        outlier = _make_account("dev-outlier", groups=["developers"], has_admin_role=True)
        accounts.append(outlier)
        permissions[outlier.id] = [
            _make_permission(
                outlier.id,
                "iam",
                PermissionScope.ADMIN,
                actions=["iam:*"],
                perm_suffix=f"-{j}",
            )
            for j in range(50)
        ]

        findings = detector.detect(accounts, permissions)

        assert len(findings) >= 1
        for finding in findings:
            assert finding.category == FindingCategory.ANOMALY
