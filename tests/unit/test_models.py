"""Unit tests for data models."""

from datetime import datetime, timezone, timedelta

import pytest

from accessaudit.models import (
    Account,
    AccountStatus,
    Finding,
    FindingCategory,
    FindingSeverity,
    Permission,
    PermissionScope,
    Policy,
)


class TestAccount:
    """Tests for Account model."""

    def test_account_creation(self):
        """Test basic account creation."""
        account = Account(
            id="arn:aws:iam::123456789012:user/test-user",
            provider="aws",
            username="test-user",
        )
        assert account.id == "arn:aws:iam::123456789012:user/test-user"
        assert account.provider == "aws"
        assert account.username == "test-user"
        assert account.status == AccountStatus.ACTIVE
        assert account.mfa_enabled is False
        assert account.has_admin_role is False

    def test_account_with_all_fields(self):
        """Test account with all fields populated."""
        now = datetime.now(timezone.utc)
        account = Account(
            id="arn:aws:iam::123456789012:user/admin",
            provider="aws",
            username="admin",
            email="admin@example.com",
            created_at=now - timedelta(days=365),
            last_login=now - timedelta(days=1),
            last_activity=now - timedelta(hours=2),
            status=AccountStatus.ACTIVE,
            mfa_enabled=True,
            has_admin_role=True,
            groups=["Administrators", "Developers"],
            tags={"Department": "IT"},
            metadata={"user_id": "AIDA123456"},
        )
        assert account.email == "admin@example.com"
        assert account.mfa_enabled is True
        assert account.has_admin_role is True
        assert len(account.groups) == 2

    def test_is_dormant_true(self):
        """Test dormant account detection."""
        account = Account(
            id="user-1",
            provider="aws",
            username="dormant-user",
            last_activity=datetime.now(timezone.utc) - timedelta(days=100),
        )
        assert account.is_dormant(threshold_days=90) is True

    def test_is_dormant_false(self):
        """Test active account is not dormant."""
        account = Account(
            id="user-1",
            provider="aws",
            username="active-user",
            last_activity=datetime.now(timezone.utc) - timedelta(days=30),
        )
        assert account.is_dormant(threshold_days=90) is False

    def test_is_dormant_no_activity(self):
        """Test account with no activity data."""
        account = Account(
            id="user-1",
            provider="aws",
            username="new-user",
        )
        assert account.is_dormant() is False

    def test_days_since_activity(self):
        """Test days since activity calculation."""
        account = Account(
            id="user-1",
            provider="aws",
            username="test",
            last_activity=datetime.now(timezone.utc) - timedelta(days=45),
        )
        days = account.days_since_activity()
        assert days is not None
        assert 44 <= days <= 46  # Allow for test execution time


class TestPermission:
    """Tests for Permission model."""

    def test_permission_creation(self):
        """Test basic permission creation."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="s3",
            resource_arn="arn:aws:s3:::my-bucket/*",
            actions=["s3:GetObject", "s3:ListBucket"],
            source_policy="policy-1",
        )
        assert permission.id == "perm-1"
        assert permission.resource_type == "s3"
        assert len(permission.actions) == 2

    def test_is_wildcard(self):
        """Test wildcard detection."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="s3",
            resource_arn="*",
            actions=["s3:*"],
            source_policy="policy-1",
        )
        assert permission.is_wildcard() is True

    def test_is_full_wildcard(self):
        """Test full wildcard detection."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="all",
            resource_arn="*",
            actions=["*"],
            source_policy="policy-1",
        )
        assert permission.is_full_wildcard() is True

    def test_is_not_wildcard(self):
        """Test non-wildcard permission."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="s3",
            resource_arn="arn:aws:s3:::my-bucket/*",
            actions=["s3:GetObject"],
            source_policy="policy-1",
        )
        assert permission.is_full_wildcard() is False

    def test_calculate_scope_admin(self):
        """Test admin scope calculation."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="all",
            resource_arn="*",
            actions=["*"],
            source_policy="policy-1",
        )
        assert permission.calculate_scope() == PermissionScope.ADMIN

    def test_calculate_scope_read(self):
        """Test read scope calculation."""
        permission = Permission(
            id="perm-1",
            account_id="user-1",
            resource_type="s3",
            resource_arn="arn:aws:s3:::my-bucket/*",
            actions=["s3:GetObject", "s3:ListBucket"],
            source_policy="policy-1",
        )
        assert permission.calculate_scope() == PermissionScope.READ


class TestPolicy:
    """Tests for Policy model."""

    def test_policy_creation(self):
        """Test basic policy creation."""
        policy = Policy(
            id="policy-1",
            name="TestPolicy",
            arn="arn:aws:iam::123456789012:policy/TestPolicy",
            provider="aws",
            policy_type="customer-managed",
            document={
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ],
            },
        )
        assert policy.name == "TestPolicy"
        assert policy.policy_type == "customer-managed"

    def test_has_wildcard_actions(self):
        """Test wildcard action detection."""
        policy = Policy(
            id="policy-1",
            name="AdminPolicy",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            provider="aws",
            policy_type="managed",
            document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        )
        assert policy.has_wildcard_actions() is True

    def test_has_wildcard_resources(self):
        """Test wildcard resource detection."""
        policy = Policy(
            id="policy-1",
            name="S3FullAccess",
            arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            provider="aws",
            policy_type="managed",
            document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            },
        )
        assert policy.has_wildcard_resources() is True

    def test_is_overly_permissive(self):
        """Test overly permissive policy detection."""
        policy = Policy(
            id="policy-1",
            name="AdminPolicy",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            provider="aws",
            policy_type="managed",
            document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        )
        assert policy.is_overly_permissive() is True

    def test_not_overly_permissive(self):
        """Test limited policy is not overly permissive."""
        policy = Policy(
            id="policy-1",
            name="LimitedPolicy",
            arn="arn:aws:iam::123456789012:policy/LimitedPolicy",
            provider="aws",
            policy_type="customer-managed",
            document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    }
                ],
            },
        )
        assert policy.is_overly_permissive() is False


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            id="finding-1",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.EXCESSIVE_PERMISSIONS,
            account_id="user-1",
            title="Test Finding",
            description="Test description",
            remediation="Fix it",
        )
        assert finding.id == "finding-1"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.category == FindingCategory.EXCESSIVE_PERMISSIONS

    def test_risk_score_critical(self):
        """Test critical severity risk score."""
        finding = Finding(
            id="finding-1",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.EXCESSIVE_PERMISSIONS,
            account_id="user-1",
            title="Critical Issue",
            description="Description",
            remediation="Fix now",
        )
        assert finding.risk_score() == 100

    def test_risk_score_low(self):
        """Test low severity risk score."""
        finding = Finding(
            id="finding-1",
            severity=FindingSeverity.LOW,
            category=FindingCategory.OTHER,
            account_id="user-1",
            title="Low Issue",
            description="Description",
            remediation="Fix eventually",
        )
        assert finding.risk_score() == 25

    def test_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            id="finding-1",
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.DORMANT_ACCOUNT,
            account_id="user-1",
            title="Test",
            description="Desc",
            remediation="Fix",
        )
        data = finding.to_dict()
        assert data["id"] == "finding-1"
        assert data["severity"] == "medium"
        assert data["category"] == "dormant_account"
        assert data["risk_score"] == 50
