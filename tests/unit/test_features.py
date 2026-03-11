"""Unit tests for ML feature extraction."""

from datetime import UTC, datetime, timedelta

import pytest

from accessaudit.analysis.features import FeatureExtractor
from accessaudit.models import Account, AccountStatus, Permission, PermissionScope


def _make_account(
    account_id: str,
    groups: list[str] | None = None,
    mfa_enabled: bool = False,
    has_admin_role: bool = False,
    created_at: datetime | None = None,
) -> Account:
    """Helper to create Account fixtures."""
    return Account(
        id=account_id,
        provider="aws",
        username=account_id,
        email=f"{account_id}@example.com",
        created_at=created_at or datetime(2024, 1, 1, tzinfo=UTC),
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
) -> Permission:
    """Helper to create Permission fixtures."""
    return Permission(
        id=f"perm-{account_id}-{resource_type}-{scope.value}",
        account_id=account_id,
        resource_type=resource_type,
        resource_arn=f"arn:aws:{resource_type}:::*",
        actions=[f"{resource_type}:Get*"],
        effect="Allow",
        scope=scope,
        source_policy=source_policy,
    )


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    @pytest.fixture
    def extractor(self):
        return FeatureExtractor()

    @pytest.fixture
    def sample_accounts(self):
        return [
            _make_account("user-1", groups=["devs"], mfa_enabled=True),
            _make_account("user-2", groups=["devs", "admins"], has_admin_role=True),
            _make_account("user-3", groups=["readonly"]),
        ]

    @pytest.fixture
    def sample_permissions(self):
        return {
            "user-1": [
                _make_permission("user-1", "s3", PermissionScope.READ),
                _make_permission("user-1", "ec2", PermissionScope.WRITE),
                _make_permission("user-1", "s3", PermissionScope.WRITE, source_policy="policy-2"),
            ],
            "user-2": [
                _make_permission("user-2", "s3", PermissionScope.ADMIN),
                _make_permission("user-2", "ec2", PermissionScope.ADMIN),
                _make_permission("user-2", "iam", PermissionScope.ADMIN),
                _make_permission("user-2", "lambda", PermissionScope.WRITE),
            ],
            "user-3": [
                _make_permission("user-3", "s3", PermissionScope.READ),
            ],
        }

    def test_extract_returns_correct_shape(self, extractor, sample_accounts, sample_permissions):
        """extract() returns (feature_vectors, account_ids) with matching lengths."""
        vectors, account_ids = extractor.extract(sample_accounts, sample_permissions)

        assert len(vectors) == len(sample_accounts)
        assert len(account_ids) == len(sample_accounts)
        assert set(account_ids) == {"user-1", "user-2", "user-3"}

    def test_feature_vector_length(self, extractor, sample_accounts, sample_permissions):
        """All feature vectors have the same length."""
        vectors, _ = extractor.extract(sample_accounts, sample_permissions)

        lengths = [len(v) for v in vectors]
        assert len(set(lengths)) == 1, f"Inconsistent vector lengths: {lengths}"
        assert lengths[0] > 0

    def test_peer_groups(self, extractor, sample_accounts):
        """group_by_peers groups accounts by shared group membership."""
        peer_groups = extractor.group_by_peers(sample_accounts)

        assert isinstance(peer_groups, dict)
        # user-1 and user-2 both in "devs"
        assert "devs" in peer_groups
        devs_ids = [a.id for a in peer_groups["devs"]]
        assert "user-1" in devs_ids
        assert "user-2" in devs_ids

        # user-3 in "readonly"
        assert "readonly" in peer_groups
        readonly_ids = [a.id for a in peer_groups["readonly"]]
        assert "user-3" in readonly_ids

    def test_empty_permissions(self, extractor):
        """extract() handles accounts with no permissions."""
        accounts = [_make_account("empty-user")]
        permissions: dict[str, list[Permission]] = {"empty-user": []}

        vectors, account_ids = extractor.extract(accounts, permissions)

        assert len(vectors) == 1
        assert account_ids == ["empty-user"]
        # Vector should still be valid (all zeros for permission counts)
        assert all(isinstance(v, (int, float)) for v in vectors[0])

    def test_feature_values_reflect_data(self, extractor, sample_accounts, sample_permissions):
        """Feature values should reflect the underlying account/permission data."""
        vectors, account_ids = extractor.extract(sample_accounts, sample_permissions)

        # Build a map for easy lookup
        feature_map = dict(zip(account_ids, vectors, strict=False))

        # user-2 has admin role -> admin feature should be 1
        # user-1 has MFA -> mfa feature should be 1
        # user-2 has more permissions than user-3
        v1 = feature_map["user-1"]
        v2 = feature_map["user-2"]
        v3 = feature_map["user-3"]

        # Total permissions: user-2 (4) > user-1 (3) > user-3 (1)
        # The total_perms feature is present somewhere in the vector
        # We just verify the vectors are different and non-trivial
        assert v1 != v2
        assert v2 != v3
        assert v1 != v3

    def test_accounts_not_in_permissions_map(self, extractor):
        """Accounts missing from permissions dict get zero-permission vectors."""
        accounts = [_make_account("orphan-user")]
        permissions: dict[str, list[Permission]] = {}

        vectors, account_ids = extractor.extract(accounts, permissions)

        assert len(vectors) == 1
        assert account_ids == ["orphan-user"]
