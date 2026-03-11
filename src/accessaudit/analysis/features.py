"""ML feature extraction for IAM anomaly detection."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from accessaudit.models import Account, Permission, PermissionScope


class FeatureExtractor:
    """Extracts numerical feature vectors from IAM accounts and permissions.

    Feature vector per account:
    - Permission count per known service (one feature per service seen across all accounts)
    - Scope distribution (count per PermissionScope: READ, WRITE, ADMIN, CUSTOM)
    - Total permission count
    - Number of groups
    - MFA enabled (0/1)
    - Has admin role (0/1)
    - Account age in days
    - Number of unique source policies
    """

    def extract(
        self,
        accounts: list[Account],
        permissions: dict[str, list[Permission]],
    ) -> tuple[list[list[float]], list[str]]:
        """Extract feature vectors from accounts and their permissions.

        Args:
            accounts: List of Account objects.
            permissions: Mapping of account_id -> list of Permission objects.

        Returns:
            Tuple of (feature_vectors, account_ids) where each feature vector
            is a list of floats and account_ids preserves ordering.
        """
        # Collect all service types across all accounts for consistent feature ordering
        all_services: set[str] = set()
        for perms in permissions.values():
            for perm in perms:
                all_services.add(perm.resource_type)

        service_list = sorted(all_services)

        feature_vectors: list[list[float]] = []
        account_ids: list[str] = []

        for account in accounts:
            acct_perms = permissions.get(account.id, [])
            vector = self._build_vector(account, acct_perms, service_list)
            feature_vectors.append(vector)
            account_ids.append(account.id)

        return feature_vectors, account_ids

    def group_by_peers(self, accounts: list[Account]) -> dict[str, list[Account]]:
        """Group accounts by shared group membership.

        Each group name maps to the list of accounts that belong to it.

        Args:
            accounts: List of Account objects.

        Returns:
            Dict mapping group_name -> list of accounts in that group.
        """
        peer_groups: dict[str, list[Account]] = {}
        for account in accounts:
            for group in account.groups:
                peer_groups.setdefault(group, []).append(account)
        return peer_groups

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_vector(
        self,
        account: Account,
        perms: list[Permission],
        service_list: list[str],
    ) -> list[float]:
        """Build a single feature vector for one account.

        Args:
            account: The account to featurise.
            perms: Permissions for this account.
            service_list: Ordered list of service names (shared across all accounts).

        Returns:
            Feature vector as a list of floats.
        """
        # Permission count per service
        service_counts = Counter(p.resource_type for p in perms)
        service_features = [float(service_counts.get(svc, 0)) for svc in service_list]

        # Scope distribution
        scope_counts = Counter(p.scope for p in perms)
        scope_features = [
            float(scope_counts.get(PermissionScope.READ, 0)),
            float(scope_counts.get(PermissionScope.WRITE, 0)),
            float(scope_counts.get(PermissionScope.ADMIN, 0)),
            float(scope_counts.get(PermissionScope.CUSTOM, 0)),
        ]

        # Scalar features
        total_perms = float(len(perms))
        num_groups = float(len(account.groups))
        mfa = 1.0 if account.mfa_enabled else 0.0
        admin = 1.0 if account.has_admin_role else 0.0

        # Account age in days
        if account.created_at:
            now = datetime.now(timezone.utc)
            created = account.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            account_age = float((now - created).days)
        else:
            account_age = 0.0

        # Unique source policies
        unique_policies = float(len({p.source_policy for p in perms}))

        vector = (
            service_features
            + scope_features
            + [total_perms, num_groups, mfa, admin, account_age, unique_policies]
        )
        return vector
