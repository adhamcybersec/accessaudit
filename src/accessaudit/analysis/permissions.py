"""Permission analysis module."""

import hashlib
from typing import Any

from accessaudit.models import Account, Finding, FindingCategory, FindingSeverity, Permission


class PermissionAnalyzer:
    """Analyzes IAM permissions for security issues."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize permission analyzer.

        Args:
            config: Configuration dictionary (thresholds, rules, etc.)
        """
        self.config = config or {}
        self.max_permissions_threshold = self.config.get("max_permissions_threshold", 50)

    async def analyze(
        self, accounts: list[Account], all_permissions: dict[str, list[Permission]]
    ) -> list[Finding]:
        """Analyze permissions for security issues.

        Args:
            accounts: List of accounts to analyze
            all_permissions: Dict mapping account_id -> list of permissions

        Returns:
            List of Finding objects
        """
        findings = []

        for account in accounts:
            account_permissions = all_permissions.get(account.id, [])

            # Check for wildcard permissions
            wildcard_findings = await self._check_wildcard_permissions(account, account_permissions)
            findings.extend(wildcard_findings)

            # Check for excessive permissions
            excessive_findings = await self._check_excessive_permissions(
                account, account_permissions
            )
            findings.extend(excessive_findings)

            # Check for admin without MFA
            mfa_findings = await self._check_admin_without_mfa(account, account_permissions)
            findings.extend(mfa_findings)

        return findings

    async def _check_wildcard_permissions(
        self, account: Account, permissions: list[Permission]
    ) -> list[Finding]:
        """Check for wildcard (*) permissions.

        Args:
            account: Account to check
            permissions: Account permissions

        Returns:
            List of findings
        """
        findings = []

        for permission in permissions:
            if permission.is_full_wildcard():
                finding_id = hashlib.md5(
                    f"wildcard:{account.id}:{permission.source_policy}".encode()
                ).hexdigest()[:16]

                finding = Finding(
                    id=f"finding-{finding_id}",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.EXCESSIVE_PERMISSIONS,
                    account_id=account.id,
                    title="User has full wildcard permissions",
                    description=(
                        f"Account {account.username} has unrestricted"
                        f" wildcard permissions (*:*) from policy"
                        f" {permission.source_policy}. This grants full"
                        " administrative access to all AWS services"
                        " and resources."
                    ),
                    remediation=(
                        "Replace wildcard policy with least-privilege"
                        " policies granting only required permissions"
                        " for the user's role."
                    ),
                    resource_arn=permission.resource_arn,
                    policy_arn=permission.source_policy,
                    metadata={
                        "actions": permission.actions,
                        "resource": permission.resource_arn,
                        "source_policy": permission.source_policy,
                    },
                )
                findings.append(finding)

            elif permission.is_wildcard():
                # Service-level wildcards (e.g., s3:*)
                finding_id = hashlib.md5(
                    f"service-wildcard:{account.id}:{permission.source_policy}".encode()
                ).hexdigest()[:16]

                finding = Finding(
                    id=f"finding-{finding_id}",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.EXCESSIVE_PERMISSIONS,
                    account_id=account.id,
                    title="User has service-level wildcard permissions",
                    description=(
                        f"Account {account.username} has wildcard"
                        f" permissions for {permission.resource_type}"
                        f" from policy {permission.source_policy}."
                    ),
                    remediation=(
                        "Restrict permissions to only the specific"
                        " actions required for this user's role."
                    ),
                    resource_arn=permission.resource_arn,
                    policy_arn=permission.source_policy,
                    metadata={
                        "actions": permission.actions,
                        "resource_type": permission.resource_type,
                        "source_policy": permission.source_policy,
                    },
                )
                findings.append(finding)

        return findings

    async def _check_excessive_permissions(
        self, account: Account, permissions: list[Permission]
    ) -> list[Finding]:
        """Check if account has excessive number of permissions.

        Args:
            account: Account to check
            permissions: Account permissions

        Returns:
            List of findings
        """
        findings = []

        if len(permissions) > self.max_permissions_threshold:
            finding_id = hashlib.md5(f"excessive:{account.id}".encode()).hexdigest()[:16]

            finding = Finding(
                id=f"finding-{finding_id}",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.EXCESSIVE_PERMISSIONS,
                account_id=account.id,
                title=f"Account has excessive permissions ({len(permissions)})",
                description=(
                    f"Account {account.username} has"
                    f" {len(permissions)} permissions, exceeding the"
                    f" threshold of {self.max_permissions_threshold}."
                    " This may indicate over-provisioning."
                ),
                remediation=(
                    "Review account's actual usage and remove unused"
                    " permissions. Consider consolidating overlapping"
                    " permissions."
                ),
                metadata={
                    "permission_count": len(permissions),
                    "threshold": self.max_permissions_threshold,
                },
            )
            findings.append(finding)

        return findings

    async def _check_admin_without_mfa(
        self, account: Account, permissions: list[Permission]
    ) -> list[Finding]:
        """Check if admin account lacks MFA.

        Args:
            account: Account to check
            permissions: Account permissions

        Returns:
            List of findings
        """
        findings = []

        # Check if account has admin permissions but no MFA
        if account.has_admin_role and not account.mfa_enabled:
            finding_id = hashlib.md5(f"admin-no-mfa:{account.id}".encode()).hexdigest()[:16]

            finding = Finding(
                id=f"finding-{finding_id}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.MISSING_MFA,
                account_id=account.id,
                title="Admin account without MFA",
                description=(
                    f"Account {account.username} has administrative"
                    " privileges but does not have MFA enabled."
                    " This creates a significant security risk."
                ),
                remediation=(
                    "Enable MFA (Multi-Factor Authentication)"
                    " for this privileged account immediately."
                ),
                metadata={"has_admin_role": True, "mfa_enabled": False},
            )
            findings.append(finding)

        return findings
