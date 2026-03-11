"""Dormant account detection module."""

import hashlib
from typing import Any

from accessaudit.models import Account, Finding, FindingCategory, FindingSeverity


class DormantAccountAnalyzer:
    """Detects dormant/inactive accounts."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize dormant account analyzer.

        Args:
            config: Configuration dictionary (thresholds, etc.)
        """
        self.config = config or {}
        self.dormant_threshold_days = self.config.get("dormant_threshold_days", 90)

    async def analyze(self, accounts: list[Account]) -> list[Finding]:
        """Analyze accounts for dormancy.

        Args:
            accounts: List of accounts to analyze

        Returns:
            List of Finding objects
        """
        findings = []

        for account in accounts:
            if account.is_dormant(self.dormant_threshold_days):
                finding = await self._create_dormant_finding(account)
                findings.append(finding)

        return findings

    async def _create_dormant_finding(self, account: Account) -> Finding:
        """Create a finding for a dormant account.

        Args:
            account: Dormant account

        Returns:
            Finding object
        """
        days_inactive = account.days_since_activity() or 0
        finding_id = hashlib.md5(f"dormant:{account.id}".encode()).hexdigest()[:16]

        # Severity based on inactivity duration
        if days_inactive > 365:
            severity = FindingSeverity.HIGH
        elif days_inactive > 180:
            severity = FindingSeverity.MEDIUM
        else:
            severity = FindingSeverity.LOW

        return Finding(
            id=f"finding-{finding_id}",
            severity=severity,
            category=FindingCategory.DORMANT_ACCOUNT,
            account_id=account.id,
            title=f"Dormant account - inactive for {days_inactive} days",
            description=f"Account {account.username} has been inactive for {days_inactive} days, exceeding the threshold of {self.dormant_threshold_days} days. Dormant accounts pose security risks as they may have outdated permissions and could be compromised.",
            remediation=f"Review account usage and consider: (1) Disabling the account if no longer needed, (2) Removing or reducing permissions, (3) Contacting the account owner to verify continued need.",
            metadata={
                "days_inactive": days_inactive,
                "threshold": self.dormant_threshold_days,
                "last_activity": account.last_activity.isoformat() if account.last_activity else None,
                "last_login": account.last_login.isoformat() if account.last_login else None,
            },
        )
