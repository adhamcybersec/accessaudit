"""Scan orchestrator for IAM auditing."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from accessaudit.connectors.aws import AWSConnector
from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, Permission, Policy

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None

try:
    from accessaudit.connectors.gcp import GCPConnector
except ImportError:
    GCPConnector = None


@dataclass
class ScanResult:
    """Result of an IAM scan operation."""

    scan_id: str
    provider: str
    started_at: datetime
    completed_at: datetime | None = None
    accounts: list[Account] = field(default_factory=list)
    permissions: dict[str, list[Permission]] = field(default_factory=dict)
    policies: list[Policy] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "provider": self.provider,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "account_count": len(self.accounts),
            "policy_count": len(self.policies),
            "permission_count": sum(len(p) for p in self.permissions.values()),
            "error_count": len(self.errors),
            "status": self.status,
        }


class Scanner:
    """Orchestrates IAM scanning across providers."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize scanner.

        Args:
            config: Scanner configuration (providers, regions, etc.)
        """
        self.config = config or {}
        self.connectors: dict[str, BaseConnector] = {}

    def _create_connector(self, provider: str, provider_config: dict[str, Any]) -> BaseConnector:
        """Create connector for a provider.

        Args:
            provider: Provider name (aws, azure, gcp)
            provider_config: Provider-specific configuration

        Returns:
            Connector instance

        Raises:
            ValueError: If provider is not supported
        """
        connectors: dict[str, type[BaseConnector]] = {
            "aws": AWSConnector,
        }

        if AzureConnector is not None:
            connectors["azure"] = AzureConnector
        if GCPConnector is not None:
            connectors["gcp"] = GCPConnector

        if provider not in connectors:
            raise ValueError(f"Unsupported provider: {provider}")

        return connectors[provider](provider_config)

    async def scan(
        self, provider: str, provider_config: dict[str, Any] | None = None
    ) -> ScanResult:
        """Run a scan against a provider.

        Args:
            provider: Provider to scan (aws, azure, gcp)
            provider_config: Provider-specific configuration

        Returns:
            ScanResult with accounts, permissions, and policies
        """
        import uuid

        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(
            scan_id=scan_id,
            provider=provider,
            started_at=datetime.now(),
            status="running",
        )

        try:
            # Create and connect to provider
            config = provider_config or self.config.get("providers", {}).get(provider, {})
            connector = self._create_connector(provider, config)
            self.connectors[provider] = connector

            await connector.connect()

            # Fetch accounts
            print(f"[{scan_id}] Fetching accounts...")
            result.accounts = await connector.list_accounts()
            print(f"[{scan_id}] Found {len(result.accounts)} accounts")

            # Fetch permissions for each account
            print(f"[{scan_id}] Fetching permissions...")
            for account in result.accounts:
                try:
                    permissions = await connector.get_account_permissions(account.id)
                    result.permissions[account.id] = permissions
                except Exception as e:
                    result.errors.append(f"Failed to get permissions for {account.username}: {e}")

            total_perms = sum(len(p) for p in result.permissions.values())
            print(f"[{scan_id}] Found {total_perms} permissions")

            # Fetch policies
            print(f"[{scan_id}] Fetching policies...")
            result.policies = await connector.list_policies()
            print(f"[{scan_id}] Found {len(result.policies)} policies")

            # Disconnect
            await connector.disconnect()

            result.status = "completed"
            result.completed_at = datetime.now()

        except Exception as e:
            result.errors.append(f"Scan failed: {e}")
            result.status = "failed"
            result.completed_at = datetime.now()
            raise RuntimeError(f"Scan failed: {e}") from e

        return result

    async def scan_multiple(
        self, providers: list[str], provider_configs: dict[str, dict[str, Any]] | None = None
    ) -> dict[str, ScanResult]:
        """Scan multiple providers concurrently.

        Args:
            providers: List of providers to scan
            provider_configs: Provider-specific configurations

        Returns:
            Dict mapping provider -> ScanResult
        """
        configs = provider_configs or {}

        async def scan_provider(provider: str) -> tuple[str, ScanResult]:
            result = await self.scan(provider, configs.get(provider))
            return provider, result

        tasks = [scan_provider(provider) for provider in providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scan_results = {}
        for item in results:
            if isinstance(item, Exception):
                print(f"Scan error: {item}")
            else:
                provider, result = item
                scan_results[provider] = result

        return scan_results
