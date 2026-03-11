"""Base connector interface for IAM providers."""

from abc import ABC, abstractmethod
from typing import Any

from accessaudit.models import Account, Permission, Policy


class BaseConnector(ABC):
    """Abstract base class for IAM provider connectors."""

    def __init__(self, config: dict[str, Any]):
        """Initialize connector with configuration.

        Args:
            config: Provider-specific configuration dictionary
        """
        self.config = config
        self.provider_name = self.__class__.__name__.replace("Connector", "").lower()

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to IAM provider.

        Raises:
            ConnectionError: If connection fails
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to IAM provider."""
        pass

    @abstractmethod
    async def list_accounts(self) -> list[Account]:
        """List all user accounts from provider.

        Returns:
            List of Account objects

        Raises:
            RuntimeError: If fetching accounts fails
        """
        pass

    @abstractmethod
    async def get_account(self, account_id: str) -> Account | None:
        """Get specific account details.

        Args:
            account_id: Account identifier

        Returns:
            Account object or None if not found
        """
        pass

    @abstractmethod
    async def list_policies(self) -> list[Policy]:
        """List all policies from provider.

        Returns:
            List of Policy objects

        Raises:
            RuntimeError: If fetching policies fails
        """
        pass

    @abstractmethod
    async def get_account_permissions(self, account_id: str) -> list[Permission]:
        """Get all permissions for a specific account.

        Args:
            account_id: Account identifier

        Returns:
            List of Permission objects

        Raises:
            RuntimeError: If fetching permissions fails
        """
        pass

    async def list_roles(self) -> list[Policy]:
        """List all roles from provider.

        Returns an empty list by default. Subclasses may override to
        return provider-specific role information.

        Returns:
            List of Policy objects representing roles
        """
        return []

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connection to provider.

        Returns:
            True if connection successful, False otherwise
        """
        pass

    def __repr__(self) -> str:
        """String representation of connector."""
        return f"<{self.__class__.__name__} provider={self.provider_name}>"
