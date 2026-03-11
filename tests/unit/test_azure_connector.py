"""Tests for Azure AD connector."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from accessaudit.connectors.azure import AzureConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy
from tests.fixtures.azure_fixtures import (
    make_azure_user,
    make_azure_directory_role,
    make_azure_rbac_assignment,
)


@pytest.fixture
def azure_config():
    return {
        "tenant_id": "test-tenant-id",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "subscription_id": "test-sub-id",
    }


@pytest.fixture
def connector(azure_config):
    c = AzureConnector(azure_config)
    # Set _credential to a truthy sentinel so methods skip connect()
    c._credential = MagicMock()
    return c


class TestAzureConnectorInit:
    def test_provider_name(self, connector):
        assert connector.provider_name == "azure"

    def test_config_stored(self, connector, azure_config):
        assert connector.config == azure_config


class TestAzureListAccounts:
    @pytest.mark.asyncio
    async def test_list_accounts_returns_accounts(self, connector):
        """Should convert Azure AD users to Account models."""
        mock_users = [
            make_azure_user(user_id="u1", display_name="Alice", upn="alice@contoso.com"),
            make_azure_user(
                user_id="u2", display_name="Bob", upn="bob@contoso.com", account_enabled=False
            ),
        ]

        with patch.object(connector, "_fetch_users", return_value=mock_users):
            with patch.object(connector, "_fetch_user_mfa_status", return_value={}):
                with patch.object(connector, "_fetch_directory_role_members", return_value={}):
                    accounts = await connector.list_accounts()

        assert len(accounts) == 2
        assert accounts[0].provider == "azure"
        assert accounts[0].username == "alice@contoso.com"
        assert accounts[1].status == AccountStatus.DISABLED


class TestAzureListPolicies:
    @pytest.mark.asyncio
    async def test_list_policies_returns_rbac_roles(self, connector):
        """Should return RBAC role definitions as Policy models."""
        mock_roles = [
            {
                "id": "/role-def/owner",
                "properties": {
                    "roleName": "Owner",
                    "permissions": [{"actions": ["*"]}],
                    "type": "BuiltInRole",
                },
            },
        ]

        with patch.object(connector, "_fetch_rbac_role_definitions", return_value=mock_roles):
            policies = await connector.list_policies()

        assert len(policies) == 1
        assert policies[0].provider == "azure"
        assert policies[0].name == "Owner"


class TestAzureGetAccountPermissions:
    @pytest.mark.asyncio
    async def test_get_permissions_includes_rbac(self, connector):
        """Should include RBAC role assignments as permissions."""
        mock_assignments = [
            make_azure_rbac_assignment(principal_id="u1", role_definition_name="Contributor"),
        ]

        with patch.object(
            connector, "_fetch_rbac_assignments_for_principal", return_value=mock_assignments
        ):
            with patch.object(connector, "_fetch_directory_roles_for_user", return_value=[]):
                permissions = await connector.get_account_permissions("u1")

        assert len(permissions) >= 1
        assert permissions[0].account_id == "u1"
        assert "Contributor" in permissions[0].source_policy


class TestAzureTestConnection:
    @pytest.mark.asyncio
    async def test_connection_success(self, connector):
        with patch.object(connector, "connect", new_callable=AsyncMock):
            result = await connector.test_connection()
        assert result is True

    @pytest.mark.asyncio
    async def test_connection_failure(self, connector):
        with patch.object(connector, "connect", side_effect=ConnectionError("fail")):
            result = await connector.test_connection()
        assert result is False
