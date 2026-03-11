"""Tests for GCP IAM connector."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from accessaudit.connectors.gcp import GCPConnector
from accessaudit.models import AccountStatus
from tests.fixtures.gcp_fixtures import (
    make_gcp_iam_binding,
    make_gcp_role,
    make_gcp_service_account,
)


@pytest.fixture
def gcp_config():
    return {
        "project_id": "my-project",
        "credentials_file": "/path/to/creds.json",
    }


@pytest.fixture
def connector(gcp_config):
    c = GCPConnector(gcp_config)
    # Set _credentials to a truthy sentinel so methods skip connect()
    c._credentials = MagicMock()
    return c


class TestGCPConnectorInit:
    def test_provider_name(self, connector):
        assert connector.provider_name == "gcp"

    def test_project_id_stored(self, connector):
        assert connector.project_id == "my-project"


class TestGCPListAccounts:
    @pytest.mark.asyncio
    async def test_list_accounts_returns_service_accounts(self, connector):
        mock_sas = [
            make_gcp_service_account(email="sa1@proj.iam.gserviceaccount.com", unique_id="sa-1"),
            make_gcp_service_account(
                email="sa2@proj.iam.gserviceaccount.com", unique_id="sa-2", disabled=True
            ),
        ]

        with patch.object(connector, "_fetch_service_accounts", return_value=mock_sas):
            with patch.object(connector, "_fetch_iam_bindings", return_value=[]):
                accounts = await connector.list_accounts()

        assert len(accounts) == 2
        assert accounts[0].provider == "gcp"
        assert accounts[0].username == "sa1@proj.iam.gserviceaccount.com"
        assert accounts[1].status == AccountStatus.DISABLED


class TestGCPListPolicies:
    @pytest.mark.asyncio
    async def test_list_policies_returns_roles(self, connector):
        mock_roles = [
            make_gcp_role(name="roles/owner", title="Owner", permissions=["*"]),
        ]

        with patch.object(connector, "_fetch_roles", return_value=mock_roles):
            policies = await connector.list_policies()

        assert len(policies) == 1
        assert policies[0].provider == "gcp"
        assert policies[0].name == "Owner"


class TestGCPGetAccountPermissions:
    @pytest.mark.asyncio
    async def test_get_permissions_from_bindings(self, connector):
        mock_bindings = [
            make_gcp_iam_binding(
                role="roles/editor", members=["serviceAccount:sa1@proj.iam.gserviceaccount.com"]
            ),
        ]

        with patch.object(connector, "_fetch_iam_bindings", return_value=mock_bindings):
            permissions = await connector.get_account_permissions(
                "sa1@proj.iam.gserviceaccount.com"
            )

        assert len(permissions) == 1
        assert permissions[0].account_id == "sa1@proj.iam.gserviceaccount.com"


class TestGCPTestConnection:
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
