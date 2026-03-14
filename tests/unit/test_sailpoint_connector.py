"""Tests for SailPoint IIQ connector."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from accessaudit.connectors.sailpoint import SailPointConnector
from tests.fixtures.sailpoint_fixtures import (
    SCIM_ENTITLEMENTS_RESPONSE,
    SCIM_ROLES_RESPONSE,
    SCIM_USER_DETAIL,
    SCIM_USERS_RESPONSE,
    SERVICE_PROVIDER_CONFIG,
)


@pytest.fixture
def connector():
    return SailPointConnector(
        {
            "base_url": "https://iiq.example.com/identityiq",
            "username": "spadmin",
            "password": "admin",
        }
    )


def _mock_response(json_data, status_code=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


async def test_connect_success(connector):
    """Test successful connection to SailPoint IIQ."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=_mock_response(SERVICE_PROVIDER_CONFIG))

    with patch("accessaudit.connectors.sailpoint.httpx.AsyncClient", return_value=mock_client):
        await connector.connect()

    assert connector.client is not None


async def test_connect_no_base_url():
    """Test connection fails without base_url."""
    conn = SailPointConnector({"base_url": ""})
    with pytest.raises(ConnectionError, match="base_url is required"):
        await conn.connect()


async def test_list_accounts(connector):
    """Test listing accounts from SCIM Users endpoint."""
    connector.client = AsyncMock(spec=httpx.AsyncClient)
    connector.client.get = AsyncMock(return_value=_mock_response(SCIM_USERS_RESPONSE))

    accounts = await connector.list_accounts()
    assert len(accounts) == 2
    assert accounts[0].username == "john.doe"
    assert accounts[0].email == "john.doe@example.com"
    assert accounts[0].provider == "sailpoint"
    assert accounts[0].has_admin_role is True  # "IT Administrators" group
    assert accounts[1].username == "jane.smith"
    assert accounts[1].has_admin_role is False


async def test_list_policies(connector):
    """Test listing roles as policies."""
    connector.client = AsyncMock(spec=httpx.AsyncClient)
    connector.client.get = AsyncMock(return_value=_mock_response(SCIM_ROLES_RESPONSE))

    policies = await connector.list_policies()
    assert len(policies) == 1
    assert policies[0].name == "IT Administrator"
    assert policies[0].provider == "sailpoint"
    assert "user-001" in policies[0].attached_to


async def test_get_account_permissions(connector):
    """Test fetching permissions for a user."""
    connector.client = AsyncMock(spec=httpx.AsyncClient)

    # First call: entitlements, second call: user detail
    connector.client.get = AsyncMock(
        side_effect=[
            _mock_response(SCIM_ENTITLEMENTS_RESPONSE),
            _mock_response(SCIM_USER_DETAIL),
        ]
    )

    permissions = await connector.get_account_permissions("user-001")
    # 1 entitlement + 1 group membership
    assert len(permissions) == 2
    assert any(p.resource_type == "entitlement" for p in permissions)
    assert any(p.resource_type == "role" for p in permissions)


async def test_get_account_found(connector):
    """Test getting a specific account."""
    connector.client = AsyncMock(spec=httpx.AsyncClient)
    connector.client.get = AsyncMock(return_value=_mock_response(SCIM_USER_DETAIL))

    account = await connector.get_account("user-001")
    assert account is not None
    assert account.username == "john.doe"


async def test_get_account_not_found(connector):
    """Test getting a nonexistent account."""
    connector.client = AsyncMock(spec=httpx.AsyncClient)
    connector.client.get = AsyncMock(return_value=_mock_response({}, status_code=404))

    account = await connector.get_account("nonexistent")
    assert account is None


async def test_disconnect(connector):
    """Test disconnecting closes the client."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    connector.client = mock_client
    await connector.disconnect()
    mock_client.aclose.assert_called_once()
    assert connector.client is None


async def test_basic_auth_headers(connector):
    """Test Basic auth header generation."""
    headers = connector._build_headers()
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")


async def test_bearer_auth_headers():
    """Test Bearer token header generation."""
    conn = SailPointConnector({"base_url": "https://test.com", "token": "my-token"})
    headers = conn._build_headers()
    assert headers["Authorization"] == "Bearer my-token"
