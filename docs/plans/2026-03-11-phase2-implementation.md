# Phase 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend AccessAudit with Azure AD + GCP connectors, ML anomaly detection, OPA policy engine, FastAPI + HTMX dashboard, and HTML/PDF compliance reports.

**Architecture:** Plug new components into existing layered architecture. BaseConnector ABC gets Azure/GCP implementations. Analysis engine gains ML anomaly detector + OPA policy engine. FastAPI wraps existing Scanner/Analyzer/Reporter. HTMX dashboard served by same FastAPI app. Compliance reports use Jinja2 HTML templates with optional weasyprint PDF.

**Tech Stack:** Python 3.11+, FastAPI, HTMX, Jinja2, Tailwind CSS (CDN), scikit-learn (Isolation Forest), OPA (subprocess), weasyprint, msal, azure-identity, google-cloud-iam

---

## Task 1: Update Dependencies and Project Config

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/accessaudit/__init__.py`

**Step 1: Update pyproject.toml with new dependencies**

Add to `dependencies` list:
```python
"weasyprint>=61.0",        # PDF report generation
```

Add new optional dependency groups:
```toml
azure = [
    "msal>=1.26.0",
    "azure-identity>=1.15.0",
    "azure-mgmt-authorization>=4.0.0",
    "azure-mgmt-resource>=23.0.0",
    "msgraph-sdk>=1.2.0",
]

gcp = [
    "google-cloud-iam>=2.14.0",
    "google-auth>=2.27.0",
    "google-cloud-resource-manager>=1.12.0",
]

all = [
    "accessaudit[azure,gcp]",
]
```

**Step 2: Install updated dependencies**

Run: `cd /home/adhampx/phoenix/projects/accessaudit && pip install -e ".[dev]"`
Expected: Successful installation

**Step 3: Verify existing tests still pass**

Run: `cd /home/adhampx/phoenix/projects/accessaudit && python -m pytest tests/ -v`
Expected: All 40 tests pass

**Step 4: Commit**

```
git add pyproject.toml
git commit -m "chore: update dependencies for Phase 2 features"
```

---

## Task 2: Extend BaseConnector ABC with list_roles()

**Files:**
- Modify: `src/accessaudit/connectors/base.py`
- Modify: `tests/unit/test_connectors.py`

**Step 1: Write failing test**

Add to `tests/unit/test_connectors.py`:
```python
@pytest.mark.asyncio
async def test_base_connector_list_roles_default():
    """list_roles() should return empty list by default."""
    connector = MockConnector({"region": "us-east-1"})
    roles = await connector.list_roles()
    assert roles == []
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_connectors.py::test_base_connector_list_roles_default -v`
Expected: FAIL with AttributeError (list_roles not defined)

**Step 3: Add list_roles to BaseConnector**

In `src/accessaudit/connectors/base.py`, add after `test_connection()`:
```python
async def list_roles(self) -> list[Policy]:
    """List roles from provider. Override in subclasses that have distinct role concepts.

    Returns:
        List of Policy objects representing roles
    """
    return []
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_connectors.py -v`
Expected: All pass

**Step 5: Commit**

```
git add src/accessaudit/connectors/base.py tests/unit/test_connectors.py
git commit -m "feat: add list_roles() to BaseConnector ABC"
```

---

## Task 3: Add ANOMALY to FindingCategory

**Files:**
- Modify: `src/accessaudit/models/finding.py`
- Modify: `tests/unit/test_models.py`

**Step 1: Write failing test**

Add to `tests/unit/test_models.py`:
```python
def test_finding_category_anomaly():
    """FindingCategory should include ANOMALY."""
    assert FindingCategory.ANOMALY == "anomaly"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_models.py::test_finding_category_anomaly -v`
Expected: FAIL with AttributeError

**Step 3: Add ANOMALY to FindingCategory enum**

In `src/accessaudit/models/finding.py`, add to `FindingCategory`:
```python
ANOMALY = "anomaly"
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_models.py -v`
Expected: All pass

**Step 5: Commit**

```
git add src/accessaudit/models/finding.py tests/unit/test_models.py
git commit -m "feat: add ANOMALY category to FindingCategory"
```

---

## Task 4: Azure AD Connector

**Files:**
- Create: `src/accessaudit/connectors/azure.py`
- Create: `tests/unit/test_azure_connector.py`
- Create: `tests/fixtures/azure_fixtures.py`
- Modify: `src/accessaudit/connectors/__init__.py`

**Step 1: Create Azure fixtures**

Create `tests/fixtures/azure_fixtures.py`:
```python
"""Mock Azure AD and RBAC data for testing."""


def make_azure_user(
    user_id: str = "user-001",
    display_name: str = "John Doe",
    upn: str = "john.doe@contoso.com",
    account_enabled: bool = True,
    mfa_registered: bool = True,
    member_of: list[str] | None = None,
    last_sign_in: str | None = "2026-03-01T10:00:00Z",
) -> dict:
    """Create a mock Azure AD user."""
    return {
        "id": user_id,
        "displayName": display_name,
        "userPrincipalName": upn,
        "accountEnabled": account_enabled,
        "createdDateTime": "2025-01-15T10:00:00Z",
        "signInActivity": {
            "lastSignInDateTime": last_sign_in,
        } if last_sign_in else None,
        "memberOf": [{"displayName": g} for g in (member_of or [])],
    }


def make_azure_directory_role(
    role_id: str = "role-001",
    display_name: str = "Global Administrator",
    members: list[str] | None = None,
) -> dict:
    """Create a mock Azure directory role."""
    return {
        "id": role_id,
        "displayName": display_name,
        "members": members or [],
    }


def make_azure_rbac_assignment(
    assignment_id: str = "assign-001",
    principal_id: str = "user-001",
    role_definition_name: str = "Contributor",
    scope: str = "/subscriptions/sub-001",
) -> dict:
    """Create a mock Azure RBAC role assignment."""
    return {
        "id": assignment_id,
        "properties": {
            "principalId": principal_id,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{assignment_id}",
            "scope": scope,
        },
        "role_definition_name": role_definition_name,
    }


def make_azure_service_principal(
    sp_id: str = "sp-001",
    display_name: str = "MyApp",
    app_id: str = "app-001",
) -> dict:
    """Create a mock Azure service principal."""
    return {
        "id": sp_id,
        "displayName": display_name,
        "appId": app_id,
        "servicePrincipalType": "Application",
    }
```

**Step 2: Write failing tests**

Create `tests/unit/test_azure_connector.py`:
```python
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
    return AzureConnector(azure_config)


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
            make_azure_user(user_id="u2", display_name="Bob", upn="bob@contoso.com", account_enabled=False),
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
            {"id": "/role-def/owner", "properties": {"roleName": "Owner", "permissions": [{"actions": ["*"]}], "type": "BuiltInRole"}},
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

        with patch.object(connector, "_fetch_rbac_assignments_for_principal", return_value=mock_assignments):
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
```

**Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_azure_connector.py -v`
Expected: FAIL (module not found)

**Step 4: Implement AzureConnector**

Create `src/accessaudit/connectors/azure.py`:
```python
"""Azure AD + ARM RBAC connector."""

import hashlib
from datetime import datetime, timezone
from typing import Any

from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class AzureConnector(BaseConnector):
    """Azure AD + ARM RBAC connector using Microsoft Graph API and Azure Management SDK."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.tenant_id = config.get("tenant_id", "")
        self.client_id = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")
        self.subscription_id = config.get("subscription_id", "")
        self._credential = None
        self._graph_token = None
        self._auth_client = None

    async def connect(self) -> None:
        if not HAS_AZURE:
            raise ConnectionError(
                "Azure SDK not installed. Install with: pip install accessaudit[azure]"
            )

        try:
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            # Get Graph API token to verify credentials
            self._graph_token = self._credential.get_token("https://graph.microsoft.com/.default")

            # Initialize ARM authorization client
            if self.subscription_id:
                self._auth_client = AuthorizationManagementClient(
                    self._credential, self.subscription_id
                )
        except Exception as e:
            raise ConnectionError(f"Azure connection failed: {e}") from e

    async def disconnect(self) -> None:
        self._credential = None
        self._graph_token = None
        self._auth_client = None

    async def test_connection(self) -> bool:
        try:
            await self.connect()
            return True
        except Exception:
            return False

    async def list_accounts(self) -> list[Account]:
        if not self._credential:
            await self.connect()

        users = await self._fetch_users()
        mfa_status = await self._fetch_user_mfa_status()
        admin_members = await self._fetch_directory_role_members()

        accounts = []
        for user in users:
            user_id = user["id"]
            upn = user.get("userPrincipalName", "")

            # Determine status
            status = AccountStatus.ACTIVE if user.get("accountEnabled") else AccountStatus.DISABLED

            # Last sign-in
            sign_in = user.get("signInActivity") or {}
            last_sign_in_str = sign_in.get("lastSignInDateTime")
            last_login = None
            if last_sign_in_str:
                try:
                    last_login = datetime.fromisoformat(last_sign_in_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            # Groups
            groups = [m.get("displayName", "") for m in user.get("memberOf", []) if m.get("displayName")]

            # Admin check
            is_admin = user_id in admin_members.get("Global Administrator", set())

            # MFA
            mfa_enabled = mfa_status.get(user_id, False)

            created_str = user.get("createdDateTime")
            created_at = None
            if created_str:
                try:
                    created_at = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            account = Account(
                id=user_id,
                provider="azure",
                username=upn,
                email=upn if "@" in upn else None,
                created_at=created_at,
                last_login=last_login,
                last_activity=last_login,
                status=status,
                mfa_enabled=mfa_enabled,
                has_admin_role=is_admin,
                groups=groups,
                metadata={"display_name": user.get("displayName", "")},
            )
            accounts.append(account)

        return accounts

    async def get_account(self, account_id: str) -> Account | None:
        if not self._credential:
            await self.connect()

        try:
            user = await self._graph_get(f"/users/{account_id}")
            if not user:
                return None
            accounts = await self.list_accounts()
            for a in accounts:
                if a.id == account_id:
                    return a
            return None
        except Exception:
            return None

    async def list_policies(self) -> list[Policy]:
        if not self._credential:
            await self.connect()

        role_defs = await self._fetch_rbac_role_definitions()
        policies = []

        for role_def in role_defs:
            props = role_def.get("properties", {})
            role_name = props.get("roleName", "Unknown")
            role_type = props.get("type", "CustomRole")

            permissions_list = props.get("permissions", [])
            actions = []
            for perm in permissions_list:
                actions.extend(perm.get("actions", []))

            policy = Policy(
                id=role_def["id"],
                name=role_name,
                arn=role_def["id"],
                provider="azure",
                policy_type="builtin" if role_type == "BuiltInRole" else "custom",
                document={"permissions": permissions_list},
                is_aws_managed=False,
                metadata={"role_type": role_type},
            )
            policies.append(policy)

        return policies

    async def list_roles(self) -> list[Policy]:
        """List Azure directory roles."""
        if not self._credential:
            await self.connect()

        roles_data = await self._graph_get("/directoryRoles")
        roles = []

        for role in (roles_data or {}).get("value", []):
            policy = Policy(
                id=role["id"],
                name=role.get("displayName", ""),
                arn=role["id"],
                provider="azure",
                policy_type="directory-role",
                document={"role_template_id": role.get("roleTemplateId")},
                is_aws_managed=False,
                metadata={"description": role.get("description", "")},
            )
            roles.append(policy)

        return roles

    async def get_account_permissions(self, account_id: str) -> list[Permission]:
        if not self._credential:
            await self.connect()

        permissions = []

        # Directory roles
        dir_roles = await self._fetch_directory_roles_for_user(account_id)
        for role in dir_roles:
            perm_id = hashlib.md5(f"azure-dir-role:{account_id}:{role['id']}".encode()).hexdigest()[:16]
            permission = Permission(
                id=f"perm-{perm_id}",
                account_id=account_id,
                resource_type="directory",
                resource_arn=f"/directory/roles/{role['id']}",
                actions=[f"directory:{role.get('displayName', 'Unknown')}"],
                effect="Allow",
                source_policy=f"DirectoryRole:{role.get('displayName', 'Unknown')}",
                metadata={"role_type": "directory"},
            )
            permission.scope = permission.calculate_scope()
            permissions.append(permission)

        # RBAC assignments
        rbac_assignments = await self._fetch_rbac_assignments_for_principal(account_id)
        for assignment in rbac_assignments:
            role_name = assignment.get("role_definition_name", "Unknown")
            props = assignment.get("properties", {})
            scope = props.get("scope", "")

            perm_id = hashlib.md5(f"azure-rbac:{account_id}:{assignment['id']}".encode()).hexdigest()[:16]
            permission = Permission(
                id=f"perm-{perm_id}",
                account_id=account_id,
                resource_type="subscription",
                resource_arn=scope,
                actions=[f"rbac:{role_name}"],
                effect="Allow",
                source_policy=f"RBAC:{role_name}",
                metadata={"assignment_id": assignment["id"]},
            )
            permission.scope = permission.calculate_scope()
            permissions.append(permission)

        return permissions

    # --- Private helpers: Graph API ---

    async def _graph_get(self, endpoint: str) -> dict | None:
        """Make a GET request to Microsoft Graph API."""
        if not HAS_HTTPX:
            return None

        token = self._credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}
        url = f"https://graph.microsoft.com/v1.0{endpoint}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
        return None

    async def _fetch_users(self) -> list[dict]:
        """Fetch all Azure AD users via Graph API."""
        result = await self._graph_get(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,"
            "createdDateTime,signInActivity&$top=999"
        )
        if not result:
            return []

        users = result.get("value", [])

        # Handle pagination
        next_link = result.get("@odata.nextLink")
        while next_link:
            path = next_link.replace("https://graph.microsoft.com/v1.0", "")
            result = await self._graph_get(path)
            if not result:
                break
            users.extend(result.get("value", []))
            next_link = result.get("@odata.nextLink")

        return users

    async def _fetch_user_mfa_status(self) -> dict[str, bool]:
        """Fetch MFA registration status for all users."""
        result = await self._graph_get(
            "/reports/authenticationMethods/userRegistrationDetails"
        )
        if not result:
            return {}

        mfa_status = {}
        for entry in result.get("value", []):
            user_id = entry.get("id", "")
            methods = entry.get("methodsRegistered", [])
            mfa_status[user_id] = len(methods) > 1
        return mfa_status

    async def _fetch_directory_role_members(self) -> dict[str, set[str]]:
        """Fetch members of directory roles. Returns {role_name: {user_ids}}."""
        result = await self._graph_get("/directoryRoles?$expand=members")
        if not result:
            return {}

        role_members: dict[str, set[str]] = {}
        for role in result.get("value", []):
            role_name = role.get("displayName", "")
            members = {m["id"] for m in role.get("members", []) if "id" in m}
            role_members[role_name] = members
        return role_members

    async def _fetch_directory_roles_for_user(self, user_id: str) -> list[dict]:
        """Fetch directory roles assigned to a specific user."""
        result = await self._graph_get(f"/users/{user_id}/memberOf/microsoft.graph.directoryRole")
        if not result:
            return []
        return result.get("value", [])

    async def _fetch_rbac_role_definitions(self) -> list[dict]:
        """Fetch RBAC role definitions via ARM."""
        if not self._auth_client:
            return []

        try:
            definitions = list(self._auth_client.role_definitions.list(
                scope=f"/subscriptions/{self.subscription_id}"
            ))
            return [d.as_dict() for d in definitions]
        except Exception:
            return []

    async def _fetch_rbac_assignments_for_principal(self, principal_id: str) -> list[dict]:
        """Fetch RBAC role assignments for a principal."""
        if not self._auth_client:
            return []

        try:
            assignments = list(self._auth_client.role_assignments.list_for_scope(
                scope=f"/subscriptions/{self.subscription_id}",
                filter=f"principalId eq '{principal_id}'"
            ))
            result = []
            for a in assignments:
                a_dict = a.as_dict()
                role_def_id = a_dict.get("properties", {}).get("roleDefinitionId", "")
                try:
                    role_def = self._auth_client.role_definitions.get_by_id(role_def_id)
                    a_dict["role_definition_name"] = role_def.role_name
                except Exception:
                    a_dict["role_definition_name"] = "Unknown"
                result.append(a_dict)
            return result
        except Exception:
            return []
```

**Step 5: Update connectors __init__.py**

In `src/accessaudit/connectors/__init__.py`:
```python
"""IAM provider connectors."""

from accessaudit.connectors.base import BaseConnector
from accessaudit.connectors.aws import AWSConnector

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None

__all__ = ["BaseConnector", "AWSConnector", "AzureConnector"]
```

**Step 6: Run tests**

Run: `python -m pytest tests/unit/test_azure_connector.py -v`
Expected: All pass

**Step 7: Commit**

```
git add src/accessaudit/connectors/azure.py src/accessaudit/connectors/__init__.py tests/unit/test_azure_connector.py tests/fixtures/azure_fixtures.py
git commit -m "feat: add Azure AD + ARM RBAC connector"
```

---

## Task 5: GCP IAM Connector

**Files:**
- Create: `src/accessaudit/connectors/gcp.py`
- Create: `tests/unit/test_gcp_connector.py`
- Create: `tests/fixtures/gcp_fixtures.py`
- Modify: `src/accessaudit/connectors/__init__.py`

**Step 1: Create GCP fixtures**

Create `tests/fixtures/gcp_fixtures.py`:
```python
"""Mock GCP IAM data for testing."""


def make_gcp_service_account(
    email: str = "my-sa@project.iam.gserviceaccount.com",
    unique_id: str = "sa-001",
    display_name: str = "My Service Account",
    disabled: bool = False,
) -> dict:
    return {
        "name": f"projects/my-project/serviceAccounts/{email}",
        "email": email,
        "uniqueId": unique_id,
        "displayName": display_name,
        "disabled": disabled,
    }


def make_gcp_iam_binding(
    role: str = "roles/editor",
    members: list[str] | None = None,
) -> dict:
    return {
        "role": role,
        "members": members or ["serviceAccount:my-sa@project.iam.gserviceaccount.com"],
    }


def make_gcp_role(
    name: str = "roles/editor",
    title: str = "Editor",
    permissions: list[str] | None = None,
    stage: str = "GA",
) -> dict:
    return {
        "name": name,
        "title": title,
        "includedPermissions": permissions or ["resourcemanager.projects.get"],
        "stage": stage,
    }
```

**Step 2: Write failing tests**

Create `tests/unit/test_gcp_connector.py`:
```python
"""Tests for GCP IAM connector."""

import pytest
from unittest.mock import AsyncMock, patch

from accessaudit.connectors.gcp import GCPConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy
from tests.fixtures.gcp_fixtures import (
    make_gcp_service_account,
    make_gcp_iam_binding,
    make_gcp_role,
)


@pytest.fixture
def gcp_config():
    return {
        "project_id": "my-project",
        "credentials_file": "/path/to/creds.json",
    }


@pytest.fixture
def connector(gcp_config):
    return GCPConnector(gcp_config)


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
            make_gcp_service_account(email="sa2@proj.iam.gserviceaccount.com", unique_id="sa-2", disabled=True),
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
            make_gcp_iam_binding(role="roles/editor", members=["serviceAccount:sa1@proj.iam.gserviceaccount.com"]),
        ]

        with patch.object(connector, "_fetch_iam_bindings", return_value=mock_bindings):
            permissions = await connector.get_account_permissions("sa1@proj.iam.gserviceaccount.com")

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
```

**Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_gcp_connector.py -v`
Expected: FAIL (module not found)

**Step 4: Implement GCPConnector**

Create `src/accessaudit/connectors/gcp.py`:
```python
"""GCP IAM connector."""

import hashlib
from typing import Any

from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy

try:
    from google.oauth2 import service_account
    from google.cloud import resourcemanager_v3
    HAS_GCP = True
except ImportError:
    HAS_GCP = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class GCPConnector(BaseConnector):
    """GCP IAM connector using Cloud Resource Manager and IAM APIs."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.project_id = config.get("project_id", "")
        self.credentials_file = config.get("credentials_file")
        self._credentials = None
        self._rm_client = None

    async def connect(self) -> None:
        if not HAS_GCP:
            raise ConnectionError(
                "GCP SDK not installed. Install with: pip install accessaudit[gcp]"
            )

        try:
            if self.credentials_file:
                self._credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_file,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
            else:
                import google.auth
                self._credentials, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )

            self._rm_client = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
            self._rm_client.get_project(name=f"projects/{self.project_id}")

        except Exception as e:
            raise ConnectionError(f"GCP connection failed: {e}") from e

    async def disconnect(self) -> None:
        self._credentials = None
        self._rm_client = None

    async def test_connection(self) -> bool:
        try:
            await self.connect()
            return True
        except Exception:
            return False

    async def list_accounts(self) -> list[Account]:
        if not self._credentials:
            await self.connect()

        service_accounts = await self._fetch_service_accounts()
        bindings = await self._fetch_iam_bindings()

        member_roles: dict[str, list[str]] = {}
        for binding in bindings:
            role = binding.get("role", "")
            for member in binding.get("members", []):
                member_roles.setdefault(member, []).append(role)

        accounts = []
        for sa in service_accounts:
            email = sa.get("email", "")
            disabled = sa.get("disabled", False)
            member_key = f"serviceAccount:{email}"
            roles = member_roles.get(member_key, [])

            is_admin = any("owner" in r.lower() or "admin" in r.lower() for r in roles)

            account = Account(
                id=sa.get("uniqueId", email),
                provider="gcp",
                username=email,
                email=email,
                status=AccountStatus.DISABLED if disabled else AccountStatus.ACTIVE,
                mfa_enabled=False,
                has_admin_role=is_admin,
                groups=[],
                metadata={
                    "display_name": sa.get("displayName", ""),
                    "name": sa.get("name", ""),
                    "roles": roles,
                },
            )
            accounts.append(account)

        return accounts

    async def get_account(self, account_id: str) -> Account | None:
        if not self._credentials:
            await self.connect()

        accounts = await self.list_accounts()
        for a in accounts:
            if a.id == account_id or a.username == account_id:
                return a
        return None

    async def list_policies(self) -> list[Policy]:
        if not self._credentials:
            await self.connect()

        roles = await self._fetch_roles()
        policies = []

        for role in roles:
            role_name = role.get("name", "")
            title = role.get("title", role_name)
            perms = role.get("includedPermissions", [])
            stage = role.get("stage", "")

            is_predefined = role_name.startswith("roles/")

            policy = Policy(
                id=role_name,
                name=title,
                arn=role_name,
                provider="gcp",
                policy_type="predefined" if is_predefined else "custom",
                document={"includedPermissions": perms},
                is_aws_managed=False,
                metadata={"stage": stage},
            )
            policies.append(policy)

        return policies

    async def list_roles(self) -> list[Policy]:
        """List GCP IAM roles."""
        return await self.list_policies()

    async def get_account_permissions(self, account_id: str) -> list[Permission]:
        if not self._credentials:
            await self.connect()

        bindings = await self._fetch_iam_bindings()
        permissions = []

        member_key = f"serviceAccount:{account_id}"

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])

            if member_key in members or account_id in members:
                perm_id = hashlib.md5(f"gcp:{account_id}:{role}".encode()).hexdigest()[:16]

                permission = Permission(
                    id=f"perm-{perm_id}",
                    account_id=account_id,
                    resource_type="project",
                    resource_arn=f"projects/{self.project_id}",
                    actions=[role],
                    effect="Allow",
                    source_policy=role,
                    metadata={"binding_role": role},
                )
                permission.scope = permission.calculate_scope()
                permissions.append(permission)

        return permissions

    # --- Private helpers ---

    async def _fetch_service_accounts(self) -> list[dict]:
        """Fetch service accounts via IAM API."""
        if not HAS_HTTPX or not self._credentials:
            return []

        try:
            import google.auth.transport.requests
            self._credentials.refresh(google.auth.transport.requests.Request())
            url = f"https://iam.googleapis.com/v1/projects/{self.project_id}/serviceAccounts"
            headers = {"Authorization": f"Bearer {self._credentials.token}"}

            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    return response.json().get("accounts", [])
        except Exception:
            pass
        return []

    async def _fetch_iam_bindings(self) -> list[dict]:
        """Fetch IAM policy bindings for the project."""
        if not HAS_HTTPX or not self._credentials:
            return []

        try:
            import google.auth.transport.requests
            self._credentials.refresh(google.auth.transport.requests.Request())
            url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}:getIamPolicy"
            headers = {"Authorization": f"Bearer {self._credentials.token}"}

            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json={})
                if response.status_code == 200:
                    return response.json().get("bindings", [])
        except Exception:
            pass
        return []

    async def _fetch_roles(self) -> list[dict]:
        """Fetch IAM roles (predefined + custom)."""
        if not HAS_HTTPX or not self._credentials:
            return []

        roles = []
        try:
            import google.auth.transport.requests
            self._credentials.refresh(google.auth.transport.requests.Request())
            headers = {"Authorization": f"Bearer {self._credentials.token}"}

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://iam.googleapis.com/v1/roles?view=FULL&pageSize=1000",
                    headers=headers,
                )
                if response.status_code == 200:
                    roles.extend(response.json().get("roles", []))

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://iam.googleapis.com/v1/projects/{self.project_id}/roles?view=FULL",
                    headers=headers,
                )
                if response.status_code == 200:
                    roles.extend(response.json().get("roles", []))
        except Exception:
            pass
        return roles
```

**Step 5: Update connectors __init__.py**

In `src/accessaudit/connectors/__init__.py`:
```python
"""IAM provider connectors."""

from accessaudit.connectors.base import BaseConnector
from accessaudit.connectors.aws import AWSConnector

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None

try:
    from accessaudit.connectors.gcp import GCPConnector
except ImportError:
    GCPConnector = None

__all__ = ["BaseConnector", "AWSConnector", "AzureConnector", "GCPConnector"]
```

**Step 6: Run tests**

Run: `python -m pytest tests/unit/test_gcp_connector.py -v`
Expected: All pass

**Step 7: Commit**

```
git add src/accessaudit/connectors/gcp.py src/accessaudit/connectors/__init__.py tests/unit/test_gcp_connector.py tests/fixtures/gcp_fixtures.py
git commit -m "feat: add GCP IAM connector"
```

---

## Task 6: Register New Connectors in Scanner

**Files:**
- Modify: `src/accessaudit/core/scanner.py`
- Modify: `tests/unit/test_connectors.py`

**Step 1: Write failing test**

Add to existing connector tests:
```python
def test_scanner_supports_azure():
    scanner = Scanner()
    connector = scanner._create_connector("azure", {"tenant_id": "t", "client_id": "c", "client_secret": "s"})
    assert connector.provider_name == "azure"

def test_scanner_supports_gcp():
    scanner = Scanner()
    connector = scanner._create_connector("gcp", {"project_id": "p"})
    assert connector.provider_name == "gcp"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_connectors.py::test_scanner_supports_azure -v`
Expected: FAIL (ValueError: Unsupported provider: azure)

**Step 3: Update Scanner._create_connector**

In `src/accessaudit/core/scanner.py`, update the imports and `_create_connector` method:

Replace the existing import:
```python
from accessaudit.connectors.aws import AWSConnector
```

With:
```python
from accessaudit.connectors.aws import AWSConnector

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None

try:
    from accessaudit.connectors.gcp import GCPConnector
except ImportError:
    GCPConnector = None
```

Update the connectors dict in `_create_connector`:
```python
connectors = {
    "aws": AWSConnector,
}
if AzureConnector:
    connectors["azure"] = AzureConnector
if GCPConnector:
    connectors["gcp"] = GCPConnector
```

**Step 4: Run tests**

Run: `python -m pytest tests/ -v`
Expected: All pass

**Step 5: Commit**

```
git add src/accessaudit/core/scanner.py tests/unit/test_connectors.py
git commit -m "feat: register Azure and GCP connectors in Scanner"
```

---

## Task 7: ML Feature Extraction

**Files:**
- Create: `src/accessaudit/analysis/features.py`
- Create: `tests/unit/test_features.py`

**Step 1: Write failing tests**

Create `tests/unit/test_features.py`:
```python
"""Tests for ML feature extraction."""

import pytest
from datetime import datetime, timezone, timedelta

from accessaudit.analysis.features import FeatureExtractor
from accessaudit.models import Account, Permission, PermissionScope


@pytest.fixture
def accounts():
    return [
        Account(
            id="u1", provider="aws", username="alice",
            mfa_enabled=True, has_admin_role=False,
            groups=["developers"],
            created_at=datetime.now(timezone.utc) - timedelta(days=365),
            last_activity=datetime.now(timezone.utc) - timedelta(days=5),
        ),
        Account(
            id="u2", provider="aws", username="bob",
            mfa_enabled=False, has_admin_role=True,
            groups=["developers", "admins"],
            created_at=datetime.now(timezone.utc) - timedelta(days=200),
            last_activity=datetime.now(timezone.utc) - timedelta(days=1),
        ),
    ]


@pytest.fixture
def permissions():
    return {
        "u1": [
            Permission(id="p1", account_id="u1", resource_type="s3", resource_arn="arn:s3:::bucket", actions=["s3:GetObject"], source_policy="pol1"),
            Permission(id="p2", account_id="u1", resource_type="s3", resource_arn="arn:s3:::bucket", actions=["s3:PutObject"], source_policy="pol1"),
            Permission(id="p3", account_id="u1", resource_type="ec2", resource_arn="*", actions=["ec2:DescribeInstances"], source_policy="pol2"),
        ],
        "u2": [
            Permission(id="p4", account_id="u2", resource_type="iam", resource_arn="*", actions=["*"], source_policy="admin-pol"),
        ],
    }


class TestFeatureExtractor:
    def test_extract_returns_correct_shape(self, accounts, permissions):
        extractor = FeatureExtractor()
        features, account_ids = extractor.extract(accounts, permissions)
        assert len(features) == 2
        assert len(account_ids) == 2

    def test_feature_vector_length(self, accounts, permissions):
        extractor = FeatureExtractor()
        features, _ = extractor.extract(accounts, permissions)
        assert len(features[0]) == len(features[1])

    def test_peer_groups(self, accounts, permissions):
        extractor = FeatureExtractor()
        groups = extractor.group_by_peers(accounts)
        assert "developers" in groups
        assert len(groups["developers"]) == 2

    def test_empty_permissions(self, accounts):
        extractor = FeatureExtractor()
        features, account_ids = extractor.extract(accounts, {})
        assert len(features) == 2
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_features.py -v`
Expected: FAIL (module not found)

**Step 3: Implement FeatureExtractor**

Create `src/accessaudit/analysis/features.py`:
```python
"""Feature extraction for ML anomaly detection."""

from collections import Counter
from datetime import datetime, timezone

from accessaudit.models import Account, Permission, PermissionScope


class FeatureExtractor:
    """Extracts feature vectors from accounts and permissions for ML analysis."""

    SERVICE_PREFIXES = [
        "s3", "ec2", "iam", "lambda", "rds", "dynamodb", "sqs", "sns",
        "cloudwatch", "kms", "sts", "directory", "subscription", "project",
    ]

    def extract(
        self, accounts: list[Account], all_permissions: dict[str, list[Permission]]
    ) -> tuple[list[list[float]], list[str]]:
        """Extract feature vectors for all accounts."""
        features = []
        account_ids = []

        for account in accounts:
            permissions = all_permissions.get(account.id, [])
            feature_vector = self._account_features(account, permissions)
            features.append(feature_vector)
            account_ids.append(account.id)

        return features, account_ids

    def group_by_peers(self, accounts: list[Account]) -> dict[str, list[Account]]:
        """Group accounts by their primary group for peer comparison."""
        groups: dict[str, list[Account]] = {}

        for account in accounts:
            if account.groups:
                primary_group = account.groups[0]
            else:
                primary_group = "_ungrouped"

            groups.setdefault(primary_group, []).append(account)

        return groups

    def _account_features(self, account: Account, permissions: list[Permission]) -> list[float]:
        """Extract feature vector for a single account."""
        features: list[float] = []

        # Permission count per service
        service_counts = Counter()
        for perm in permissions:
            matched = False
            for svc in self.SERVICE_PREFIXES:
                if svc in perm.resource_type.lower():
                    service_counts[svc] += 1
                    matched = True
                    break
            if not matched:
                service_counts["_other"] += 1

        for svc in self.SERVICE_PREFIXES:
            features.append(float(service_counts.get(svc, 0)))

        # Scope distribution
        total = len(permissions) or 1
        scope_counts = Counter(p.scope for p in permissions)
        features.append(scope_counts.get(PermissionScope.READ, 0) / total)
        features.append(scope_counts.get(PermissionScope.WRITE, 0) / total)
        features.append(scope_counts.get(PermissionScope.ADMIN, 0) / total)

        # Total permission count
        features.append(float(len(permissions)))

        # Number of groups
        features.append(float(len(account.groups)))

        # MFA enabled
        features.append(1.0 if account.mfa_enabled else 0.0)

        # Has admin role
        features.append(1.0 if account.has_admin_role else 0.0)

        # Account age in days
        if account.created_at:
            age = (datetime.now(timezone.utc) - account.created_at.replace(tzinfo=timezone.utc)).days
            features.append(float(max(age, 0)))
        else:
            features.append(0.0)

        # Number of unique source policies
        unique_policies = set(p.source_policy for p in permissions)
        features.append(float(len(unique_policies)))

        return features
```

**Step 4: Run tests**

Run: `python -m pytest tests/unit/test_features.py -v`
Expected: All pass

**Step 5: Commit**

```
git add src/accessaudit/analysis/features.py tests/unit/test_features.py
git commit -m "feat: add ML feature extraction for anomaly detection"
```

---

## Task 8: ML Anomaly Detector

**Files:**
- Create: `src/accessaudit/analysis/anomaly.py`
- Create: `tests/unit/test_anomaly.py`

**Step 1: Write failing tests**

Create `tests/unit/test_anomaly.py`:
```python
"""Tests for ML anomaly detection."""

import pytest
from datetime import datetime, timezone, timedelta

from accessaudit.analysis.anomaly import AnomalyDetector
from accessaudit.models import Account, Permission, FindingCategory


def _make_account(uid: str, groups: list[str] | None = None, admin: bool = False) -> Account:
    return Account(
        id=uid, provider="aws", username=f"user-{uid}",
        mfa_enabled=True, has_admin_role=admin,
        groups=groups or ["developers"],
        created_at=datetime.now(timezone.utc) - timedelta(days=180),
        last_activity=datetime.now(timezone.utc) - timedelta(days=3),
    )


def _make_permissions(uid: str, count: int = 3) -> list[Permission]:
    return [
        Permission(
            id=f"p-{uid}-{i}", account_id=uid,
            resource_type="s3", resource_arn="arn:s3:::bucket",
            actions=["s3:GetObject"], source_policy=f"pol-{uid}",
        )
        for i in range(count)
    ]


class TestAnomalyDetector:
    def test_init_default_config(self):
        detector = AnomalyDetector()
        assert detector.min_group_size == 10
        assert detector.contamination == 0.1

    def test_init_custom_config(self):
        detector = AnomalyDetector({"min_group_size": 5, "contamination": 0.05})
        assert detector.min_group_size == 5

    @pytest.mark.asyncio
    async def test_skips_small_groups(self):
        """Groups with fewer than min_group_size accounts should be skipped."""
        detector = AnomalyDetector({"min_group_size": 10})
        accounts = [_make_account(f"u{i}") for i in range(5)]
        permissions = {a.id: _make_permissions(a.id) for a in accounts}

        findings = await detector.analyze(accounts, permissions)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detects_outlier_in_large_group(self):
        """Should detect an account with vastly different permissions."""
        detector = AnomalyDetector({"min_group_size": 5, "contamination": 0.15})

        accounts = [_make_account(f"u{i}") for i in range(14)]
        permissions = {a.id: _make_permissions(a.id, count=3) for a in accounts}

        outlier = _make_account("outlier", admin=True)
        accounts.append(outlier)
        permissions[outlier.id] = [
            Permission(
                id=f"p-outlier-{i}", account_id=outlier.id,
                resource_type="iam", resource_arn="*",
                actions=["*"], source_policy="admin-pol",
            )
            for i in range(50)
        ]

        findings = await detector.analyze(accounts, permissions)
        assert len(findings) >= 1
        anomaly_findings = [f for f in findings if f.category == FindingCategory.ANOMALY]
        assert len(anomaly_findings) >= 1

    @pytest.mark.asyncio
    async def test_findings_have_anomaly_category(self):
        """All findings should have ANOMALY category."""
        detector = AnomalyDetector({"min_group_size": 3, "contamination": 0.3})

        accounts = [_make_account(f"u{i}") for i in range(9)]
        permissions = {a.id: _make_permissions(a.id, count=2) for a in accounts}

        outlier = _make_account("outlier", admin=True)
        accounts.append(outlier)
        permissions[outlier.id] = [
            Permission(
                id=f"p-out-{i}", account_id=outlier.id,
                resource_type="iam", resource_arn="*",
                actions=["*"], source_policy="admin",
            )
            for i in range(40)
        ]

        findings = await detector.analyze(accounts, permissions)
        for f in findings:
            assert f.category == FindingCategory.ANOMALY
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_anomaly.py -v`
Expected: FAIL (module not found)

**Step 3: Implement AnomalyDetector**

Create `src/accessaudit/analysis/anomaly.py`:
```python
"""ML-based anomaly detection for IAM permissions."""

import hashlib
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from accessaudit.analysis.features import FeatureExtractor
from accessaudit.models import Account, Finding, FindingCategory, FindingSeverity, Permission


class AnomalyDetector:
    """Detects permission anomalies using Isolation Forest on peer groups."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.min_group_size = self.config.get("min_group_size", 10)
        self.contamination = self.config.get("contamination", 0.1)
        self.feature_extractor = FeatureExtractor()

    async def analyze(
        self, accounts: list[Account], all_permissions: dict[str, list[Permission]]
    ) -> list[Finding]:
        """Run anomaly detection across peer groups."""
        findings = []
        peer_groups = self.feature_extractor.group_by_peers(accounts)

        for group_name, group_accounts in peer_groups.items():
            if len(group_accounts) < self.min_group_size:
                continue

            group_findings = await self._analyze_group(
                group_name, group_accounts, all_permissions
            )
            findings.extend(group_findings)

        return findings

    async def _analyze_group(
        self,
        group_name: str,
        accounts: list[Account],
        all_permissions: dict[str, list[Permission]],
    ) -> list[Finding]:
        """Analyze a single peer group for anomalies."""
        features, account_ids = self.feature_extractor.extract(accounts, all_permissions)

        if not features:
            return []

        X = np.array(features)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        clf = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        predictions = clf.fit_predict(X_scaled)
        scores = clf.decision_function(X_scaled)

        findings = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:
                account = accounts[i]
                account_perms = all_permissions.get(account.id, [])

                finding = self._create_finding(
                    account, group_name, float(score), account_perms
                )
                findings.append(finding)

        return findings

    def _create_finding(
        self,
        account: Account,
        group_name: str,
        anomaly_score: float,
        permissions: list[Permission],
    ) -> Finding:
        """Create a Finding for an anomalous account."""
        finding_id = hashlib.md5(
            f"anomaly:{account.id}:{group_name}".encode()
        ).hexdigest()[:16]

        if anomaly_score < -0.5:
            severity = FindingSeverity.HIGH
        elif anomaly_score < -0.3:
            severity = FindingSeverity.MEDIUM
        else:
            severity = FindingSeverity.LOW

        return Finding(
            id=f"finding-{finding_id}",
            severity=severity,
            category=FindingCategory.ANOMALY,
            account_id=account.id,
            title=f"Anomalous permission pattern detected in group '{group_name}'",
            description=(
                f"Account {account.username} has a permission pattern that is statistically "
                f"unusual compared to {group_name} peers. This may indicate over-provisioning, "
                f"role drift, or compromised credentials. "
                f"Anomaly score: {anomaly_score:.3f} (more negative = more anomalous)."
            ),
            remediation=(
                f"Review this account's {len(permissions)} permissions and compare with "
                f"other members of '{group_name}'. Remove any permissions not required for "
                f"this user's role."
            ),
            metadata={
                "anomaly_score": round(anomaly_score, 4),
                "peer_group": group_name,
                "permission_count": len(permissions),
                "detection_method": "isolation_forest",
            },
        )
```

**Step 4: Update analysis __init__.py**

In `src/accessaudit/analysis/__init__.py`, add:
```python
from accessaudit.analysis.anomaly import AnomalyDetector
from accessaudit.analysis.features import FeatureExtractor
```

**Step 5: Run tests**

Run: `python -m pytest tests/unit/test_anomaly.py -v`
Expected: All pass

**Step 6: Commit**

```
git add src/accessaudit/analysis/anomaly.py src/accessaudit/analysis/features.py src/accessaudit/analysis/__init__.py tests/unit/test_anomaly.py
git commit -m "feat: add ML anomaly detection with Isolation Forest"
```

---

## Task 9: Integrate AnomalyDetector into Analyzer

**Files:**
- Modify: `src/accessaudit/core/analyzer.py`
- Modify: `tests/unit/test_analysis.py`

**Step 1: Write failing test**

Add to `tests/unit/test_analysis.py`:
```python
@pytest.mark.asyncio
async def test_analyzer_runs_anomaly_detection():
    """Analyzer should include anomaly detection in its pipeline."""
    analyzer = Analyzer({"analysis": {"anomaly": {"min_group_size": 3}}})
    assert hasattr(analyzer, "anomaly_detector")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_analysis.py::test_analyzer_runs_anomaly_detection -v`
Expected: FAIL

**Step 3: Add AnomalyDetector to Analyzer**

In `src/accessaudit/core/analyzer.py`, add import:
```python
from accessaudit.analysis.anomaly import AnomalyDetector
```

In `__init__`, after the rule engine initialization add:
```python
anomaly_config = analysis_config.get("anomaly", {})
self.anomaly_detector = AnomalyDetector(anomaly_config)
```

In `analyze()`, after rule engine execution add:
```python
print(f"[{scan_result.scan_id}] Running anomaly detection...")
anomaly_findings = await self.anomaly_detector.analyze(
    scan_result.accounts, scan_result.permissions
)
result.findings.extend(anomaly_findings)
```

**Step 4: Run tests**

Run: `python -m pytest tests/unit/test_analysis.py -v`
Expected: All pass

**Step 5: Commit**

```
git add src/accessaudit/core/analyzer.py tests/unit/test_analysis.py
git commit -m "feat: integrate ML anomaly detection into Analyzer pipeline"
```

---

## Task 10: OPA Policy Engine

**Files:**
- Create: `src/accessaudit/analysis/policy_engine.py`
- Create: `tests/unit/test_policy_engine.py`
- Create: `rules/base.rego`

**Step 1: Write failing tests**

Create `tests/unit/test_policy_engine.py`:
```python
"""Tests for OPA policy engine."""

import json
import pytest
from unittest.mock import patch, AsyncMock
from pathlib import Path

from accessaudit.analysis.policy_engine import PolicyEngine
from accessaudit.models import Account, Permission, Policy, FindingCategory


@pytest.fixture
def base_rego(tmp_path):
    rego = tmp_path / "base.rego"
    rego.write_text("""
package accessaudit.rules

deny[msg] {
    input.account.has_admin_role
    not input.account.mfa_enabled
    msg := sprintf("Admin %s has no MFA", [input.account.username])
}
""")
    return str(rego)


@pytest.fixture
def engine(base_rego):
    return PolicyEngine({"rules_dir": str(Path(base_rego).parent)})


class TestPolicyEngine:
    def test_init_loads_rules_dir(self, engine, base_rego):
        assert len(engine.rule_files) >= 1

    @pytest.mark.asyncio
    async def test_evaluate_returns_violations(self, engine):
        """Should detect admin without MFA via Rego rule."""
        account = Account(
            id="u1", provider="aws", username="admin-user",
            mfa_enabled=False, has_admin_role=True,
        )

        opa_result = {
            "result": [{"expressions": [{"value": ["Admin admin-user has no MFA"]}]}]
        }

        with patch.object(engine, "_run_opa", return_value=opa_result):
            findings = await engine.evaluate_account(account, [])

        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.POLICY_VIOLATION

    @pytest.mark.asyncio
    async def test_no_violations_returns_empty(self, engine):
        """Account with MFA should pass."""
        account = Account(
            id="u2", provider="aws", username="good-user",
            mfa_enabled=True, has_admin_role=True,
        )

        opa_result = {"result": [{"expressions": [{"value": []}]}]}

        with patch.object(engine, "_run_opa", return_value=opa_result):
            findings = await engine.evaluate_account(account, [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_opa_not_installed_falls_back(self, engine):
        """Should gracefully handle missing OPA binary."""
        with patch.object(engine, "_opa_available", return_value=False):
            account = Account(
                id="u1", provider="aws", username="user",
                mfa_enabled=False, has_admin_role=True,
            )
            findings = await engine.evaluate_account(account, [])
            assert isinstance(findings, list)
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_policy_engine.py -v`
Expected: FAIL (module not found)

**Step 3: Create base.rego**

Create `rules/base.rego`:
```rego
package accessaudit.rules

# Admin accounts must have MFA enabled
deny[msg] {
    input.account.has_admin_role
    not input.account.mfa_enabled
    msg := sprintf("Admin account '%s' does not have MFA enabled", [input.account.username])
}

# No full wildcard permissions (*:* on *)
deny[msg] {
    some perm in input.permissions
    perm.actions[_] == "*"
    perm.resource_arn == "*"
    msg := sprintf("Full wildcard permissions from policy '%s'", [perm.source_policy])
}

# Dormant admin accounts are high risk
deny[msg] {
    input.account.has_admin_role
    input.account.days_since_activity > 90
    msg := sprintf("Dormant admin account '%s' inactive for %d days", [input.account.username, input.account.days_since_activity])
}
```

**Step 4: Implement PolicyEngine**

Create `src/accessaudit/analysis/policy_engine.py`:
```python
"""OPA/Rego policy engine for IAM compliance checks."""

import asyncio
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from accessaudit.models import (
    Account,
    Finding,
    FindingCategory,
    FindingSeverity,
    Permission,
    Policy,
)


class PolicyEngine:
    """Evaluates IAM data against OPA/Rego policies."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.rules_dir = self.config.get("rules_dir", "rules")
        self.rule_files = self._discover_rules()

    def _discover_rules(self) -> list[str]:
        """Find all .rego files in rules directory."""
        rules_path = Path(self.rules_dir)
        if not rules_path.exists():
            return []
        return [str(f) for f in rules_path.glob("*.rego")]

    def _opa_available(self) -> bool:
        """Check if OPA binary is available on PATH."""
        return shutil.which("opa") is not None

    async def evaluate_account(
        self, account: Account, permissions: list[Permission]
    ) -> list[Finding]:
        """Evaluate all Rego rules against an account and its permissions."""
        if not self._opa_available():
            return []

        if not self.rule_files:
            return []

        input_doc = self._build_input(account, permissions)

        findings = []
        for rule_file in self.rule_files:
            violations = await self._evaluate_rule_file(rule_file, input_doc)
            for violation_msg in violations:
                finding = self._create_finding(account, rule_file, violation_msg)
                findings.append(finding)

        return findings

    async def evaluate_all(
        self,
        accounts: list[Account],
        all_permissions: dict[str, list[Permission]],
        policies: list[Policy] | None = None,
    ) -> list[Finding]:
        """Evaluate rules against all accounts."""
        findings = []

        for account in accounts:
            permissions = all_permissions.get(account.id, [])
            account_findings = await self.evaluate_account(account, permissions)
            findings.extend(account_findings)

        return findings

    def _build_input(self, account: Account, permissions: list[Permission]) -> dict:
        """Build the JSON input document for OPA evaluation."""
        return {
            "account": {
                "id": account.id,
                "provider": account.provider,
                "username": account.username,
                "email": account.email,
                "mfa_enabled": account.mfa_enabled,
                "has_admin_role": account.has_admin_role,
                "groups": account.groups,
                "status": account.status.value,
                "days_since_activity": account.days_since_activity() or 0,
            },
            "permissions": [
                {
                    "id": p.id,
                    "resource_type": p.resource_type,
                    "resource_arn": p.resource_arn,
                    "actions": p.actions,
                    "effect": p.effect,
                    "scope": p.scope.value,
                    "source_policy": p.source_policy,
                }
                for p in permissions
            ],
        }

    async def _evaluate_rule_file(self, rule_file: str, input_doc: dict) -> list[str]:
        """Evaluate a single Rego rule file against input."""
        result = await self._run_opa(rule_file, input_doc)
        if not result:
            return []

        violations = []
        try:
            expressions = result.get("result", [{}])
            for expr in expressions:
                values = expr.get("expressions", [{}])
                for val in values:
                    messages = val.get("value", [])
                    if isinstance(messages, list):
                        violations.extend(messages)
                    elif isinstance(messages, str):
                        violations.append(messages)
        except (KeyError, TypeError, IndexError):
            pass

        return violations

    async def _run_opa(self, rule_file: str, input_doc: dict) -> dict | None:
        """Run OPA eval subprocess."""
        input_json = json.dumps({"input": input_doc})

        try:
            proc = await asyncio.create_subprocess_exec(
                "opa", "eval",
                "--data", rule_file,
                "--input", "/dev/stdin",
                "--format", "json",
                "data.accessaudit.rules.deny",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(input=input_json.encode())

            if proc.returncode == 0:
                return json.loads(stdout.decode())
            else:
                print(f"OPA error: {stderr.decode()}")
                return None
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"OPA execution error: {e}")
            return None

    def _create_finding(self, account: Account, rule_file: str, violation_msg: str) -> Finding:
        """Create a Finding from a Rego policy violation."""
        finding_id = hashlib.md5(
            f"rego:{account.id}:{rule_file}:{violation_msg}".encode()
        ).hexdigest()[:16]

        rule_name = Path(rule_file).stem

        return Finding(
            id=f"finding-{finding_id}",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.POLICY_VIOLATION,
            account_id=account.id,
            title=f"Policy violation: {violation_msg}",
            description=(
                f"Account {account.username} violates policy defined in "
                f"'{rule_name}.rego': {violation_msg}"
            ),
            remediation="Review and remediate the policy violation according to organizational guidelines.",
            metadata={
                "rule_file": rule_file,
                "rule_name": rule_name,
                "violation_message": violation_msg,
                "engine": "opa",
            },
        )
```

**Step 5: Run tests**

Run: `python -m pytest tests/unit/test_policy_engine.py -v`
Expected: All pass

**Step 6: Commit**

```
git add src/accessaudit/analysis/policy_engine.py tests/unit/test_policy_engine.py rules/base.rego
git commit -m "feat: add OPA/Rego policy engine with base rules"
```

---

## Task 11: Compliance Report Mappings

**Files:**
- Create: `src/accessaudit/core/compliance/__init__.py`
- Create: `src/accessaudit/core/compliance/mappings.py`
- Create: `src/accessaudit/core/compliance/soc2.py`
- Create: `src/accessaudit/core/compliance/iso27001.py`
- Create: `tests/unit/test_compliance.py`

This task creates the compliance framework mapping layer. See the design doc for full SOC 2 and ISO 27001 control mappings.

**Step 1-5: Standard TDD cycle** (tests, implement modules, verify, commit)

Commit message: `feat: add SOC 2 and ISO 27001 compliance mappings`

---

## Task 12: HTML + PDF Report Generation

**Files:**
- Create: `src/accessaudit/core/templates/reports/executive_report.html`
- Create: `src/accessaudit/core/templates/reports/soc2_report.html`
- Create: `src/accessaudit/core/templates/reports/iso27001_report.html`
- Modify: `src/accessaudit/core/reporter.py`
- Create: `tests/unit/test_reporter_html.py`

Extends Reporter with `generate_html_report()` and `generate_pdf_report()` methods. Templates use Jinja2 + Tailwind CSS CDN.

**Step 1-6: Standard TDD cycle** (tests, templates, Reporter methods, verify, commit)

Commit message: `feat: add HTML and PDF compliance report generation`

---

## Task 13: FastAPI Application

**Files:**
- Create: `src/accessaudit/api/__init__.py`
- Create: `src/accessaudit/api/app.py`
- Create: `src/accessaudit/api/routes/__init__.py`
- Create: `src/accessaudit/api/routes/scans.py`
- Create: `src/accessaudit/api/routes/findings.py`
- Create: `src/accessaudit/api/routes/reports.py`
- Create: `src/accessaudit/api/routes/rules.py`
- Create: `src/accessaudit/api/routes/health.py`
- Create: `tests/unit/test_api.py`

REST API wrapping existing Scanner/Analyzer/Reporter. Scans run in background via asyncio.create_task(). In-memory result store (no DB yet).

**Step 1-5: Standard TDD cycle** (tests, app factory, route modules, verify, commit)

Commit message: `feat: add FastAPI REST API with scan, findings, reports, and rules endpoints`

---

## Task 14: HTMX Dashboard

**Files:**
- Create: `src/accessaudit/api/templates/base.html`
- Create: `src/accessaudit/api/templates/dashboard.html`
- Create: `src/accessaudit/api/templates/scans.html`
- Create: `src/accessaudit/api/templates/findings.html`
- Create: `src/accessaudit/api/templates/reports.html`
- Create: `src/accessaudit/api/templates/rules.html`
- Create: `src/accessaudit/api/routes/dashboard.py`
- Modify: `src/accessaudit/api/app.py`
- Create: `tests/unit/test_dashboard.py`

Server-rendered HTML pages with HTMX for interactivity and Tailwind CSS via CDN.

**Step 1-7: Standard TDD cycle** (tests, templates, dashboard routes, register in app, verify, commit)

Commit message: `feat: add HTMX + Jinja2 dashboard with Tailwind CSS`

---

## Task 15: Update CLI with New Commands

**Files:**
- Modify: `src/accessaudit/cli/main.py`

Add `scan azure`, `scan gcp` commands. Add `report generate --format html/pdf --template soc2/iso27001/executive`. Add `serve` command for API server.

Commit message: `feat: add Azure/GCP scan commands and serve command to CLI`

---

## Task 16: Create Compliance Rego Rule Packs

**Files:**
- Create: `rules/soc2.rego`
- Create: `rules/iso27001.rego`
- Create: `rules/cis_aws.rego`

Commit message: `feat: add SOC 2, ISO 27001, and CIS AWS compliance rule packs`

---

## Task 17: Integration Tests

**Files:**
- Create: `tests/integration/test_multi_provider_scan.py`
- Create: `tests/integration/test_api_workflow.py`

Test full scan->analyze->report pipeline with mocked providers. Test API workflow: trigger scan -> poll -> fetch findings -> generate report.

Commit message: `test: add integration tests for multi-provider and API workflows`

---

## Task 18: Update Documentation and Configuration

**Files:**
- Modify: `README.md`
- Modify: `examples/config.example.yaml`
- Modify: `TASKS.md`
- Modify: `docker/Dockerfile` (add OPA binary)

Commit message: `docs: update documentation for Phase 2 features`

---

## Summary

| Task | Component | Tests Added |
|------|-----------|-------------|
| 1 | Dependencies | 0 (verify existing) |
| 2 | BaseConnector.list_roles() | 1 |
| 3 | FindingCategory.ANOMALY | 1 |
| 4 | Azure AD Connector | 6 |
| 5 | GCP IAM Connector | 6 |
| 6 | Scanner registration | 2 |
| 7 | ML Feature Extraction | 4 |
| 8 | ML Anomaly Detector | 4 |
| 9 | Analyzer integration | 1 |
| 10 | OPA Policy Engine | 4 |
| 11 | Compliance Mappings | 5 |
| 12 | HTML/PDF Reports | 4 |
| 13 | FastAPI API | 5 |
| 14 | HTMX Dashboard | 5 |
| 15 | CLI updates | 0 (manual) |
| 16 | Rego rule packs | 0 (config) |
| 17 | Integration tests | 2+ |
| 18 | Documentation | 0 |
| **Total** | | **~50 new tests** |
