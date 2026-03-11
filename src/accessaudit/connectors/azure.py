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
