"""SailPoint IdentityIQ connector via SCIM 2.0 API."""

import hashlib
from base64 import b64encode
from datetime import datetime
from typing import Any

import httpx

from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, AccountStatus, Permission, PermissionScope, Policy


class SailPointConnector(BaseConnector):
    """SailPoint IIQ connector using SCIM 2.0 API.

    Maps:
      - SCIM Users → Account
      - Entitlements → Permission
      - Roles → Policy

    Auth: HTTP Basic or OAuth2 Bearer token.
    """

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "").rstrip("/")
        self.username = config.get("username")
        self.password = config.get("password")
        self.token = config.get("token")
        self.client: httpx.AsyncClient | None = None
        self.provider_name = "sailpoint"

    def _build_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        headers: dict[str, str] = {
            "Accept": "application/scim+json",
            "Content-Type": "application/scim+json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            creds = b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
        return headers

    async def connect(self) -> None:
        """Establish connection to SailPoint IIQ."""
        if not self.base_url:
            raise ConnectionError("SailPoint base_url is required")

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._build_headers(),
            timeout=30.0,
        )

        # Test connection
        if not await self.test_connection():
            raise ConnectionError("SailPoint connection test failed")

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def test_connection(self) -> bool:
        """Test connection by fetching ServiceProviderConfig."""
        if not self.client:
            return False
        try:
            resp = await self.client.get("/scim/v2/ServiceProviderConfig")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def list_accounts(self) -> list[Account]:
        """List all user accounts from SailPoint IIQ via SCIM Users endpoint."""
        if not self.client:
            raise RuntimeError("Not connected")

        accounts: list[Account] = []
        start_index = 1
        count = 100

        while True:
            resp = await self.client.get(
                "/scim/v2/Users",
                params={"startIndex": start_index, "count": count},
            )
            resp.raise_for_status()
            data = resp.json()

            for resource in data.get("Resources", []):
                accounts.append(self._scim_user_to_account(resource))

            total = data.get("totalResults", 0)
            start_index += count
            if start_index > total:
                break

        return accounts

    async def get_account(self, account_id: str) -> Account | None:
        """Get specific account by ID."""
        if not self.client:
            raise RuntimeError("Not connected")
        try:
            resp = await self.client.get(f"/scim/v2/Users/{account_id}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return self._scim_user_to_account(resp.json())
        except httpx.HTTPError:
            return None

    async def list_policies(self) -> list[Policy]:
        """List all roles from SailPoint IIQ as policies."""
        if not self.client:
            raise RuntimeError("Not connected")

        policies: list[Policy] = []
        start_index = 1
        count = 100

        while True:
            try:
                resp = await self.client.get(
                    "/scim/v2/Roles",
                    params={"startIndex": start_index, "count": count},
                )
                if resp.status_code == 404:
                    break
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError:
                break

            for resource in data.get("Resources", []):
                policies.append(self._scim_role_to_policy(resource))

            total = data.get("totalResults", 0)
            start_index += count
            if start_index > total:
                break

        return policies

    async def get_account_permissions(self, account_id: str) -> list[Permission]:
        """Get permissions for a user based on their entitlements."""
        if not self.client:
            raise RuntimeError("Not connected")

        permissions: list[Permission] = []

        try:
            resp = await self.client.get(
                "/scim/v2/Entitlements",
                params={"filter": f'owner eq "{account_id}"'},
            )
            if resp.status_code == 404:
                return permissions
            resp.raise_for_status()
            data = resp.json()

            for resource in data.get("Resources", []):
                permissions.append(self._scim_entitlement_to_permission(account_id, resource))

        except httpx.HTTPError:
            pass

        # Also check user's group memberships for role-based permissions
        try:
            resp = await self.client.get(f"/scim/v2/Users/{account_id}")
            if resp.status_code == 200:
                user_data = resp.json()
                for group in user_data.get("groups", []):
                    perm_id = hashlib.md5(
                        f"{account_id}:{group.get('value', '')}".encode()
                    ).hexdigest()[:16]
                    permissions.append(
                        Permission(
                            id=perm_id,
                            account_id=account_id,
                            resource_type="role",
                            resource_arn=f"sailpoint:role:{group.get('value', '')}",
                            actions=["assume_role"],
                            effect="Allow",
                            scope=PermissionScope.READ,
                            conditions={},
                            source_policy=group.get("display", "Unknown Role"),
                            metadata={"group_ref": group.get("$ref", "")},
                        )
                    )
        except httpx.HTTPError:
            pass

        return permissions

    def _scim_user_to_account(self, resource: dict[str, Any]) -> Account:
        """Convert SCIM User resource to Account model."""
        user_id = resource.get("id", "")
        username = resource.get("userName", "")
        active = resource.get("active", True)

        # Extract email from emails array
        email = None
        for em in resource.get("emails", []):
            if em.get("primary", False) or email is None:
                email = em.get("value")

        # Parse name
        name_obj = resource.get("name", {})
        display_name = resource.get("displayName", "")
        if not display_name and name_obj:
            display_name = f"{name_obj.get('givenName', '')} {name_obj.get('familyName', '')}".strip()

        # Extract metadata
        meta = resource.get("meta", {})
        created_str = meta.get("created")
        last_modified_str = meta.get("lastModified")

        created_at = datetime.fromisoformat(created_str) if created_str else None
        last_modified = datetime.fromisoformat(last_modified_str) if last_modified_str else None

        # Extract groups for admin detection
        groups = [g.get("display", "") for g in resource.get("groups", [])]
        has_admin = any(
            "admin" in g.lower() or "superuser" in g.lower() for g in groups
        )

        return Account(
            id=user_id,
            provider="sailpoint",
            username=username,
            email=email,
            created_at=created_at,
            last_login=None,
            last_activity=last_modified,
            status=AccountStatus.ACTIVE if active else AccountStatus.DISABLED,
            mfa_enabled=resource.get("urn:ietf:params:scim:schemas:sailpoint:1.0", {}).get(
                "mfaEnabled", False
            ),
            has_admin_role=has_admin,
            groups=groups,
            tags={},
            metadata={
                "display_name": display_name,
                "scim_id": user_id,
                "resource_type": meta.get("resourceType", "User"),
            },
        )

    def _scim_role_to_policy(self, resource: dict[str, Any]) -> Policy:
        """Convert SCIM Role resource to Policy model."""
        role_id = resource.get("id", "")
        display_name = resource.get("displayName", resource.get("name", "Unknown"))
        meta = resource.get("meta", {})

        # Extract members
        members = [m.get("value", "") for m in resource.get("members", [])]

        return Policy(
            id=role_id,
            name=display_name,
            arn=f"sailpoint:role:{role_id}",
            provider="sailpoint",
            policy_type="role",
            document=resource,
            attached_to=members,
            created_at=meta.get("created"),
            updated_at=meta.get("lastModified"),
            is_aws_managed=False,
            metadata={
                "scim_id": role_id,
                "resource_type": meta.get("resourceType", "Role"),
            },
        )

    def _scim_entitlement_to_permission(
        self, account_id: str, resource: dict[str, Any]
    ) -> Permission:
        """Convert SCIM Entitlement resource to Permission model."""
        ent_id = resource.get("id", "")
        name = resource.get("displayName", resource.get("name", "Unknown"))
        application = resource.get("application", "unknown")

        # Determine scope from entitlement type
        ent_type = resource.get("type", "").lower()
        if "admin" in ent_type or "admin" in name.lower():
            scope = PermissionScope.ADMIN
        elif "write" in ent_type or "modify" in name.lower():
            scope = PermissionScope.WRITE
        elif "read" in ent_type or "view" in name.lower():
            scope = PermissionScope.READ
        else:
            scope = PermissionScope.CUSTOM

        return Permission(
            id=ent_id,
            account_id=account_id,
            resource_type="entitlement",
            resource_arn=f"sailpoint:entitlement:{application}:{ent_id}",
            actions=[name],
            effect="Allow",
            scope=scope,
            conditions={},
            source_policy=application,
            metadata={
                "application": application,
                "entitlement_type": ent_type,
            },
        )
