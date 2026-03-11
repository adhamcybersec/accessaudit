"""GCP IAM connector."""

import hashlib
from typing import Any

from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy

try:
    from google.cloud import resourcemanager_v3
    from google.oauth2 import service_account

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
