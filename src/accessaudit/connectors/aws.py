"""AWS IAM connector."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from accessaudit.connectors.base import BaseConnector
from accessaudit.models import Account, AccountStatus, Permission, Policy


class AWSConnector(BaseConnector):
    """AWS IAM connector using boto3."""

    def __init__(self, config: dict[str, Any]):
        """Initialize AWS connector.

        Args:
            config: AWS configuration (access_key_id, secret_access_key, region, etc.)
        """
        super().__init__(config)
        self.iam_client = None
        self.region = config.get("region", "us-east-1")

    async def connect(self) -> None:
        """Establish connection to AWS IAM."""
        try:
            # Create IAM client
            aws_config = {}
            if "access_key_id" in self.config:
                aws_config["aws_access_key_id"] = self.config["access_key_id"]
            if "secret_access_key" in self.config:
                aws_config["aws_secret_access_key"] = self.config["secret_access_key"]
            if "region" in self.config:
                aws_config["region_name"] = self.config["region"]

            self.iam_client = boto3.client("iam", **aws_config)

            # Test connection
            self.iam_client.get_user()
        except NoCredentialsError as e:
            raise ConnectionError(f"AWS credentials not found: {e}") from e
        except ClientError as e:
            # If GetUser fails, try listing users (works with broader permissions)
            try:
                self.iam_client.list_users(MaxItems=1)
            except ClientError as list_err:
                raise ConnectionError(f"AWS connection failed: {list_err}") from list_err
        except Exception as e:
            raise ConnectionError(f"Failed to connect to AWS: {e}") from e

    async def disconnect(self) -> None:
        """Close AWS connection (boto3 handles cleanup automatically)."""
        self.iam_client = None

    async def test_connection(self) -> bool:
        """Test AWS IAM connection.

        Returns:
            True if connection successful
        """
        try:
            await self.connect()
            return True
        except Exception:
            return False

    async def list_accounts(self) -> list[Account]:
        """List all IAM users.

        Returns:
            List of Account objects
        """
        if not self.iam_client:
            await self.connect()

        accounts = []

        try:
            # Paginate through IAM users
            paginator = self.iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    account = await self._user_to_account(user)
                    accounts.append(account)

        except ClientError as e:
            raise RuntimeError(f"Failed to list AWS IAM users: {e}") from e

        return accounts

    async def get_account(self, account_id: str) -> Account | None:
        """Get specific IAM user.

        Args:
            account_id: User ARN or username

        Returns:
            Account object or None if not found
        """
        if not self.iam_client:
            await self.connect()

        try:
            # Extract username from ARN if needed
            username = account_id.split("/")[-1] if "/" in account_id else account_id

            user = self.iam_client.get_user(UserName=username)["User"]
            return await self._user_to_account(user)

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return None
            raise RuntimeError(f"Failed to get AWS user {account_id}: {e}") from e

    async def list_policies(self) -> list[Policy]:
        """List all IAM policies (AWS-managed + customer-managed).

        Returns:
            List of Policy objects
        """
        if not self.iam_client:
            await self.connect()

        policies = []

        try:
            # List customer-managed policies
            paginator = self.iam_client.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy_summary in page["Policies"]:
                    policy = await self._fetch_policy_details(policy_summary)
                    if policy:
                        policies.append(policy)

            # Optionally list AWS-managed policies (can be a lot!)
            # for page in paginator.paginate(Scope="AWS"):
            #     for policy_summary in page["Policies"]:
            #         policy = await self._fetch_policy_details(policy_summary)
            #         if policy:
            #             policies.append(policy)

        except ClientError as e:
            raise RuntimeError(f"Failed to list AWS policies: {e}") from e

        return policies

    async def get_account_permissions(self, account_id: str) -> list[Permission]:
        """Get all permissions for an IAM user.

        Args:
            account_id: User ARN or username

        Returns:
            List of Permission objects
        """
        if not self.iam_client:
            await self.connect()

        permissions = []

        try:
            username = account_id.split("/")[-1] if "/" in account_id else account_id

            # Get attached managed policies
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)[
                "AttachedPolicies"
            ]
            for policy_summary in attached_policies:
                policy_arn = policy_summary["PolicyArn"]
                policy_perms = await self._extract_policy_permissions(policy_arn, account_id)
                permissions.extend(policy_perms)

            # Get inline policies
            inline_policy_names = self.iam_client.list_user_policies(UserName=username)[
                "PolicyNames"
            ]
            for policy_name in inline_policy_names:
                policy_doc = self.iam_client.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )["PolicyDocument"]
                inline_perms = await self._parse_policy_document(
                    policy_doc, account_id, f"inline:{policy_name}"
                )
                permissions.extend(inline_perms)

            # Get group policies
            groups = self.iam_client.list_groups_for_user(UserName=username)["Groups"]
            for group in groups:
                group_name = group["GroupName"]

                # Group attached policies
                group_attached = self.iam_client.list_attached_group_policies(
                    GroupName=group_name
                )["AttachedPolicies"]
                for policy_summary in group_attached:
                    policy_arn = policy_summary["PolicyArn"]
                    policy_perms = await self._extract_policy_permissions(policy_arn, account_id)
                    permissions.extend(policy_perms)

                # Group inline policies
                group_inline = self.iam_client.list_group_policies(GroupName=group_name)[
                    "PolicyNames"
                ]
                for policy_name in group_inline:
                    policy_doc = self.iam_client.get_group_policy(
                        GroupName=group_name, PolicyName=policy_name
                    )["PolicyDocument"]
                    group_inline_perms = await self._parse_policy_document(
                        policy_doc, account_id, f"group-inline:{group_name}/{policy_name}"
                    )
                    permissions.extend(group_inline_perms)

        except ClientError as e:
            raise RuntimeError(f"Failed to get permissions for {account_id}: {e}") from e

        return permissions

    # Private helper methods

    async def _user_to_account(self, user: dict[str, Any]) -> Account:
        """Convert AWS IAM User to Account model.

        Args:
            user: AWS IAM User dict from boto3

        Returns:
            Account object
        """
        username = user["UserName"]
        user_arn = user["Arn"]

        # Get last access info
        try:
            access_key_metadata = self.iam_client.list_access_keys(UserName=username)[
                "AccessKeyMetadata"
            ]
            last_used_info = None
            for key in access_key_metadata:
                key_id = key["AccessKeyId"]
                last_used = self.iam_client.get_access_key_last_used(AccessKeyId=key_id).get(
                    "AccessKeyLastUsed"
                )
                if last_used and "LastUsedDate" in last_used:
                    last_used_info = last_used["LastUsedDate"]
                    break
        except Exception:
            last_used_info = None

        # Get MFA devices
        try:
            mfa_devices = self.iam_client.list_mfa_devices(UserName=username)["MFADevices"]
            mfa_enabled = len(mfa_devices) > 0
        except Exception:
            mfa_enabled = False

        # Get groups
        try:
            groups = self.iam_client.list_groups_for_user(UserName=username)["Groups"]
            group_names = [g["GroupName"] for g in groups]
        except Exception:
            group_names = []

        # Get user tags
        try:
            tags_response = self.iam_client.list_user_tags(UserName=username)
            tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
        except Exception:
            tags = {}

        # Check if user has admin-level permissions (simplified check)
        has_admin = await self._check_admin_permissions(username)

        # Convert timezone-aware datetime to naive (or ensure consistency)
        created_at = user.get("CreateDate")
        if created_at and created_at.tzinfo is not None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        last_activity = last_used_info
        if last_activity and last_activity.tzinfo is not None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        return Account(
            id=user_arn,
            provider="aws",
            username=username,
            email=tags.get("Email"),
            created_at=created_at,
            last_login=None,  # AWS doesn't track console login via IAM API
            last_activity=last_activity,
            status=AccountStatus.ACTIVE,  # AWS doesn't have inactive status
            mfa_enabled=mfa_enabled,
            has_admin_role=has_admin,
            groups=group_names,
            tags=tags,
            metadata={"arn": user_arn, "user_id": user.get("UserId")},
        )

    async def _check_admin_permissions(self, username: str) -> bool:
        """Check if user has admin-level permissions.

        Args:
            username: IAM username

        Returns:
            True if user has admin permissions
        """
        try:
            # Check for AdministratorAccess policy
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)[
                "AttachedPolicies"
            ]
            for policy in attached_policies:
                if "AdministratorAccess" in policy["PolicyName"] or "Admin" in policy[
                    "PolicyName"
                ]:
                    return True

            # Check groups for admin policies
            groups = self.iam_client.list_groups_for_user(UserName=username)["Groups"]
            for group in groups:
                group_policies = self.iam_client.list_attached_group_policies(
                    GroupName=group["GroupName"]
                )["AttachedPolicies"]
                for policy in group_policies:
                    if "AdministratorAccess" in policy["PolicyName"] or "Admin" in policy[
                        "PolicyName"
                    ]:
                        return True

        except Exception:
            pass

        return False

    async def _fetch_policy_details(self, policy_summary: dict[str, Any]) -> Policy | None:
        """Fetch full policy details including document.

        Args:
            policy_summary: Policy summary from list_policies

        Returns:
            Policy object or None if fetch fails
        """
        try:
            policy_arn = policy_summary["Arn"]
            policy_name = policy_summary["PolicyName"]

            # Get default policy version
            default_version_id = policy_summary.get("DefaultVersionId")
            if not default_version_id:
                # Fetch policy to get default version
                policy = self.iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
                default_version_id = policy["DefaultVersionId"]

            # Get policy document
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=default_version_id
            )["PolicyVersion"]
            policy_document = policy_version["Document"]

            # Get policy attachments
            attached_entities = []
            try:
                entities = self.iam_client.list_entities_for_policy(PolicyArn=policy_arn)
                for user in entities.get("PolicyUsers", []):
                    attached_entities.append(user["UserArn"])
                for group in entities.get("PolicyGroups", []):
                    attached_entities.append(group["GroupArn"])
                for role in entities.get("PolicyRoles", []):
                    attached_entities.append(role["RoleArn"])
            except Exception:
                pass

            is_aws_managed = policy_arn.startswith("arn:aws:iam::aws:policy/")

            return Policy(
                id=policy_arn,
                name=policy_name,
                arn=policy_arn,
                provider="aws",
                policy_type="managed" if is_aws_managed else "customer-managed",
                document=policy_document,
                attached_to=attached_entities,
                created_at=policy_summary.get("CreateDate", "").isoformat()
                if policy_summary.get("CreateDate")
                else None,
                updated_at=policy_summary.get("UpdateDate", "").isoformat()
                if policy_summary.get("UpdateDate")
                else None,
                is_aws_managed=is_aws_managed,
                metadata={"policy_id": policy_summary.get("PolicyId")},
            )

        except Exception as e:
            # Log error but don't fail entire operation
            print(f"Failed to fetch policy {policy_summary.get('PolicyName')}: {e}")
            return None

    async def _extract_policy_permissions(
        self, policy_arn: str, account_id: str
    ) -> list[Permission]:
        """Extract permissions from a policy ARN.

        Args:
            policy_arn: Policy ARN
            account_id: Account ID these permissions belong to

        Returns:
            List of Permission objects
        """
        try:
            # Get policy default version
            policy = self.iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
            default_version_id = policy["DefaultVersionId"]

            # Get policy document
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=default_version_id
            )["PolicyVersion"]
            policy_document = policy_version["Document"]

            return await self._parse_policy_document(policy_document, account_id, policy_arn)

        except Exception as e:
            print(f"Failed to extract permissions from {policy_arn}: {e}")
            return []

    async def _parse_policy_document(
        self, policy_doc: dict[str, Any], account_id: str, source_policy: str
    ) -> list[Permission]:
        """Parse AWS policy document into Permission objects.

        Args:
            policy_doc: AWS policy document
            account_id: Account ID
            source_policy: Policy ARN or identifier

        Returns:
            List of Permission objects
        """
        permissions = []

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, statement in enumerate(statements):
            effect = statement.get("Effect", "Allow")

            # Parse actions
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Parse resources
            resources = statement.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]

            # Create permission for each resource
            for resource in resources:
                # Extract resource type from ARN
                resource_type = "unknown"
                if resource != "*" and ":" in resource:
                    parts = resource.split(":")
                    if len(parts) >= 3:
                        resource_type = parts[2]

                # Generate unique permission ID
                perm_id = hashlib.md5(
                    f"{account_id}:{source_policy}:{idx}:{resource}".encode()
                ).hexdigest()[:16]

                permission = Permission(
                    id=f"perm-{perm_id}",
                    account_id=account_id,
                    resource_type=resource_type,
                    resource_arn=resource,
                    actions=actions,
                    effect=effect,
                    source_policy=source_policy,
                    conditions=statement.get("Condition", {}),
                )

                # Auto-calculate scope
                permission.scope = permission.calculate_scope()

                permissions.append(permission)

        return permissions
