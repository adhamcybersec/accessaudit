"""Policy data model."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyEffect(StrEnum):
    """Policy effect enumeration."""

    ALLOW = "Allow"
    DENY = "Deny"


class Policy(BaseModel):
    """Represents an IAM policy document."""

    id: str = Field(..., description="Unique policy identifier")
    name: str = Field(..., description="Policy name")
    arn: str = Field(..., description="Policy ARN or unique identifier")
    provider: str = Field(..., description="IAM provider (aws, azure, gcp)")
    policy_type: str = Field(..., description="Policy type (managed, inline, custom)")
    document: dict[str, Any] = Field(..., description="Raw policy document/JSON")
    attached_to: list[str] = Field(
        default_factory=list, description="List of account IDs this policy is attached to"
    )
    created_at: str | None = Field(None, description="Policy creation timestamp")
    updated_at: str | None = Field(None, description="Policy last update timestamp")
    is_aws_managed: bool = Field(default=False, description="Whether this is an AWS-managed policy")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "id": "policy-123",
                "name": "AdministratorAccess",
                "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "provider": "aws",
                "policy_type": "managed",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
                "attached_to": ["arn:aws:iam::123456789012:user/admin"],
                "is_aws_managed": True,
                "metadata": {},
            }
        }

    def has_wildcard_actions(self) -> bool:
        """Check if policy contains wildcard actions.

        Returns:
            True if policy has wildcard actions, False otherwise
        """
        if "Statement" not in self.document:
            return False

        for statement in self.document["Statement"]:
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if "*" in actions:
                return True

            # Check for service-level wildcards (e.g., "s3:*")
            if any("*" in action for action in actions):
                return True

        return False

    def has_wildcard_resources(self) -> bool:
        """Check if policy contains wildcard resources.

        Returns:
            True if policy has wildcard resources, False otherwise
        """
        if "Statement" not in self.document:
            return False

        for statement in self.document["Statement"]:
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in resources or any("*" in resource for resource in resources):
                return True

        return False

    def is_overly_permissive(self) -> bool:
        """Check if policy is overly permissive (wildcard actions + resources).

        Returns:
            True if policy grants wildcard access, False otherwise
        """
        return self.has_wildcard_actions() and self.has_wildcard_resources()

    def extract_permissions(self, account_id: str) -> list[dict[str, Any]]:
        """Extract individual permissions from policy document.

        Args:
            account_id: Account ID to associate permissions with

        Returns:
            List of permission dictionaries
        """
        permissions = []

        if "Statement" not in self.document:
            return permissions

        for idx, statement in enumerate(self.document["Statement"]):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            effect = statement.get("Effect", "Allow")

            for resource in resources or ["*"]:
                permission = {
                    "id": f"{self.id}-stmt-{idx}-{hash(resource)}",
                    "account_id": account_id,
                    "resource_type": resource.split(":")[2] if ":" in resource else "unknown",
                    "resource_arn": resource,
                    "actions": actions,
                    "effect": effect,
                    "source_policy": self.arn,
                    "conditions": statement.get("Condition", {}),
                }
                permissions.append(permission)

        return permissions
