"""Permission data model."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PermissionScope(StrEnum):
    """Permission scope/level enumeration."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    CUSTOM = "custom"


class Permission(BaseModel):
    """Represents a permission granted to an account."""

    id: str = Field(..., description="Unique permission identifier")
    account_id: str = Field(..., description="Account this permission belongs to")
    resource_type: str = Field(..., description="Type of resource (s3, ec2, user, role, etc.)")
    resource_arn: str = Field(..., description="Resource ARN or identifier")
    actions: list[str] = Field(default_factory=list, description="Allowed actions")
    effect: str = Field(default="Allow", description="Permission effect (Allow/Deny)")
    scope: PermissionScope = Field(default=PermissionScope.CUSTOM, description="Permission scope")
    conditions: dict[str, Any] = Field(
        default_factory=dict, description="Conditional policy constraints"
    )
    source_policy: str = Field(..., description="Policy ARN/name that grants this permission")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "id": "perm-123456",
                "account_id": "arn:aws:iam::123456789012:user/john.doe",
                "resource_type": "s3",
                "resource_arn": "arn:aws:s3:::my-bucket/*",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "effect": "Allow",
                "scope": "read",
                "conditions": {},
                "source_policy": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                "metadata": {},
            }
        }

    def is_wildcard(self) -> bool:
        """Check if permission contains wildcard actions.

        Returns:
            True if any action is a wildcard (*), False otherwise
        """
        return any("*" in action for action in self.actions)

    def is_full_wildcard(self) -> bool:
        """Check if permission grants full wildcard access.

        Returns:
            True if actions is ["*"] AND resource is "*", False otherwise
        """
        return "*" in self.actions and self.resource_arn == "*"

    def calculate_scope(self) -> PermissionScope:
        """Calculate permission scope based on actions.

        Returns:
            Calculated permission scope
        """
        # Full wildcard = admin
        if self.is_full_wildcard():
            return PermissionScope.ADMIN

        # Common admin actions
        admin_keywords = ["admin", "delete", "create", "put", "write", "*"]
        if any(keyword in action.lower() for action in self.actions for keyword in admin_keywords):
            if "*" in self.actions or any("*" in action for action in self.actions):
                return PermissionScope.ADMIN
            return PermissionScope.WRITE

        # Read-only actions
        read_keywords = ["get", "list", "describe", "read"]
        if all(
            any(keyword in action.lower() for keyword in read_keywords) for action in self.actions
        ):
            return PermissionScope.READ

        return PermissionScope.CUSTOM
