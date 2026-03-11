"""Account data model."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AccountStatus(StrEnum):
    """Account status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    PENDING = "pending"


class Account(BaseModel):
    """Represents an IAM account/user across different providers."""

    id: str = Field(..., description="Unique account identifier")
    provider: str = Field(..., description="IAM provider (aws, azure, gcp, sailpoint)")
    username: str = Field(..., description="Account username/login")
    email: str | None = Field(None, description="Account email address")
    created_at: datetime | None = Field(None, description="Account creation timestamp")
    last_login: datetime | None = Field(None, description="Last successful login timestamp")
    last_activity: datetime | None = Field(None, description="Last activity/access timestamp")
    status: AccountStatus = Field(default=AccountStatus.ACTIVE, description="Account status")
    mfa_enabled: bool = Field(default=False, description="Whether MFA/2FA is enabled")
    has_admin_role: bool = Field(default=False, description="Whether account has admin privileges")
    groups: list[str] = Field(default_factory=list, description="Groups this account belongs to")
    tags: dict[str, str] = Field(default_factory=dict, description="Provider-specific tags")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional provider-specific metadata"
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "id": "arn:aws:iam::123456789012:user/john.doe",
                "provider": "aws",
                "username": "john.doe",
                "email": "john.doe@example.com",
                "created_at": "2023-01-15T10:30:00Z",
                "last_login": "2024-03-10T14:22:00Z",
                "last_activity": "2024-03-11T09:15:00Z",
                "status": "active",
                "mfa_enabled": True,
                "has_admin_role": False,
                "groups": ["developers", "readonly-users"],
                "tags": {"Department": "Engineering", "Team": "Backend"},
                "metadata": {"arn": "arn:aws:iam::123456789012:user/john.doe"},
            }
        }

    def is_dormant(self, threshold_days: int = 90) -> bool:
        """Check if account is dormant (inactive beyond threshold).

        Args:
            threshold_days: Number of days of inactivity to consider dormant

        Returns:
            True if account is dormant, False otherwise
        """
        if not self.last_activity and not self.last_login:
            # No activity/login data - can't determine dormancy
            return False

        last_used = self.last_activity or self.last_login
        if not last_used:
            return False

        days_since_activity = (datetime.now(last_used.tzinfo) - last_used).days
        return days_since_activity > threshold_days

    def days_since_activity(self) -> int | None:
        """Calculate days since last activity.

        Returns:
            Number of days since last activity, or None if no activity data
        """
        last_used = self.last_activity or self.last_login
        if not last_used:
            return None

        return (datetime.now(last_used.tzinfo) - last_used).days
