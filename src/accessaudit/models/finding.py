"""Finding data model."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Finding category types."""

    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    DORMANT_ACCOUNT = "dormant_account"
    POLICY_VIOLATION = "policy_violation"
    MISSING_MFA = "missing_mfa"
    WEAK_PASSWORD = "weak_password"
    UNUSED_CREDENTIALS = "unused_credentials"
    OVERPRIVILEGED_ROLE = "overprivileged_role"
    ANOMALY = "anomaly"
    OTHER = "other"


class Finding(BaseModel):
    """Represents a security finding/issue discovered during audit."""

    id: str = Field(..., description="Unique finding identifier")
    severity: FindingSeverity = Field(..., description="Finding severity level")
    category: FindingCategory = Field(..., description="Finding category")
    account_id: str = Field(..., description="Account ID this finding relates to")
    title: str = Field(..., description="Short finding title")
    description: str = Field(..., description="Detailed finding description")
    remediation: str = Field(..., description="Recommended remediation steps")
    detected_at: datetime = Field(
        default_factory=datetime.now, description="When finding was detected"
    )
    resource_arn: str | None = Field(None, description="Related resource ARN/ID")
    policy_arn: str | None = Field(None, description="Related policy ARN/ID")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional context"
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "id": "finding-123456",
                "severity": "high",
                "category": "excessive_permissions",
                "account_id": "arn:aws:iam::123456789012:user/john.doe",
                "title": "User has wildcard admin policy",
                "description": "User john.doe has AdministratorAccess policy attached with full wildcard permissions (*:* on all resources)",
                "remediation": "Remove AdministratorAccess policy and grant least-privilege permissions based on actual usage",
                "detected_at": "2024-03-11T10:30:00Z",
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "metadata": {"policy_name": "AdministratorAccess", "is_aws_managed": True},
            }
        }

    def risk_score(self) -> int:
        """Calculate numeric risk score based on severity.

        Returns:
            Risk score (0-100)
        """
        severity_scores = {
            FindingSeverity.CRITICAL: 100,
            FindingSeverity.HIGH: 75,
            FindingSeverity.MEDIUM: 50,
            FindingSeverity.LOW: 25,
            FindingSeverity.INFO: 10,
        }
        return severity_scores.get(self.severity, 0)

    def to_dict(self) -> dict:
        """Convert finding to dictionary for reporting.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category.value,
            "account_id": self.account_id,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "detected_at": self.detected_at.isoformat(),
            "resource_arn": self.resource_arn,
            "policy_arn": self.policy_arn,
            "risk_score": self.risk_score(),
            "metadata": self.metadata,
        }
