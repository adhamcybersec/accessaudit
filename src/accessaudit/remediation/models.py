"""Remediation models and state machine."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from accessaudit.db.models import Base


class RemediationStatus(StrEnum):
    """State machine for remediation actions."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationActionType(StrEnum):
    """Types of remediation actions."""

    REMOVE_POLICY = "remove_policy"
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_MFA = "enable_mfa"
    REDUCE_PERMISSIONS = "reduce_permissions"
    ROTATE_CREDENTIALS = "rotate_credentials"


# Valid state transitions
VALID_TRANSITIONS: dict[RemediationStatus, set[RemediationStatus]] = {
    RemediationStatus.PENDING: {RemediationStatus.APPROVED, RemediationStatus.REJECTED},
    RemediationStatus.APPROVED: {RemediationStatus.EXECUTING, RemediationStatus.CANCELLED},
    RemediationStatus.EXECUTING: {RemediationStatus.COMPLETED, RemediationStatus.FAILED},
    RemediationStatus.REJECTED: set(),
    RemediationStatus.COMPLETED: set(),
    RemediationStatus.FAILED: {RemediationStatus.PENDING},  # Can retry
    RemediationStatus.CANCELLED: set(),
}


class RemediationAction(BaseModel):
    """A remediation action with state machine."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    finding_id: str
    action_type: RemediationActionType
    status: RemediationStatus = RemediationStatus.PENDING
    provider: str
    account_id: str
    resource_arn: str = ""
    description: str = ""
    parameters: dict[str, Any] = {}
    rollback_data: dict[str, Any] = {}
    result: dict[str, Any] = {}
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    approved_by: str | None = None
    executed_at: datetime | None = None
    completed_at: datetime | None = None

    def can_transition_to(self, new_status: RemediationStatus) -> bool:
        """Check if transition to new_status is valid."""
        return new_status in VALID_TRANSITIONS.get(self.status, set())

    def transition_to(self, new_status: RemediationStatus) -> None:
        """Transition to new status. Raises ValueError if invalid."""
        if not self.can_transition_to(new_status):
            raise ValueError(
                f"Invalid transition: {self.status} → {new_status}"
            )
        self.status = new_status
        self.updated_at = datetime.now()


class RemediationActionDB(Base):
    """SQLAlchemy model for remediation actions."""

    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[str] = mapped_column(String(50), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(50), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    account_id: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_arn: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    parameters: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rollback_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
