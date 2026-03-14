"""Base notification types and provider interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class NotificationEventType(StrEnum):
    """Types of events that can trigger notifications."""

    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    CRITICAL_FINDING = "critical_finding"
    REMEDIATION_PENDING = "remediation_pending"
    REMEDIATION_APPROVED = "remediation_approved"
    REMEDIATION_EXECUTED = "remediation_executed"


class Notification(BaseModel):
    """A notification to be dispatched."""

    event_type: NotificationEventType
    title: str
    message: str
    severity: str = "info"
    timestamp: datetime = datetime.now()  # noqa: B008
    metadata: dict[str, Any] = {}


class BaseNotificationProvider(ABC):
    """Abstract base class for notification providers."""

    @abstractmethod
    async def send(self, notification: Notification) -> bool:
        """Send a notification.

        Returns:
            True if sent successfully.
        """
        ...

    @abstractmethod
    def supports_event(self, event_type: NotificationEventType) -> bool:
        """Check if this provider handles the given event type."""
        ...
