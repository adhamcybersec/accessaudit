"""Notification manager for dispatching to multiple providers."""

import logging
from typing import Any

from accessaudit.notifications.base import (
    BaseNotificationProvider,
    Notification,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

MAX_RETRIES = 3


class NotificationManager:
    """Registers providers and dispatches notifications by event type and severity."""

    def __init__(self) -> None:
        self.providers: list[tuple[BaseNotificationProvider, str]] = []
        self.history: list[dict[str, Any]] = []

    def register(self, provider: BaseNotificationProvider, min_severity: str = "info") -> None:
        """Register a notification provider with minimum severity filter."""
        self.providers.append((provider, min_severity))

    async def dispatch(self, notification: Notification) -> list[bool]:
        """Dispatch notification to all matching providers.

        Returns list of success/failure booleans.
        """
        results: list[bool] = []

        notification_severity = _SEVERITY_ORDER.get(notification.severity, 0)

        for provider, min_severity in self.providers:
            min_sev = _SEVERITY_ORDER.get(min_severity, 0)
            if notification_severity < min_sev:
                continue

            if not provider.supports_event(notification.event_type):
                continue

            success = await self._send_with_retry(provider, notification)
            results.append(success)

            self.history.append(
                {
                    "event_type": notification.event_type.value,
                    "provider": provider.__class__.__name__,
                    "success": success,
                    "timestamp": notification.timestamp.isoformat(),
                }
            )

        return results

    async def _send_with_retry(
        self, provider: BaseNotificationProvider, notification: Notification
    ) -> bool:
        """Send with retry logic."""
        for attempt in range(MAX_RETRIES):
            try:
                if await provider.send(notification):
                    return True
            except Exception:
                logger.warning(
                    "Notification send failed (attempt %d/%d) for %s",
                    attempt + 1,
                    MAX_RETRIES,
                    provider.__class__.__name__,
                )

        logger.error("Notification send exhausted retries for %s", provider.__class__.__name__)
        return False
