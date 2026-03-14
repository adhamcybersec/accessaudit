"""Generic webhook notification provider."""

import hashlib
import hmac
import logging

import httpx

from accessaudit.notifications.base import BaseNotificationProvider, Notification, NotificationEventType

logger = logging.getLogger(__name__)


class WebhookProvider(BaseNotificationProvider):
    """Send notifications via HTTP POST webhook."""

    def __init__(
        self,
        webhook_url: str,
        secret: str | None = None,
        events: list[str] | None = None,
    ):
        self.webhook_url = webhook_url
        self.secret = secret
        self.events = events or [e.value for e in NotificationEventType]

    async def send(self, notification: Notification) -> bool:
        payload = notification.model_dump(mode="json")
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self.secret:
            import json

            body = json.dumps(payload)
            sig = hmac.new(
                self.secret.encode(), body.encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Signature-256"] = f"sha256={sig}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.webhook_url, json=payload, headers=headers, timeout=10.0)
            return resp.status_code < 300

    def supports_event(self, event_type: NotificationEventType) -> bool:
        return event_type.value in self.events
