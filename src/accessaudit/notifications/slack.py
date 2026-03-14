"""Slack notification provider using Incoming Webhooks."""

import logging

import httpx

from accessaudit.notifications.base import (
    BaseNotificationProvider,
    Notification,
    NotificationEventType,
)

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#0066FF",
    "info": "#808080",
}


class SlackProvider(BaseNotificationProvider):
    """Send notifications via Slack Incoming Webhook with Block Kit."""

    def __init__(self, webhook_url: str, events: list[str] | None = None):
        self.webhook_url = webhook_url
        self.events = events or [e.value for e in NotificationEventType]

    async def send(self, notification: Notification) -> bool:
        color = _SEVERITY_COLORS.get(notification.severity, "#808080")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"AccessAudit: {notification.title}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": notification.message,
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"*Severity:* {notification.severity.upper()}"
                            f" | *Event:* {notification.event_type.value}"
                        ),
                    }
                ],
            },
        ]

        payload = {
            "attachments": [{"color": color, "blocks": blocks}],
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.webhook_url, json=payload, timeout=10.0)
            return resp.status_code == 200

    def supports_event(self, event_type: NotificationEventType) -> bool:
        return event_type.value in self.events
