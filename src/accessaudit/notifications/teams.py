"""Microsoft Teams notification provider using Incoming Webhooks."""

import logging

import httpx

from accessaudit.notifications.base import BaseNotificationProvider, Notification, NotificationEventType

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": "attention",
    "high": "warning",
    "medium": "accent",
    "low": "good",
    "info": "default",
}


class TeamsProvider(BaseNotificationProvider):
    """Send notifications via Teams Incoming Webhook with Adaptive Cards."""

    def __init__(self, webhook_url: str, events: list[str] | None = None):
        self.webhook_url = webhook_url
        self.events = events or [e.value for e in NotificationEventType]

    async def send(self, notification: Notification) -> bool:
        style = _SEVERITY_COLORS.get(notification.severity, "default")

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"AccessAudit: {notification.title}",
                                "weight": "bolder",
                                "size": "medium",
                                "color": style,
                            },
                            {
                                "type": "TextBlock",
                                "text": notification.message,
                                "wrap": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Severity", "value": notification.severity.upper()},
                                    {"title": "Event", "value": notification.event_type.value},
                                ],
                            },
                        ],
                    },
                }
            ],
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.webhook_url, json=card, timeout=10.0)
            return resp.status_code < 300

    def supports_event(self, event_type: NotificationEventType) -> bool:
        return event_type.value in self.events
