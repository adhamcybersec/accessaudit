"""Notification configuration and management endpoints."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from accessaudit.notifications.base import Notification, NotificationEventType

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


class NotificationConfigUpdate(BaseModel):
    """Update notification configuration."""

    enabled: bool = True
    providers: list[dict[str, Any]] = []


class TestNotificationRequest(BaseModel):
    """Request to send a test notification."""

    message: str = "This is a test notification from AccessAudit."


@router.get("/config")
async def get_notification_config(request: Request) -> dict[str, Any]:
    """Get current notification configuration."""
    manager = getattr(request.app.state, "notification_manager", None)
    return {
        "enabled": manager is not None,
        "provider_count": len(manager.providers) if manager else 0,
    }


@router.put("/config")
async def update_notification_config(
    request: Request, body: NotificationConfigUpdate
) -> dict[str, Any]:
    """Update notification configuration."""
    from accessaudit.notifications.manager import NotificationManager
    from accessaudit.notifications.slack import SlackProvider
    from accessaudit.notifications.teams import TeamsProvider
    from accessaudit.notifications.webhook import WebhookProvider

    manager = NotificationManager()

    for prov_config in body.providers:
        prov_type = prov_config.get("type", "webhook")
        url = prov_config.get("webhook_url", "")
        min_sev = prov_config.get("min_severity", "medium")
        events = prov_config.get("events")

        if prov_type == "slack":
            provider = SlackProvider(webhook_url=url, events=events)
        elif prov_type == "teams":
            provider = TeamsProvider(webhook_url=url, events=events)
        else:
            provider = WebhookProvider(webhook_url=url, events=events)

        manager.register(provider, min_severity=min_sev)

    request.app.state.notification_manager = manager

    return {"enabled": body.enabled, "provider_count": len(manager.providers)}


@router.post("/test")
async def test_notification(request: Request, body: TestNotificationRequest) -> dict[str, Any]:
    """Send a test notification to all configured providers."""
    manager = getattr(request.app.state, "notification_manager", None)
    if not manager or not manager.providers:
        raise HTTPException(status_code=400, detail="No notification providers configured")

    notification = Notification(
        event_type=NotificationEventType.SCAN_COMPLETED,
        title="Test Notification",
        message=body.message,
        severity="info",
    )

    results = await manager.dispatch(notification)
    return {
        "sent": sum(results),
        "failed": len(results) - sum(results),
        "total_providers": len(results),
    }


@router.get("/history")
async def get_notification_history(request: Request) -> list[dict[str, Any]]:
    """Get notification dispatch history."""
    manager = getattr(request.app.state, "notification_manager", None)
    if not manager:
        return []
    return manager.history[-100:]  # Last 100 entries
