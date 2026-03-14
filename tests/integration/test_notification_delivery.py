"""Integration test: notification delivery."""

import pytest
from httpx import ASGITransport, AsyncClient

from accessaudit.api.app import create_app
from accessaudit.notifications.base import BaseNotificationProvider, Notification, NotificationEventType


class MockProvider(BaseNotificationProvider):
    """Test provider that records sent notifications."""

    def __init__(self):
        self.sent: list[Notification] = []

    async def send(self, notification: Notification) -> bool:
        self.sent.append(notification)
        return True

    def supports_event(self, event_type: NotificationEventType) -> bool:
        return True


@pytest.fixture
async def client_with_notifications():
    app = create_app()
    async with app.router.lifespan_context(app):
        # Set up mock notification provider
        from accessaudit.notifications.manager import NotificationManager

        manager = NotificationManager()
        mock_provider = MockProvider()
        manager.register(mock_provider)
        app.state.notification_manager = manager

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, mock_provider


async def test_notification_test_endpoint(client_with_notifications):
    """POST /api/v1/notifications/test sends to configured providers."""
    client, mock_provider = client_with_notifications

    resp = await client.post(
        "/api/v1/notifications/test",
        json={"message": "Integration test notification"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["sent"] == 1
    assert data["failed"] == 0
    assert len(mock_provider.sent) == 1
    assert mock_provider.sent[0].title == "Test Notification"


async def test_notification_history(client_with_notifications):
    """Notification history records dispatched notifications."""
    client, _ = client_with_notifications

    # Send a test notification
    await client.post(
        "/api/v1/notifications/test",
        json={"message": "Test"},
    )

    resp = await client.get("/api/v1/notifications/history")
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) >= 1
    assert history[0]["success"] is True
