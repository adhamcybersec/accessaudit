"""Tests for notification system."""

import pytest

from accessaudit.notifications.base import (
    BaseNotificationProvider,
    Notification,
    NotificationEventType,
)
from accessaudit.notifications.manager import NotificationManager
from accessaudit.notifications.slack import SlackProvider
from accessaudit.notifications.teams import TeamsProvider
from accessaudit.notifications.webhook import WebhookProvider


class FakeProvider(BaseNotificationProvider):
    """Test notification provider."""

    def __init__(self, success: bool = True, events: list[str] | None = None):
        self.success = success
        self.events = events or [e.value for e in NotificationEventType]
        self.sent: list[Notification] = []

    async def send(self, notification: Notification) -> bool:
        self.sent.append(notification)
        return self.success

    def supports_event(self, event_type: NotificationEventType) -> bool:
        return event_type.value in self.events


@pytest.fixture
def notification():
    return Notification(
        event_type=NotificationEventType.SCAN_COMPLETED,
        title="Scan Complete",
        message="AWS scan completed with 5 findings",
        severity="high",
    )


async def test_manager_dispatch_to_all_providers(notification):
    manager = NotificationManager()
    p1 = FakeProvider()
    p2 = FakeProvider()
    manager.register(p1)
    manager.register(p2)

    results = await manager.dispatch(notification)
    assert results == [True, True]
    assert len(p1.sent) == 1
    assert len(p2.sent) == 1


async def test_manager_severity_filtering(notification):
    manager = NotificationManager()
    high_only = FakeProvider()
    all_severities = FakeProvider()
    manager.register(high_only, min_severity="critical")
    manager.register(all_severities, min_severity="low")

    # notification.severity is "high", which is below "critical"
    results = await manager.dispatch(notification)
    assert len(results) == 1
    assert len(high_only.sent) == 0
    assert len(all_severities.sent) == 1


async def test_manager_event_filtering(notification):
    manager = NotificationManager()
    scan_only = FakeProvider(events=["scan_completed"])
    remediation_only = FakeProvider(events=["remediation_pending"])
    manager.register(scan_only)
    manager.register(remediation_only)

    results = await manager.dispatch(notification)
    assert len(results) == 1
    assert len(scan_only.sent) == 1
    assert len(remediation_only.sent) == 0


async def test_manager_retry_on_failure():
    manager = NotificationManager()
    failing = FakeProvider(success=False)
    manager.register(failing)

    notification = Notification(
        event_type=NotificationEventType.SCAN_FAILED,
        title="Scan Failed",
        message="AWS scan failed",
        severity="high",
    )

    results = await manager.dispatch(notification)
    assert results == [False]
    # Should have tried 3 times (MAX_RETRIES)
    assert len(failing.sent) == 3


async def test_manager_history(notification):
    manager = NotificationManager()
    manager.register(FakeProvider())

    await manager.dispatch(notification)
    assert len(manager.history) == 1
    assert manager.history[0]["event_type"] == "scan_completed"
    assert manager.history[0]["success"] is True


async def test_webhook_provider_supports_event():
    provider = WebhookProvider(webhook_url="https://test.com", events=["scan_completed"])
    assert provider.supports_event(NotificationEventType.SCAN_COMPLETED) is True
    assert provider.supports_event(NotificationEventType.SCAN_FAILED) is False


async def test_slack_provider_supports_event():
    provider = SlackProvider(webhook_url="https://hooks.slack.com/test")
    # All events by default
    assert provider.supports_event(NotificationEventType.SCAN_COMPLETED) is True
    assert provider.supports_event(NotificationEventType.REMEDIATION_PENDING) is True


async def test_teams_provider_supports_event():
    provider = TeamsProvider(webhook_url="https://teams.webhook.com/test")
    assert provider.supports_event(NotificationEventType.CRITICAL_FINDING) is True
