"""Tests for scheduling service."""

import pytest

from accessaudit.scheduling.models import ScheduledScan
from accessaudit.scheduling.service import SchedulerService, _validate_cron


def test_validate_cron_valid():
    assert _validate_cron("0 * * * *") is True
    assert _validate_cron("*/5 * * * *") is True
    assert _validate_cron("0 0 * * 0") is True


def test_validate_cron_invalid():
    assert _validate_cron("invalid") is False
    assert _validate_cron("") is False
    assert _validate_cron("0 * *") is False


async def test_create_schedule():
    service = SchedulerService()
    schedule = ScheduledScan(
        name="Daily AWS Scan",
        provider="aws",
        cron_expression="0 2 * * *",
    )
    created = service.create_schedule(schedule)
    assert created.name == "Daily AWS Scan"
    assert created.id in service.schedules


async def test_create_schedule_invalid_cron():
    service = SchedulerService()
    schedule = ScheduledScan(
        name="Bad Schedule",
        provider="aws",
        cron_expression="invalid",
    )
    with pytest.raises(ValueError, match="Invalid cron"):
        service.create_schedule(schedule)


async def test_list_schedules():
    service = SchedulerService()
    service.create_schedule(ScheduledScan(name="S1", provider="aws", cron_expression="0 * * * *"))
    service.create_schedule(ScheduledScan(name="S2", provider="azure", cron_expression="0 0 * * *"))
    assert len(service.list_schedules()) == 2


async def test_get_schedule():
    service = SchedulerService()
    schedule = service.create_schedule(
        ScheduledScan(name="Test", provider="aws", cron_expression="0 * * * *")
    )
    found = service.get_schedule(schedule.id)
    assert found is not None
    assert found.name == "Test"


async def test_get_nonexistent_schedule():
    service = SchedulerService()
    assert service.get_schedule("nonexistent") is None


async def test_update_schedule():
    service = SchedulerService()
    schedule = service.create_schedule(
        ScheduledScan(name="Test", provider="aws", cron_expression="0 * * * *")
    )
    updated = service.update_schedule(schedule.id, {"name": "Updated"})
    assert updated is not None
    assert updated.name == "Updated"


async def test_delete_schedule():
    service = SchedulerService()
    schedule = service.create_schedule(
        ScheduledScan(name="Test", provider="aws", cron_expression="0 * * * *")
    )
    assert service.delete_schedule(schedule.id) is True
    assert service.get_schedule(schedule.id) is None


async def test_enable_disable_schedule():
    service = SchedulerService()
    schedule = service.create_schedule(
        ScheduledScan(name="Test", provider="aws", cron_expression="0 * * * *", enabled=False)
    )
    assert service.enable_schedule(schedule.id) is True
    assert service.get_schedule(schedule.id).enabled is True

    assert service.disable_schedule(schedule.id) is True
    assert service.get_schedule(schedule.id).enabled is False


async def test_get_runs_empty():
    service = SchedulerService()
    schedule = service.create_schedule(
        ScheduledScan(name="Test", provider="aws", cron_expression="0 * * * *")
    )
    assert service.get_runs(schedule.id) == []
