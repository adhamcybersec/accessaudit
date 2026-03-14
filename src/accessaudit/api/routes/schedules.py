"""Scheduled scan endpoints."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from accessaudit.scheduling.models import ScheduledScan, ScheduledScanCreate, ScheduledScanUpdate
from accessaudit.scheduling.service import SchedulerService

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


def _get_scheduler(request: Request) -> SchedulerService:
    """Get scheduler service from app state."""
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    return scheduler  # type: ignore[no-any-return]


@router.get("")
async def list_schedules(request: Request) -> list[dict[str, Any]]:
    """List all scheduled scans."""
    scheduler = _get_scheduler(request)
    result: list[dict[str, Any]] = [s.model_dump(mode="json") for s in scheduler.list_schedules()]
    return result


@router.post("", status_code=201)
async def create_schedule(request: Request, body: ScheduledScanCreate) -> dict[str, Any]:
    """Create a new scheduled scan."""
    scheduler = _get_scheduler(request)
    schedule = ScheduledScan(
        name=body.name,
        provider=body.provider,
        config=body.config,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
        notify_on_complete=body.notify_on_complete,
        notify_on_failure=body.notify_on_failure,
    )
    try:
        created = scheduler.create_schedule(schedule)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    result: dict[str, Any] = created.model_dump(mode="json")
    return result


@router.get("/{schedule_id}")
async def get_schedule(request: Request, schedule_id: str) -> dict[str, Any]:
    """Get a specific scheduled scan."""
    scheduler = _get_scheduler(request)
    schedule = scheduler.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    result: dict[str, Any] = schedule.model_dump(mode="json")
    return result


@router.put("/{schedule_id}")
async def update_schedule(
    request: Request, schedule_id: str, body: ScheduledScanUpdate
) -> dict[str, Any]:
    """Update a scheduled scan."""
    scheduler = _get_scheduler(request)
    try:
        updated = scheduler.update_schedule(schedule_id, body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not updated:
        raise HTTPException(status_code=404, detail="Schedule not found")
    result: dict[str, Any] = updated.model_dump(mode="json")
    return result


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(request: Request, schedule_id: str) -> None:
    """Delete a scheduled scan."""
    scheduler = _get_scheduler(request)
    if not scheduler.delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")


@router.post("/{schedule_id}/enable")
async def enable_schedule(request: Request, schedule_id: str) -> dict[str, str]:
    """Enable a scheduled scan."""
    scheduler = _get_scheduler(request)
    if not scheduler.enable_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "enabled"}


@router.post("/{schedule_id}/disable")
async def disable_schedule(request: Request, schedule_id: str) -> dict[str, str]:
    """Disable a scheduled scan."""
    scheduler = _get_scheduler(request)
    if not scheduler.disable_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "disabled"}


@router.get("/{schedule_id}/runs")
async def get_schedule_runs(request: Request, schedule_id: str) -> list[dict[str, Any]]:
    """Get run history for a scheduled scan."""
    scheduler = _get_scheduler(request)
    if not scheduler.get_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    result: list[dict[str, Any]] = scheduler.get_runs(schedule_id)
    return result
