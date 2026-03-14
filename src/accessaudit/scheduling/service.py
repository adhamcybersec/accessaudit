"""Scheduler service for recurring scans."""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any

from accessaudit.scheduling.models import ScheduledScan

logger = logging.getLogger(__name__)


def _validate_cron(expression: str) -> bool:
    """Validate a cron expression (5-field format)."""
    parts = expression.strip().split()
    if len(parts) != 5:
        return False
    # Basic validation: each field should be non-empty
    return all(len(p) > 0 for p in parts)


def _next_run_from_cron(cron_expression: str) -> datetime | None:
    """Calculate next run time from cron expression."""
    try:
        from croniter import croniter

        cron = croniter(cron_expression, datetime.now())
        return cron.get_next(datetime)  # type: ignore[return-value]
    except Exception:
        return None


class SchedulerService:
    """Manages scheduled scans with in-memory storage and asyncio tasks."""

    def __init__(self) -> None:
        self.schedules: dict[str, ScheduledScan] = {}
        self.run_history: dict[str, list[dict[str, Any]]] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._running = False

    async def start(self) -> None:
        """Start the scheduler and load enabled schedules."""
        self._running = True
        for schedule_id, schedule in self.schedules.items():
            if schedule.enabled:
                self._start_schedule_task(schedule_id)
        logger.info("Scheduler started with %d schedules", len(self.schedules))

    async def stop(self) -> None:
        """Stop all scheduled tasks."""
        self._running = False
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
        logger.info("Scheduler stopped")

    def create_schedule(self, schedule: ScheduledScan) -> ScheduledScan:
        """Create a new scheduled scan."""
        if not _validate_cron(schedule.cron_expression):
            raise ValueError(f"Invalid cron expression: {schedule.cron_expression}")

        schedule.next_run_at = _next_run_from_cron(schedule.cron_expression)
        self.schedules[schedule.id] = schedule
        self.run_history[schedule.id] = []

        if schedule.enabled and self._running:
            self._start_schedule_task(schedule.id)

        return schedule

    def get_schedule(self, schedule_id: str) -> ScheduledScan | None:
        return self.schedules.get(schedule_id)

    def list_schedules(self) -> list[ScheduledScan]:
        return list(self.schedules.values())

    def update_schedule(self, schedule_id: str, updates: dict[str, Any]) -> ScheduledScan | None:
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return None

        for key, value in updates.items():
            if value is not None and hasattr(schedule, key):
                setattr(schedule, key, value)

        if "cron_expression" in updates and updates["cron_expression"]:
            if not _validate_cron(updates["cron_expression"]):
                raise ValueError(f"Invalid cron expression: {updates['cron_expression']}")
            schedule.next_run_at = _next_run_from_cron(schedule.cron_expression)

        schedule.updated_at = datetime.now()
        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        if schedule_id not in self.schedules:
            return False

        # Cancel running task
        if schedule_id in self._tasks:
            self._tasks[schedule_id].cancel()
            del self._tasks[schedule_id]

        del self.schedules[schedule_id]
        self.run_history.pop(schedule_id, None)
        return True

    def enable_schedule(self, schedule_id: str) -> bool:
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return False
        schedule.enabled = True
        if self._running:
            self._start_schedule_task(schedule_id)
        return True

    def disable_schedule(self, schedule_id: str) -> bool:
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return False
        schedule.enabled = False
        if schedule_id in self._tasks:
            self._tasks[schedule_id].cancel()
            del self._tasks[schedule_id]
        return True

    def get_runs(self, schedule_id: str) -> list[dict[str, Any]]:
        return self.run_history.get(schedule_id, [])

    def _start_schedule_task(self, schedule_id: str) -> None:
        """Start an asyncio task for the scheduled scan."""
        if schedule_id in self._tasks:
            self._tasks[schedule_id].cancel()

        self._tasks[schedule_id] = asyncio.create_task(self._run_schedule_loop(schedule_id))

    async def _run_schedule_loop(self, schedule_id: str) -> None:
        """Run a schedule in a loop, sleeping until next run time."""
        while self._running:
            schedule = self.schedules.get(schedule_id)
            if not schedule or not schedule.enabled:
                break

            next_run = _next_run_from_cron(schedule.cron_expression)
            if not next_run:
                logger.error("Cannot compute next run for schedule %s", schedule_id)
                break

            schedule.next_run_at = next_run
            delay = (next_run - datetime.now()).total_seconds()
            if delay > 0:
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    break

            # Execute the scan
            await self._execute_scheduled_scan(schedule_id)

    async def _execute_scheduled_scan(self, schedule_id: str) -> None:
        """Execute a single scheduled scan run."""
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return

        run_id = str(uuid.uuid4())[:8]
        run_record: dict[str, Any] = {
            "run_id": run_id,
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }

        try:
            from accessaudit.core.analyzer import Analyzer
            from accessaudit.core.scanner import Scanner

            scanner = Scanner()
            result = await scanner.scan(schedule.provider, schedule.config or None)

            analyzer = Analyzer()
            analysis = await analyzer.analyze(result)

            run_record["status"] = "completed"
            run_record["finding_count"] = len(analysis.findings)
            run_record["completed_at"] = datetime.now().isoformat()

            schedule.last_run_at = datetime.now()

        except Exception as e:
            run_record["status"] = "failed"
            run_record["error"] = str(e)
            run_record["completed_at"] = datetime.now().isoformat()
            logger.error("Scheduled scan %s failed: %s", schedule_id, e)

        if schedule_id not in self.run_history:
            self.run_history[schedule_id] = []
        self.run_history[schedule_id].append(run_record)
