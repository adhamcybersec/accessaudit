"""Scan endpoints."""

import asyncio
import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from accessaudit.core.scanner import Scanner, ScanResult
from accessaudit.services.storage import StorageBackend

router = APIRouter(prefix="/api/v1", tags=["scans"])


class ScanRequest(BaseModel):
    """Request body for triggering a scan."""

    provider: Literal["aws", "azure", "gcp", "sailpoint"]
    config: dict[str, Any] = {}


def _get_storage(request: Request) -> StorageBackend:
    """Get the storage backend from app state."""
    storage = getattr(request.app.state, "storage", None)
    if storage is not None:
        return storage  # type: ignore[return-value]
    # Fallback to legacy in-memory dicts
    from accessaudit.services.storage import InMemoryStorage

    mem = InMemoryStorage()
    mem.scans = request.app.state.scans
    mem.analyses = request.app.state.analyses
    return mem


@router.post("/scans", status_code=202)
async def trigger_scan(request: Request, body: ScanRequest) -> dict:
    """Trigger a new scan in the background. Returns scan ID immediately."""
    scan_id = str(uuid.uuid4())
    storage = _get_storage(request)

    # Create a placeholder scan result in pending state
    placeholder = ScanResult(
        scan_id=scan_id,
        provider=body.provider,
        started_at=datetime.now(),
        status="pending",
    )
    await storage.save_scan(placeholder)

    # Also store in legacy dict for backward compat
    request.app.state.scans[scan_id] = placeholder

    async def run_scan() -> None:
        try:
            placeholder.status = "running"
            await storage.update_scan(placeholder)
            request.app.state.scans[scan_id] = placeholder

            scanner = Scanner()
            result = await scanner.scan(body.provider, body.config or None)
            result.scan_id = scan_id
            await storage.update_scan(result)
            request.app.state.scans[scan_id] = result
        except Exception as e:
            placeholder.status = "failed"
            placeholder.errors.append(str(e))
            placeholder.completed_at = datetime.now()
            await storage.update_scan(placeholder)
            request.app.state.scans[scan_id] = placeholder

    # Store task reference to prevent garbage collection
    task = asyncio.create_task(run_scan())
    if not hasattr(request.app.state, "background_tasks"):
        request.app.state.background_tasks = set()
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)

    return {"scan_id": scan_id, "status": "pending"}


@router.get("/scans")
async def list_scans(request: Request) -> list[dict[str, Any]]:
    """List all past scans."""
    storage = _get_storage(request)
    scans = await storage.list_scans()
    return [scan.to_dict() for scan in scans]


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str) -> dict[str, Any]:
    """Get a specific scan result."""
    storage = _get_storage(request)
    scan = await storage.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    result: dict[str, Any] = scan.to_dict()
    return result


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(request: Request, scan_id: str) -> dict[str, Any]:
    """Get findings for a scan (requires analysis to have been run)."""
    storage = _get_storage(request)
    scan = await storage.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    analysis = await storage.get_analysis(scan_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis found for this scan. Run POST /api/v1/analyze/{scan_id} first.",
        )

    result: dict[str, Any] = analysis.to_dict()
    return result
