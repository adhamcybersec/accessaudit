"""Scan endpoints."""

import asyncio
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from accessaudit.core.scanner import Scanner, ScanResult

router = APIRouter(prefix="/api/v1", tags=["scans"])


class ScanRequest(BaseModel):
    """Request body for triggering a scan."""

    provider: str
    config: dict[str, Any] = {}


@router.post("/scans", status_code=202)
async def trigger_scan(request: Request, body: ScanRequest) -> dict:
    """Trigger a new scan in the background. Returns scan ID immediately."""
    scan_id = str(uuid.uuid4())[:8]

    # Create a placeholder scan result in pending state
    placeholder = ScanResult(
        scan_id=scan_id,
        provider=body.provider,
        started_at=datetime.now(),
        status="pending",
    )
    request.app.state.scans[scan_id] = placeholder

    async def run_scan() -> None:
        try:
            placeholder.status = "running"
            scanner = Scanner()
            result = await scanner.scan(body.provider, body.config or None)
            # Update the store with the completed result
            result.scan_id = scan_id
            request.app.state.scans[scan_id] = result
        except Exception as e:
            placeholder.status = "failed"
            placeholder.errors.append(str(e))
            placeholder.completed_at = datetime.now()

    asyncio.create_task(run_scan())

    return {"scan_id": scan_id, "status": "pending"}


@router.get("/scans")
async def list_scans(request: Request) -> list[dict]:
    """List all past scans."""
    return [scan.to_dict() for scan in request.app.state.scans.values()]


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str) -> dict:
    """Get a specific scan result."""
    scan = request.app.state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_dict()


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(request: Request, scan_id: str) -> dict:
    """Get findings for a scan (requires analysis to have been run)."""
    scan = request.app.state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    analysis = request.app.state.analyses.get(scan_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis found for this scan. Run POST /api/v1/analyze/{scan_id} first.",
        )

    return analysis.to_dict()
