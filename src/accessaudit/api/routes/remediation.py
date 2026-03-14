"""Remediation API endpoints."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/remediations", tags=["remediation"])


def _get_engine(request: Request):  # type: ignore[no-untyped-def]
    """Get remediation engine from app state."""
    engine = getattr(request.app.state, "remediation_engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Remediation engine not initialized")
    return engine


class ApproveRequest(BaseModel):
    approved_by: str = "api_user"


class BulkApproveRequest(BaseModel):
    action_ids: list[str]
    approved_by: str = "api_user"


@router.get("")
async def list_remediations(request: Request, scan_id: str | None = None) -> list[dict[str, Any]]:
    """List all remediation actions."""
    engine = _get_engine(request)
    actions = engine.list_actions(scan_id=scan_id)
    return [a.model_dump(mode="json") for a in actions]


@router.post("/suggest/{scan_id}")
async def suggest_remediations(request: Request, scan_id: str) -> list[dict[str, Any]]:
    """Generate remediation suggestions for a scan's findings."""
    from accessaudit.remediation.suggestions import RemediationSuggester
    from accessaudit.services.storage import StorageBackend

    # Get storage
    storage: StorageBackend | None = getattr(request.app.state, "storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not initialized")

    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    analysis = await storage.get_analysis(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    suggester = RemediationSuggester()
    suggestions = suggester.suggest(scan_id, analysis.findings, scan.provider)

    engine = _get_engine(request)
    for action in suggestions:
        engine.register_action(action)

    return [s.model_dump(mode="json") for s in suggestions]


@router.get("/{action_id}")
async def get_remediation(request: Request, action_id: str) -> dict[str, Any]:
    """Get a specific remediation action."""
    engine = _get_engine(request)
    action = engine.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action.model_dump(mode="json")


@router.post("/{action_id}/approve")
async def approve_remediation(
    request: Request, action_id: str, body: ApproveRequest
) -> dict[str, Any]:
    """Approve a pending remediation action."""
    engine = _get_engine(request)
    try:
        action = engine.approve(action_id, body.approved_by)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return action.model_dump(mode="json")


@router.post("/{action_id}/reject")
async def reject_remediation(request: Request, action_id: str) -> dict[str, Any]:
    """Reject a pending remediation action."""
    engine = _get_engine(request)
    try:
        action = engine.reject(action_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return action.model_dump(mode="json")


@router.post("/{action_id}/execute")
async def execute_remediation(request: Request, action_id: str) -> dict[str, Any]:
    """Execute an approved remediation action."""
    engine = _get_engine(request)
    try:
        action = await engine.execute(action_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return action.model_dump(mode="json")


@router.post("/{action_id}/rollback")
async def rollback_remediation(request: Request, action_id: str) -> dict[str, Any]:
    """Rollback a completed remediation action."""
    engine = _get_engine(request)
    try:
        action = await engine.rollback(action_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return action.model_dump(mode="json")


@router.post("/bulk-approve")
async def bulk_approve(request: Request, body: BulkApproveRequest) -> dict[str, Any]:
    """Approve multiple remediation actions at once."""
    engine = _get_engine(request)
    approved = []
    errors = []

    for action_id in body.action_ids:
        try:
            engine.approve(action_id, body.approved_by)
            approved.append(action_id)
        except ValueError as e:
            errors.append({"id": action_id, "error": str(e)})

    return {"approved": approved, "errors": errors}
