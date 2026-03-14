"""Analysis/findings endpoints."""

from fastapi import APIRouter, HTTPException, Request

from accessaudit.core.analyzer import Analyzer
from accessaudit.services.storage import StorageBackend

router = APIRouter(prefix="/api/v1", tags=["analyze"])


def _get_storage(request: Request) -> StorageBackend:
    """Get the storage backend from app state."""
    storage = getattr(request.app.state, "storage", None)
    if storage is not None:
        return storage  # type: ignore[no-any-return]
    from accessaudit.services.storage import InMemoryStorage

    mem = InMemoryStorage()
    mem.scans = request.app.state.scans
    mem.analyses = request.app.state.analyses
    return mem


@router.post("/analyze/{scan_id}")
async def analyze_scan(request: Request, scan_id: str) -> dict:
    """Run analysis on a completed scan result."""
    storage = _get_storage(request)
    scan = await storage.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed (status: {scan.status})",
        )

    analyzer = Analyzer()
    result = await analyzer.analyze(scan)
    await storage.save_analysis(result)

    # Also store in legacy dict for backward compat
    request.app.state.analyses[scan_id] = result

    return result.to_dict()
