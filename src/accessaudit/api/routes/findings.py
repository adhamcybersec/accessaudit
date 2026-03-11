"""Analysis/findings endpoints."""

from fastapi import APIRouter, HTTPException, Request

from accessaudit.core.analyzer import Analyzer

router = APIRouter(prefix="/api/v1", tags=["analyze"])


@router.post("/analyze/{scan_id}")
async def analyze_scan(request: Request, scan_id: str) -> dict:
    """Run analysis on a completed scan result."""
    scan = request.app.state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed (status: {scan.status})",
        )

    analyzer = Analyzer()
    result = await analyzer.analyze(scan)
    request.app.state.analyses[scan_id] = result

    return result.to_dict()
