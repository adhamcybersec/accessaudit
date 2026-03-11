"""Report generation endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from accessaudit.core.reporter import Reporter

router = APIRouter(prefix="/api/v1", tags=["reports"])


@router.get("/reports/{scan_id}")
async def get_report(
    request: Request,
    scan_id: str,
    format: str = Query(default="json", description="Report format: json, html, or pdf"),
    template: str = Query(default="executive", description="Report template name"),
) -> Response:
    """Generate or download a report for a scan."""
    scan = request.app.state.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    analysis = request.app.state.analyses.get(scan_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis found for this scan. Run POST /api/v1/analyze/{scan_id} first.",
        )

    reporter = Reporter()

    if format == "json":
        report = await reporter.generate_json_report(scan, analysis)
        return JSONResponse(content=report)
    elif format == "html":
        html = await reporter.generate_html_report(scan, analysis, template=template)
        return HTMLResponse(content=html)
    elif format == "pdf":
        pdf_bytes = await reporter.generate_pdf_report(scan, analysis, template=template)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report-{scan_id}.pdf"},
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
