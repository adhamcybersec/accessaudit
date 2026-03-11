"""Dashboard routes serving HTMX-powered HTML pages."""

from pathlib import Path

from fastapi import APIRouter, Request, Query
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["dashboard"])

_templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))


@router.get("/")
async def dashboard_home(request: Request):
    """Dashboard home page with scan summary and recent findings."""
    scans = request.app.state.scans
    analyses = request.app.state.analyses

    total_scans = len(scans)
    completed_scans = sum(1 for s in scans.values() if s.status == "completed")
    running_scans = sum(1 for s in scans.values() if s.status in ("running", "pending"))

    # Collect findings from all analyses
    all_findings = []
    for scan_id, analysis in analyses.items():
        if hasattr(analysis, "findings"):
            for f in analysis.findings:
                finding_dict = f.to_dict() if hasattr(f, "to_dict") else f
                finding_dict["scan_id"] = scan_id
                all_findings.append(finding_dict)

    recent_scans = list(scans.values())[-10:]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_findings": len(all_findings),
        "recent_scans": recent_scans,
        "findings": all_findings[:20],
    })


@router.get("/scans", response_class=None)
async def scans_page(request: Request):
    """Scans list page with HTMX polling for running scans."""
    scans_list = list(request.app.state.scans.values())
    has_running = any(s.status in ("running", "pending") for s in scans_list)

    return templates.TemplateResponse("scans.html", {
        "request": request,
        "scans": scans_list,
        "has_running": has_running,
    })


@router.get("/findings", response_class=None)
async def findings_page(
    request: Request,
    severity: str = Query(default="", description="Filter by severity"),
    category: str = Query(default="", description="Filter by category"),
):
    """Findings page with HTMX-powered filters."""
    analyses = request.app.state.analyses

    all_findings = []
    for scan_id, analysis in analyses.items():
        if hasattr(analysis, "findings"):
            for f in analysis.findings:
                finding_dict = f.to_dict() if hasattr(f, "to_dict") else f
                finding_dict["scan_id"] = scan_id
                all_findings.append(finding_dict)

    # Apply filters
    if severity:
        all_findings = [f for f in all_findings if f.get("severity") == severity]
    if category:
        all_findings = [f for f in all_findings if f.get("category") == category]

    return templates.TemplateResponse("findings.html", {
        "request": request,
        "findings": all_findings,
        "severity_filter": severity,
        "category_filter": category,
    })


@router.get("/reports", response_class=None)
async def reports_page(request: Request):
    """Reports generation page."""
    scans = list(request.app.state.scans.values())
    analyses = request.app.state.analyses

    return templates.TemplateResponse("reports.html", {
        "request": request,
        "scans": scans,
        "analyses": analyses,
    })


@router.get("/rules-dashboard", response_class=None)
async def rules_page(request: Request):
    """Policy rules management page."""
    from accessaudit.analysis.policy_engine import PolicyEngine

    engine = PolicyEngine()
    rules = []
    for rule_file in engine.rule_files:
        rules.append({
            "file": rule_file,
            "name": Path(rule_file).stem,
        })

    return templates.TemplateResponse("rules.html", {
        "request": request,
        "rules": rules,
    })
