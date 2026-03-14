"""Dashboard routes serving HTMX-powered HTML pages."""

from pathlib import Path

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["dashboard"])

_templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))


def _get_scans_dict(request: Request) -> dict:  # type: ignore[type-arg]
    """Get scans from legacy dict (dashboard uses dict access pattern)."""
    result: dict = request.app.state.scans  # type: ignore[type-arg]
    return result


def _get_analyses_dict(request: Request) -> dict:  # type: ignore[type-arg]
    """Get analyses from legacy dict."""
    result: dict = request.app.state.analyses  # type: ignore[type-arg]
    return result


@router.get("/")
async def dashboard_home(request: Request) -> HTMLResponse:
    """Dashboard home page with scan summary and recent findings."""
    scans = _get_scans_dict(request)
    analyses = _get_analyses_dict(request)

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

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "total_findings": len(all_findings),
            "recent_scans": recent_scans,
            "findings": all_findings[:20],
        },
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request) -> HTMLResponse:
    """Scans list page with HTMX polling for running scans."""
    scans_list = list(_get_scans_dict(request).values())
    has_running = any(s.status in ("running", "pending") for s in scans_list)

    return templates.TemplateResponse(
        "scans.html",
        {
            "request": request,
            "scans": scans_list,
            "has_running": has_running,
        },
    )


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    severity: str = Query(default="", description="Filter by severity"),
    category: str = Query(default="", description="Filter by category"),
) -> HTMLResponse:
    """Findings page with HTMX-powered filters."""
    analyses = _get_analyses_dict(request)

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

    return templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "findings": all_findings,
            "severity_filter": severity,
            "category_filter": category,
        },
    )


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request) -> HTMLResponse:
    """Reports generation page."""
    scans = list(_get_scans_dict(request).values())
    analyses = _get_analyses_dict(request)

    return templates.TemplateResponse(
        "reports.html",
        {
            "request": request,
            "scans": scans,
            "analyses": analyses,
        },
    )


@router.get("/schedules", response_class=HTMLResponse)
async def schedules_dashboard(request: Request) -> HTMLResponse:
    """Schedules management page."""
    scheduler = getattr(request.app.state, "scheduler", None)
    schedule_list = []
    if scheduler:
        schedule_list = [s.model_dump(mode="json") for s in scheduler.list_schedules()]

    return templates.TemplateResponse(
        "schedules.html",
        {
            "request": request,
            "schedules": schedule_list,
        },
    )


@router.get("/notifications-dashboard", response_class=HTMLResponse)
async def notifications_dashboard(request: Request) -> HTMLResponse:
    """Notifications management page."""
    manager = getattr(request.app.state, "notification_manager", None)
    config = {
        "enabled": manager is not None,
        "provider_count": len(manager.providers) if manager else 0,
    }
    history = manager.history[-50:] if manager else []

    return templates.TemplateResponse(
        "notifications.html",
        {
            "request": request,
            "config": config,
            "history": history,
        },
    )


@router.get("/remediation-dashboard", response_class=HTMLResponse)
async def remediation_dashboard(request: Request) -> HTMLResponse:
    """Remediation actions page."""
    engine = getattr(request.app.state, "remediation_engine", None)
    actions = []
    counts = {"pending": 0, "approved": 0, "completed": 0, "failed": 0}

    if engine:
        all_actions = engine.list_actions()
        actions = [a.model_dump(mode="json") for a in all_actions]
        for a in all_actions:
            status = a.status.value if hasattr(a.status, "value") else a.status
            if status in counts:
                counts[status] += 1

    return templates.TemplateResponse(
        "remediation.html",
        {
            "request": request,
            "actions": actions,
            "counts": counts,
        },
    )


@router.get("/rules-dashboard", response_class=HTMLResponse)
async def rules_page(request: Request) -> HTMLResponse:
    """Policy rules management page."""
    from accessaudit.analysis.policy_engine import PolicyEngine

    engine = PolicyEngine()
    rules = []
    for rule_file in engine.rule_files:
        rules.append(
            {
                "file": rule_file,
                "name": Path(rule_file).stem,
            }
        )

    return templates.TemplateResponse(
        "rules.html",
        {
            "request": request,
            "rules": rules,
        },
    )
