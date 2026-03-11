"""FastAPI application factory."""

from fastapi import FastAPI

from accessaudit.api.routes import health, scans, findings, reports, rules, dashboard


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI app instance with all routes registered
        and in-memory stores initialized on app.state.
    """
    app = FastAPI(
        title="AccessAudit",
        description="IAM Access Review Automation API",
        version="0.1.0",
    )

    # In-memory stores
    app.state.scans = {}       # scan_id -> ScanResult
    app.state.analyses = {}    # scan_id -> AnalysisResult

    # Register routers
    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(rules.router)
    app.include_router(dashboard.router)

    return app
