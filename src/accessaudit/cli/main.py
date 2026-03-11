"""CLI application for AccessAudit."""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from accessaudit import __version__
from accessaudit.core.analyzer import Analyzer
from accessaudit.core.reporter import Reporter
from accessaudit.core.scanner import Scanner
from accessaudit.utils.config import Config, create_example_config, load_config
from accessaudit.utils.logging import setup_logging

app = typer.Typer(
    name="accessaudit",
    help="IAM Access Review Automation Platform",
    no_args_is_help=True,
)
console = Console()

# Global state
_config: Config | None = None
_last_scan_result = None
_last_analysis_result = None


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"AccessAudit v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose output",
    ),
) -> None:
    """AccessAudit - IAM Access Review Automation Platform."""
    global _config

    # Set up logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(level=log_level)

    # Load configuration
    _config = load_config(config_file)


# ============== SCAN COMMANDS ==============

scan_app = typer.Typer(help="Scan IAM providers")
app.add_typer(scan_app, name="scan")


def _run_scan(provider: str, provider_config: dict, output: Optional[str], no_analyze: bool) -> None:
    """Run a scan for the given provider with shared logic."""
    global _last_scan_result, _last_analysis_result

    provider_label = provider.upper()
    console.print(Panel.fit(f"[bold blue]AccessAudit - {provider_label} IAM Scan[/bold blue]"))

    try:
        # Run scan
        console.print(f"\n[yellow]Starting {provider_label} IAM scan...[/yellow]")
        scanner = Scanner()
        scan_result = asyncio.run(scanner.scan(provider, provider_config))
        _last_scan_result = scan_result

        console.print(f"[green]✓[/green] Found {len(scan_result.accounts)} accounts")
        console.print(
            f"[green]✓[/green] Found {sum(len(p) for p in scan_result.permissions.values())} permissions"
        )
        console.print(f"[green]✓[/green] Found {len(scan_result.policies)} policies")

        if scan_result.errors:
            console.print(f"[yellow]![/yellow] {len(scan_result.errors)} errors occurred")

        # Run analysis
        if not no_analyze:
            console.print("\n[yellow]Running analysis...[/yellow]")
            analyzer = Analyzer(_config.to_dict() if _config else {})
            analysis_result = asyncio.run(analyzer.analyze(scan_result))
            _last_analysis_result = analysis_result

            # Show summary
            _print_analysis_summary(analysis_result)

            # Generate report
            if output:
                reporter = Reporter()
                asyncio.run(
                    reporter.generate_json_report(scan_result, analysis_result, output)
                )
                console.print(f"\n[green]✓[/green] Report saved to: {output}")

    except Exception as e:
        console.print(f"[red]✗ Scan failed: {e}[/red]")
        raise typer.Exit(1)


@scan_app.command("aws")
def scan_aws(
    region: Optional[str] = typer.Option(
        None,
        "--region",
        "-r",
        help="AWS region to scan (default: from config or us-east-1)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for JSON report",
    ),
    no_analyze: bool = typer.Option(
        False,
        "--no-analyze",
        help="Skip analysis (scan only)",
    ),
) -> None:
    """Scan AWS IAM for security issues."""
    # Build provider config
    provider_config = {}
    if _config:
        provider_config = _config.providers.aws.model_dump()
    if region:
        provider_config["regions"] = [region]
        provider_config["region"] = region

    _run_scan("aws", provider_config, output, no_analyze)


@scan_app.command("azure")
def scan_azure(
    tenant_id: Optional[str] = typer.Option(
        None,
        "--tenant-id",
        "-t",
        help="Azure AD tenant ID",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for JSON report",
    ),
    no_analyze: bool = typer.Option(
        False,
        "--no-analyze",
        help="Skip analysis (scan only)",
    ),
) -> None:
    """Scan Azure AD IAM for security issues."""
    # Build provider config
    provider_config = {}
    if _config and hasattr(_config.providers, "azure"):
        provider_config = _config.providers.azure.model_dump()
    if tenant_id:
        provider_config["tenant_id"] = tenant_id

    _run_scan("azure", provider_config, output, no_analyze)


@scan_app.command("gcp")
def scan_gcp(
    project: Optional[str] = typer.Option(
        None,
        "--project",
        "-p",
        help="GCP project ID",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for JSON report",
    ),
    no_analyze: bool = typer.Option(
        False,
        "--no-analyze",
        help="Skip analysis (scan only)",
    ),
) -> None:
    """Scan GCP IAM for security issues."""
    # Build provider config
    provider_config = {}
    if _config and hasattr(_config.providers, "gcp"):
        provider_config = _config.providers.gcp.model_dump()
    if project:
        provider_config["project_id"] = project

    _run_scan("gcp", provider_config, output, no_analyze)


# ============== FINDINGS COMMANDS ==============

findings_app = typer.Typer(help="View and filter findings")
app.add_typer(findings_app, name="findings")


@findings_app.command("list")
def findings_list(
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (critical, high, medium, low)",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="Filter by category",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of findings to show",
    ),
) -> None:
    """List findings from the last scan."""
    global _last_analysis_result

    if not _last_analysis_result:
        console.print("[yellow]No analysis results available. Run a scan first.[/yellow]")
        console.print("  accessaudit scan aws")
        raise typer.Exit(1)

    findings = _last_analysis_result.findings

    # Apply filters
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    if category:
        findings = [f for f in findings if category.lower() in f.category.value.lower()]

    if not findings:
        console.print("[green]No findings match your criteria.[/green]")
        return

    # Display findings
    table = Table(title=f"Findings ({len(findings)} total)")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Account")

    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for finding in findings[:limit]:
        color = severity_colors.get(finding.severity.value, "white")
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.category.value,
            finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
            finding.account_id.split("/")[-1] if "/" in finding.account_id else finding.account_id,
        )

    console.print(table)

    if len(findings) > limit:
        console.print(f"\n[dim]Showing {limit} of {len(findings)} findings. Use --limit to see more.[/dim]")


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(..., help="Finding ID to show details"),
) -> None:
    """Show detailed information about a finding."""
    global _last_analysis_result

    if not _last_analysis_result:
        console.print("[yellow]No analysis results available. Run a scan first.[/yellow]")
        raise typer.Exit(1)

    finding = None
    for f in _last_analysis_result.findings:
        if f.id == finding_id or f.id.endswith(finding_id):
            finding = f
            break

    if not finding:
        console.print(f"[red]Finding not found: {finding_id}[/red]")
        raise typer.Exit(1)

    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = severity_colors.get(finding.severity.value, "white")

    console.print(Panel(
        f"[bold]{finding.title}[/bold]\n\n"
        f"[{color}]Severity: {finding.severity.value.upper()}[/{color}]\n"
        f"Category: {finding.category.value}\n"
        f"Account: {finding.account_id}\n"
        f"Detected: {finding.detected_at}\n\n"
        f"[bold]Description:[/bold]\n{finding.description}\n\n"
        f"[bold]Remediation:[/bold]\n{finding.remediation}",
        title=f"Finding: {finding.id}",
    ))


# ============== REPORT COMMANDS ==============

report_app = typer.Typer(help="Generate reports")
app.add_typer(report_app, name="report")


@report_app.command("generate")
def report_generate(
    output: str = typer.Option(
        "report.json",
        "--output",
        "-o",
        help="Output file path",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Report format: json, html, pdf",
    ),
    template: str = typer.Option(
        "executive",
        "--template",
        "-t",
        help="Report template: executive, soc2, iso27001",
    ),
) -> None:
    """Generate a report from the last scan."""
    global _last_scan_result, _last_analysis_result

    valid_formats = ("json", "html", "pdf")
    if format not in valid_formats:
        console.print(f"[red]Unsupported format: {format}. Choose from: {', '.join(valid_formats)}[/red]")
        raise typer.Exit(1)

    valid_templates = ("executive", "soc2", "iso27001")
    if template not in valid_templates:
        console.print(
            f"[red]Unsupported template: {template}. Choose from: {', '.join(valid_templates)}[/red]"
        )
        raise typer.Exit(1)

    if not _last_scan_result or not _last_analysis_result:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        console.print("  accessaudit scan aws --output report.json")
        raise typer.Exit(1)

    reporter = Reporter()

    if format == "json":
        asyncio.run(
            reporter.generate_json_report(_last_scan_result, _last_analysis_result, output)
        )
        console.print(f"[green]✓[/green] JSON report saved to: {output}")
    elif format == "html":
        asyncio.run(
            reporter.generate_html_report(
                _last_scan_result, _last_analysis_result, template=template, output_path=output
            )
        )
        console.print(f"[green]✓[/green] HTML report saved to: {output}")
    elif format == "pdf":
        asyncio.run(
            reporter.generate_pdf_report(
                _last_scan_result, _last_analysis_result, template=template, output_path=output
            )
        )
        console.print(f"[green]✓[/green] PDF report saved to: {output}")


@report_app.command("summary")
def report_summary() -> None:
    """Show summary of the last scan."""
    global _last_scan_result, _last_analysis_result

    if not _last_scan_result or not _last_analysis_result:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        raise typer.Exit(1)

    reporter = Reporter()
    summary = asyncio.run(
        reporter.generate_summary_report(_last_scan_result, _last_analysis_result)
    )
    console.print(summary)


# ============== CONFIG COMMANDS ==============

config_app = typer.Typer(help="Manage configuration")
app.add_typer(config_app, name="config")


@config_app.command("init")
def config_init(
    output: str = typer.Option(
        "config.yaml",
        "--output",
        "-o",
        help="Output file path",
    ),
) -> None:
    """Create an example configuration file."""
    output_path = Path(output)
    if output_path.exists():
        overwrite = typer.confirm(f"File {output} already exists. Overwrite?")
        if not overwrite:
            raise typer.Abort()

    create_example_config(output)
    console.print(f"[green]✓[/green] Configuration file created: {output}")
    console.print("[dim]Edit this file and rename to config.yaml to use.[/dim]")


@config_app.command("show")
def config_show() -> None:
    """Show current configuration."""
    if not _config:
        console.print("[yellow]No configuration loaded.[/yellow]")
        return

    import yaml

    console.print(Panel(
        yaml.dump(_config.to_dict(), default_flow_style=False),
        title="Current Configuration",
    ))


# ============== SERVE COMMAND ==============


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
) -> None:
    """Start the AccessAudit API server."""
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]uvicorn is not installed. Install it with: pip install uvicorn[/red]"
        )
        raise typer.Exit(1)

    console.print(
        Panel.fit(
            f"[bold blue]AccessAudit API Server[/bold blue]\n"
            f"Host: {host} | Port: {port} | Reload: {reload}"
        )
    )
    uvicorn.run(
        "accessaudit.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


# ============== HELPER FUNCTIONS ==============

def _print_analysis_summary(analysis_result) -> None:
    """Print analysis summary to console."""
    summary = analysis_result.summary

    console.print("\n[bold]Analysis Summary[/bold]")
    console.print(f"  Total findings: {summary.get('total_findings', 0)}")

    severity_counts = summary.get("findings_by_severity", {})
    for severity in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}
            color = colors.get(severity, "white")
            console.print(f"    [{color}]{severity.upper()}: {count}[/{color}]")

    console.print(f"\n  Risk Score: {summary.get('total_risk_score', 0)}")

    # Top findings
    top_findings = summary.get("top_findings", [])[:3]
    if top_findings:
        console.print("\n[bold]Top Issues:[/bold]")
        for i, finding in enumerate(top_findings, 1):
            console.print(f"  {i}. [{finding['severity'].upper()}] {finding['title']}")


if __name__ == "__main__":
    app()
