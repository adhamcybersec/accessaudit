"""Report generation for IAM auditing."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.compliance.mappings import ComplianceMapper
from accessaudit.core.scanner import ScanResult
from accessaudit.models import FindingSeverity

# Template directory for Jinja2 HTML templates
_TEMPLATES_DIR = Path(__file__).parent / "templates" / "reports"

# Map template names to template files and compliance frameworks
_TEMPLATE_MAP = {
    "executive": {"file": "executive_report.html", "framework": None},
    "soc2": {"file": "soc2_report.html", "framework": "soc2"},
    "iso27001": {"file": "iso27001_report.html", "framework": "iso27001"},
}


class Reporter:
    """Generates audit reports in various formats."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize reporter.

        Args:
            config: Reporter configuration (formats, output paths, etc.)
        """
        self.config = config or {}
        self.include_remediation = self.config.get("include_remediation", True)

    async def generate_json_report(
        self,
        scan_result: ScanResult,
        analysis_result: AnalysisResult,
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Generate JSON report.

        Args:
            scan_result: Scan result
            analysis_result: Analysis result
            output_path: Optional path to write report

        Returns:
            Report as dictionary
        """
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "AccessAudit",
                "version": "0.1.0",
            },
            "scan": scan_result.to_dict(),
            "analysis": {
                "analyzed_at": analysis_result.analyzed_at.isoformat(),
                "summary": analysis_result.summary,
            },
            "findings": self._format_findings(analysis_result),
            "accounts": self._format_accounts(scan_result),
            "recommendations": self._generate_recommendations(analysis_result),
        }

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"Report saved to: {output_path}")

        return report

    def _format_findings(self, analysis_result: AnalysisResult) -> dict[str, Any]:
        """Format findings for report.

        Args:
            analysis_result: Analysis result

        Returns:
            Formatted findings
        """
        # Group findings by severity
        by_severity: dict[str, list] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for finding in analysis_result.findings:
            finding_dict = finding.to_dict()
            if not self.include_remediation:
                finding_dict.pop("remediation", None)
            by_severity[finding.severity.value].append(finding_dict)

        return {
            "total": len(analysis_result.findings),
            "by_severity": by_severity,
            "critical_count": len(by_severity["critical"]),
            "high_count": len(by_severity["high"]),
            "medium_count": len(by_severity["medium"]),
            "low_count": len(by_severity["low"]),
        }

    def _format_accounts(self, scan_result: ScanResult) -> list[dict[str, Any]]:
        """Format accounts for report.

        Args:
            scan_result: Scan result

        Returns:
            List of account summaries
        """
        accounts = []

        for account in scan_result.accounts:
            permissions = scan_result.permissions.get(account.id, [])
            accounts.append(
                {
                    "id": account.id,
                    "username": account.username,
                    "provider": account.provider,
                    "mfa_enabled": account.mfa_enabled,
                    "has_admin_role": account.has_admin_role,
                    "groups": account.groups,
                    "permission_count": len(permissions),
                    "is_dormant": account.is_dormant(),
                    "days_since_activity": account.days_since_activity(),
                }
            )

        return accounts

    def _generate_recommendations(self, analysis_result: AnalysisResult) -> list[dict[str, Any]]:
        """Generate prioritized recommendations.

        Args:
            analysis_result: Analysis result

        Returns:
            List of recommendations
        """
        recommendations = []

        # Check for critical findings
        critical_findings = [
            f for f in analysis_result.findings if f.severity == FindingSeverity.CRITICAL
        ]
        if critical_findings:
            recommendations.append(
                {
                    "priority": 1,
                    "title": "Address Critical Security Issues",
                    "description": f"Found {len(critical_findings)} critical security issues that require immediate attention.",
                    "actions": list(set(f.remediation for f in critical_findings[:3])),
                }
            )

        # Check for MFA issues
        mfa_findings = [f for f in analysis_result.findings if "mfa" in f.category.value.lower()]
        if mfa_findings:
            recommendations.append(
                {
                    "priority": 2,
                    "title": "Enable MFA for Privileged Accounts",
                    "description": f"Found {len(mfa_findings)} accounts without MFA enabled.",
                    "actions": [
                        "Enable MFA for all administrative accounts",
                        "Implement MFA enforcement policy",
                    ],
                }
            )

        # Check for dormant accounts
        dormant_findings = [
            f for f in analysis_result.findings if "dormant" in f.category.value.lower()
        ]
        if dormant_findings:
            recommendations.append(
                {
                    "priority": 3,
                    "title": "Review and Remove Dormant Accounts",
                    "description": f"Found {len(dormant_findings)} dormant accounts that may pose security risks.",
                    "actions": [
                        "Review each dormant account with team leads",
                        "Disable accounts no longer in use",
                        "Implement automated dormant account detection",
                    ],
                }
            )

        # General recommendations
        if analysis_result.summary.get("total_findings", 0) > 10:
            recommendations.append(
                {
                    "priority": 4,
                    "title": "Implement Regular Access Reviews",
                    "description": "High number of findings suggests lack of regular access reviews.",
                    "actions": [
                        "Schedule quarterly access reviews",
                        "Implement automated permission monitoring",
                        "Consider implementing just-in-time access",
                    ],
                }
            )

        return recommendations

    async def generate_summary_report(
        self, scan_result: ScanResult, analysis_result: AnalysisResult
    ) -> str:
        """Generate human-readable summary report.

        Args:
            scan_result: Scan result
            analysis_result: Analysis result

        Returns:
            Summary report as string
        """
        summary = analysis_result.summary

        lines = [
            "=" * 60,
            "            AccessAudit Security Report",
            "=" * 60,
            "",
            f"Provider: {scan_result.provider.upper()}",
            f"Scan ID: {scan_result.scan_id}",
            f"Scanned: {scan_result.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analyzed: {analysis_result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "                      Summary",
            "-" * 60,
            "",
            f"  Total Accounts:     {summary.get('total_accounts', 0)}",
            f"  Total Permissions:  {summary.get('total_permissions', 0)}",
            f"  Total Policies:     {summary.get('total_policies', 0)}",
            f"  Total Findings:     {summary.get('total_findings', 0)}",
            "",
            f"  Risk Score:         {summary.get('total_risk_score', 0)} (avg: {summary.get('average_risk_score', 0)})",
            "",
            "-" * 60,
            "                  Findings by Severity",
            "-" * 60,
            "",
        ]

        severity_counts = summary.get("findings_by_severity", {})
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            indicator = (
                "🔴"
                if severity == "critical"
                else ("🟠" if severity == "high" else ("🟡" if severity == "medium" else "🟢"))
            )
            lines.append(f"  {indicator} {severity.upper():10} {count}")

        lines.extend(
            [
                "",
                "-" * 60,
                "                    Top Findings",
                "-" * 60,
                "",
            ]
        )

        for i, finding in enumerate(summary.get("top_findings", [])[:5], 1):
            lines.append(f"  {i}. [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"     Account: {finding['account']}")
            lines.append("")

        lines.extend(
            [
                "=" * 60,
                "  Report generated by AccessAudit v0.1.0",
                "=" * 60,
            ]
        )

        return "\n".join(lines)

    async def generate_html_report(
        self,
        scan_result: ScanResult,
        analysis_result: AnalysisResult,
        template: str = "executive",
        output_path: str | Path | None = None,
    ) -> str:
        """Generate an HTML report using Jinja2 templates.

        Args:
            scan_result: Scan result
            analysis_result: Analysis result
            template: Template name ("executive", "soc2", or "iso27001")
            output_path: Optional path to write the HTML file

        Returns:
            Rendered HTML string
        """
        template_info = _TEMPLATE_MAP.get(template)
        if template_info is None:
            raise ValueError(
                f"Unknown template: '{template}'. "
                f"Available templates: {', '.join(_TEMPLATE_MAP.keys())}"
            )

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )
        jinja_template = env.get_template(template_info["file"])

        # Build template context
        context: dict[str, Any] = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "provider": scan_result.provider,
            "scan_id": scan_result.scan_id,
            "summary": analysis_result.summary,
            "findings": analysis_result.findings,
            "severity_counts": analysis_result.summary.get("findings_by_severity", {}),
        }

        # For compliance templates, add control mappings
        framework = template_info["framework"]
        if framework:
            mapper = ComplianceMapper()
            context["controls"] = mapper.map_findings(framework, analysis_result.findings)

        html = jinja_template.render(**context)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html)

        return html

    async def generate_pdf_report(
        self,
        scan_result: ScanResult,
        analysis_result: AnalysisResult,
        template: str = "executive",
        output_path: str | Path | None = None,
    ) -> bytes:
        """Generate a PDF report by rendering HTML and converting via weasyprint.

        Args:
            scan_result: Scan result
            analysis_result: Analysis result
            template: Template name ("executive", "soc2", or "iso27001")
            output_path: Optional path to write the PDF file

        Returns:
            PDF content as bytes
        """
        import weasyprint

        html = await self.generate_html_report(scan_result, analysis_result, template=template)

        pdf_bytes = weasyprint.HTML(string=html).write_pdf()

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(pdf_bytes)

        return pdf_bytes
