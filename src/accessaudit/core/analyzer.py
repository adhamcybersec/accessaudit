"""Analysis orchestrator for IAM auditing."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from accessaudit.analysis.dormant import DormantAccountAnalyzer
from accessaudit.analysis.permissions import PermissionAnalyzer
from accessaudit.analysis.rules import RuleEngine
from accessaudit.core.scanner import ScanResult
from accessaudit.models import Finding, FindingSeverity


@dataclass
class AnalysisResult:
    """Result of IAM analysis."""

    scan_id: str
    analyzed_at: datetime
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "analyzed_at": self.analyzed_at.isoformat(),
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }


class Analyzer:
    """Orchestrates all analysis modules."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize analyzer.

        Args:
            config: Analysis configuration (thresholds, rules, etc.)
        """
        self.config = config or {}

        # Initialize analyzers
        analysis_config = self.config.get("analysis", {})

        self.permission_analyzer = PermissionAnalyzer({
            "max_permissions_threshold": analysis_config.get("max_permissions_threshold", 50),
        })

        self.dormant_analyzer = DormantAccountAnalyzer({
            "dormant_threshold_days": analysis_config.get("dormant_threshold_days", 90),
        })

        # Initialize rule engine with custom rules
        rules = analysis_config.get("rules", [])
        self.rule_engine = RuleEngine(rules)

        # Add default rules if none provided
        if not rules:
            self._add_default_rules()

    def _add_default_rules(self) -> None:
        """Add default security rules."""
        from accessaudit.analysis.rules import Rule

        default_rules = [
            Rule(
                name="Admin account without MFA",
                severity="high",
                condition="account.has_admin_role AND NOT account.mfa_enabled",
                description="Administrative accounts must have MFA enabled",
                remediation="Enable MFA for this administrative account",
            ),
            Rule(
                name="Overly permissive policy",
                severity="critical",
                condition="policy.is_overly_permissive",
                description="Policy grants wildcard permissions on all resources",
                remediation="Replace with least-privilege policy",
            ),
        ]

        for rule in default_rules:
            self.rule_engine.add_rule(rule)

    async def analyze(self, scan_result: ScanResult) -> AnalysisResult:
        """Run all analyses on scan results.

        Args:
            scan_result: Result from scanner

        Returns:
            AnalysisResult with findings
        """
        result = AnalysisResult(
            scan_id=scan_result.scan_id,
            analyzed_at=datetime.now(),
        )

        # Run permission analysis
        print(f"[{scan_result.scan_id}] Running permission analysis...")
        permission_findings = await self.permission_analyzer.analyze(
            scan_result.accounts, scan_result.permissions
        )
        result.findings.extend(permission_findings)

        # Run dormant account analysis
        print(f"[{scan_result.scan_id}] Running dormant account analysis...")
        dormant_findings = await self.dormant_analyzer.analyze(scan_result.accounts)
        result.findings.extend(dormant_findings)

        # Run rule engine
        print(f"[{scan_result.scan_id}] Running rule engine...")
        rule_findings = await self.rule_engine.analyze(
            scan_result.accounts, scan_result.permissions, scan_result.policies
        )
        result.findings.extend(rule_findings)

        # Generate summary
        result.summary = self._generate_summary(scan_result, result.findings)

        print(
            f"[{scan_result.scan_id}] Analysis complete: {len(result.findings)} findings"
        )

        return result

    def _generate_summary(
        self, scan_result: ScanResult, findings: list[Finding]
    ) -> dict[str, Any]:
        """Generate analysis summary.

        Args:
            scan_result: Scan result
            findings: List of findings

        Returns:
            Summary dictionary
        """
        # Count findings by severity
        severity_counts = {severity.value: 0 for severity in FindingSeverity}
        for finding in findings:
            severity_counts[finding.severity.value] += 1

        # Count findings by category
        category_counts: dict[str, int] = {}
        for finding in findings:
            category = finding.category.value
            category_counts[category] = category_counts.get(category, 0) + 1

        # Calculate risk score
        total_risk_score = sum(f.risk_score() for f in findings)
        avg_risk_score = total_risk_score / len(findings) if findings else 0

        # Identify top findings
        top_findings = sorted(findings, key=lambda f: f.risk_score(), reverse=True)[:5]

        return {
            "total_accounts": len(scan_result.accounts),
            "total_permissions": sum(len(p) for p in scan_result.permissions.values()),
            "total_policies": len(scan_result.policies),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "findings_by_category": category_counts,
            "total_risk_score": total_risk_score,
            "average_risk_score": round(avg_risk_score, 2),
            "top_findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "account": f.account_id,
                    "risk_score": f.risk_score(),
                }
                for f in top_findings
            ],
            "accounts_with_findings": len(set(f.account_id for f in findings)),
        }
