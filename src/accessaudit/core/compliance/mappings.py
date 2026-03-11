"""Compliance framework mapper for mapping findings to control frameworks."""

from accessaudit.core.compliance.soc2 import SOC2_CONTROLS
from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS
from accessaudit.models.finding import Finding

FRAMEWORK_CONTROLS = {
    "soc2": SOC2_CONTROLS,
    "iso27001": ISO27001_CONTROLS,
}


class ComplianceMapper:
    """Maps security findings to compliance framework controls."""

    def map_findings(self, framework: str, findings: list[Finding]) -> list[dict]:
        """Map findings to compliance framework controls.

        Args:
            framework: Compliance framework name (e.g., "soc2", "iso27001").
            findings: List of Finding objects to map.

        Returns:
            List of dicts with control_id, control_name, findings, and status.

        Raises:
            ValueError: If the framework is not recognized.
        """
        controls = FRAMEWORK_CONTROLS.get(framework)
        if controls is None:
            raise ValueError(
                f"Unknown compliance framework: '{framework}'. "
                f"Supported frameworks: {', '.join(FRAMEWORK_CONTROLS.keys())}"
            )

        result = []
        for control_id, control in controls.items():
            matched_findings = [f for f in findings if f.category in control["categories"]]
            result.append(
                {
                    "control_id": control_id,
                    "control_name": control["name"],
                    "description": control["description"],
                    "findings": matched_findings,
                    "status": "fail" if matched_findings else "pass",
                }
            )

        return result
