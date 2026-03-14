"""Remediation suggestion generator."""

from accessaudit.models import Finding, FindingCategory
from accessaudit.remediation.models import RemediationAction, RemediationActionType

# Mapping from finding category to suggested remediation action type
_CATEGORY_ACTION_MAP: dict[str, RemediationActionType] = {
    FindingCategory.EXCESSIVE_PERMISSIONS: RemediationActionType.REDUCE_PERMISSIONS,
    FindingCategory.DORMANT_ACCOUNT: RemediationActionType.DISABLE_ACCOUNT,
    FindingCategory.MISSING_MFA: RemediationActionType.ENABLE_MFA,
    FindingCategory.OVERPRIVILEGED_ROLE: RemediationActionType.REDUCE_PERMISSIONS,
    FindingCategory.POLICY_VIOLATION: RemediationActionType.REMOVE_POLICY,
    FindingCategory.UNUSED_CREDENTIALS: RemediationActionType.ROTATE_CREDENTIALS,
}


class RemediationSuggester:
    """Generate remediation action suggestions from findings."""

    def suggest(
        self, scan_id: str, findings: list[Finding], provider: str
    ) -> list[RemediationAction]:
        """Generate remediation suggestions for a list of findings.

        All suggestions start in PENDING state. Never auto-executed.
        """
        suggestions: list[RemediationAction] = []

        for finding in findings:
            action_type = _CATEGORY_ACTION_MAP.get(finding.category.value)
            if not action_type:
                continue

            suggestion = RemediationAction(
                scan_id=scan_id,
                finding_id=finding.id,
                action_type=action_type,
                provider=provider,
                account_id=finding.account_id,
                resource_arn=finding.resource_arn or "",
                description=f"Suggested: {action_type.value} for {finding.title}",
                parameters={
                    "finding_severity": finding.severity.value,
                    "finding_category": finding.category.value,
                    "policy_arn": finding.policy_arn or "",
                },
            )
            suggestions.append(suggestion)

        return suggestions
