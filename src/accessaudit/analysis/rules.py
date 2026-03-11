"""Policy rule engine for custom compliance checks."""

import hashlib
from typing import Any

from accessaudit.models import (
    Account,
    Finding,
    FindingCategory,
    FindingSeverity,
    Permission,
    Policy,
)


class Rule:
    """Represents a compliance/policy rule."""

    def __init__(
        self,
        name: str,
        severity: str,
        condition: str,
        description: str | None = None,
        remediation: str | None = None,
    ):
        """Initialize rule.

        Args:
            name: Rule name
            severity: Rule severity (critical, high, medium, low)
            condition: Rule condition expression
            description: Rule description
            remediation: Recommended remediation
        """
        self.name = name
        self.severity = FindingSeverity(severity.lower())
        self.condition = condition
        self.description = description or f"Policy violation: {name}"
        self.remediation = remediation or "Review and remediate according to policy guidelines"

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate rule condition against context.

        Args:
            context: Evaluation context (account, permissions, policies, etc.)

        Returns:
            True if rule condition matches (violation detected)
        """
        # Simple string-based rule evaluation
        # In production, use a proper DSL or expression evaluator

        try:
            # Example conditions:
            # - "account.has_admin_role AND NOT account.mfa_enabled"
            # - "policy.has_wildcard_actions AND policy.has_wildcard_resources"
            # - "permission.actions contains '*'"

            condition = self.condition.lower()

            # Account checks
            if "account" in context:
                account: Account = context["account"]
                if "account.has_admin_role" in condition and not account.has_admin_role:
                    return False
                if "account.mfa_enabled" in condition and not account.mfa_enabled:
                    if "not account.mfa_enabled" in condition:
                        return True
                    return False

            # Policy checks
            if "policy" in context:
                policy: Policy = context["policy"]
                if "policy.has_wildcard_actions" in condition and not policy.has_wildcard_actions():
                    return False
                if (
                    "policy.has_wildcard_resources" in condition
                    and not policy.has_wildcard_resources()
                ):
                    return False
                if "policy.is_overly_permissive" in condition and policy.is_overly_permissive():
                    return True

            # Permission checks
            if "permission" in context:
                permission: Permission = context["permission"]
                if "permission.actions contains '*'" in condition and "*" in permission.actions:
                    return True
                if "permission.is_wildcard" in condition and permission.is_wildcard():
                    return True

            # AND logic
            if " and " in condition:
                parts = condition.split(" and ")
                return all(self._evaluate_simple_condition(part.strip(), context) for part in parts)

            # OR logic
            if " or " in condition:
                parts = condition.split(" or ")
                return any(self._evaluate_simple_condition(part.strip(), context) for part in parts)

            return self._evaluate_simple_condition(condition, context)

        except Exception as e:
            # Log error and return False (don't fail scan on bad rules)
            print(f"Rule evaluation error for '{self.name}': {e}")
            return False

    def _evaluate_simple_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate a simple condition.

        Args:
            condition: Condition string
            context: Evaluation context

        Returns:
            True if condition matches
        """
        # Handle NOT conditions
        if condition.startswith("not "):
            return not self._evaluate_simple_condition(condition[4:].strip(), context)

        # Account conditions
        if "account.has_admin_role" in condition:
            return context.get("account", Account).has_admin_role
        if "account.mfa_enabled" in condition:
            return context.get("account", Account).mfa_enabled

        # Policy conditions
        if "policy.has_wildcard_actions" in condition:
            return context.get("policy", Policy).has_wildcard_actions()
        if "policy.has_wildcard_resources" in condition:
            return context.get("policy", Policy).has_wildcard_resources()

        return False


class RuleEngine:
    """Engine for evaluating policy compliance rules."""

    def __init__(self, rules: list[dict[str, Any]] | None = None):
        """Initialize rule engine.

        Args:
            rules: List of rule definitions (from config)
        """
        self.rules: list[Rule] = []

        if rules:
            for rule_def in rules:
                rule = Rule(
                    name=rule_def["name"],
                    severity=rule_def["severity"],
                    condition=rule_def["condition"],
                    description=rule_def.get("description"),
                    remediation=rule_def.get("remediation"),
                )
                self.rules.append(rule)

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine.

        Args:
            rule: Rule to add
        """
        self.rules.append(rule)

    async def analyze(
        self,
        accounts: list[Account],
        all_permissions: dict[str, list[Permission]],
        policies: list[Policy] | None = None,
    ) -> list[Finding]:
        """Evaluate rules against accounts, permissions, and policies.

        Args:
            accounts: List of accounts
            all_permissions: Dict of account_id -> permissions
            policies: List of policies (optional)

        Returns:
            List of findings
        """
        findings = []

        for account in accounts:
            account_permissions = all_permissions.get(account.id, [])

            for rule in self.rules:
                # Build evaluation context
                context = {"account": account, "permissions": account_permissions}

                # Evaluate rule
                if rule.evaluate(context):
                    finding = await self._create_finding(rule, account, context)
                    findings.append(finding)

        # Policy-level rules
        if policies:
            for policy in policies:
                for rule in self.rules:
                    context = {"policy": policy}

                    if rule.evaluate(context):
                        # Create finding for policy (attach to first user if any)
                        account_id = policy.attached_to[0] if policy.attached_to else policy.arn
                        finding = Finding(
                            id=f"finding-{hashlib.md5(f'{rule.name}:{policy.arn}'.encode()).hexdigest()[:16]}",
                            severity=rule.severity,
                            category=FindingCategory.POLICY_VIOLATION,
                            account_id=account_id,
                            title=f"Policy violation: {rule.name}",
                            description=f"Policy {policy.name} violates rule: {rule.description}",
                            remediation=rule.remediation,
                            policy_arn=policy.arn,
                            metadata={"rule_name": rule.name, "policy_name": policy.name},
                        )
                        findings.append(finding)

        return findings

    async def _create_finding(
        self, rule: Rule, account: Account, context: dict[str, Any]
    ) -> Finding:
        """Create a finding from a rule violation.

        Args:
            rule: Violated rule
            account: Account with violation
            context: Evaluation context

        Returns:
            Finding object
        """
        finding_id = hashlib.md5(f"{rule.name}:{account.id}".encode()).hexdigest()[:16]

        return Finding(
            id=f"finding-{finding_id}",
            severity=rule.severity,
            category=FindingCategory.POLICY_VIOLATION,
            account_id=account.id,
            title=f"Policy violation: {rule.name}",
            description=f"Account {account.username} violates policy rule: {rule.description}",
            remediation=rule.remediation,
            metadata={"rule_name": rule.name},
        )
