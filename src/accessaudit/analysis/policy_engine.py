"""OPA/Rego policy engine for IAM compliance checks."""

import asyncio
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from accessaudit.models import (
    Account,
    Finding,
    FindingCategory,
    FindingSeverity,
    Permission,
    Policy,
)


class PolicyEngine:
    """Evaluates IAM data against OPA/Rego policies."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.rules_dir = self.config.get("rules_dir", "rules")
        self.rule_files = self._discover_rules()

    def _discover_rules(self) -> list[str]:
        """Find all .rego files in rules directory."""
        rules_path = Path(self.rules_dir)
        if not rules_path.exists():
            return []
        return [str(f) for f in rules_path.glob("*.rego")]

    def _opa_available(self) -> bool:
        """Check if OPA binary is available on PATH."""
        return shutil.which("opa") is not None

    async def evaluate_account(
        self, account: Account, permissions: list[Permission]
    ) -> list[Finding]:
        """Evaluate all Rego rules against an account and its permissions."""
        if not self._opa_available():
            return []

        if not self.rule_files:
            return []

        input_doc = self._build_input(account, permissions)

        findings = []
        for rule_file in self.rule_files:
            violations = await self._evaluate_rule_file(rule_file, input_doc)
            for violation_msg in violations:
                finding = self._create_finding(account, rule_file, violation_msg)
                findings.append(finding)

        return findings

    async def evaluate_all(
        self,
        accounts: list[Account],
        all_permissions: dict[str, list[Permission]],
        policies: list[Policy] | None = None,
    ) -> list[Finding]:
        """Evaluate rules against all accounts."""
        findings = []

        for account in accounts:
            permissions = all_permissions.get(account.id, [])
            account_findings = await self.evaluate_account(account, permissions)
            findings.extend(account_findings)

        return findings

    def _build_input(self, account: Account, permissions: list[Permission]) -> dict:
        """Build the JSON input document for OPA evaluation."""
        return {
            "account": {
                "id": account.id,
                "provider": account.provider,
                "username": account.username,
                "email": account.email,
                "mfa_enabled": account.mfa_enabled,
                "has_admin_role": account.has_admin_role,
                "groups": account.groups,
                "status": account.status.value,
                "days_since_activity": account.days_since_activity() or 0,
            },
            "permissions": [
                {
                    "id": p.id,
                    "resource_type": p.resource_type,
                    "resource_arn": p.resource_arn,
                    "actions": p.actions,
                    "effect": p.effect,
                    "scope": p.scope.value,
                    "source_policy": p.source_policy,
                }
                for p in permissions
            ],
        }

    async def _evaluate_rule_file(self, rule_file: str, input_doc: dict) -> list[str]:
        """Evaluate a single Rego rule file against input."""
        result = await self._run_opa(rule_file, input_doc)
        if not result:
            return []

        violations = []
        try:
            expressions = result.get("result", [{}])
            for expr in expressions:
                values = expr.get("expressions", [{}])
                for val in values:
                    messages = val.get("value", [])
                    if isinstance(messages, list):
                        violations.extend(messages)
                    elif isinstance(messages, str):
                        violations.append(messages)
        except (KeyError, TypeError, IndexError):
            pass

        return violations

    async def _run_opa(self, rule_file: str, input_doc: dict) -> dict | None:
        """Run OPA eval subprocess.

        Uses asyncio.create_subprocess_exec (not shell) to safely invoke
        the OPA binary with controlled arguments.
        """
        input_json = json.dumps({"input": input_doc})

        try:
            proc = await asyncio.create_subprocess_exec(
                "opa",
                "eval",
                "--data",
                rule_file,
                "--input",
                "/dev/stdin",
                "--format",
                "json",
                "data.accessaudit.rules.deny",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(input=input_json.encode())

            if proc.returncode == 0:
                return json.loads(stdout.decode())
            else:
                print(f"OPA error: {stderr.decode()}")
                return None
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"OPA evaluation error: {e}")
            return None

    def _create_finding(self, account: Account, rule_file: str, violation_msg: str) -> Finding:
        """Create a Finding from a Rego policy violation."""
        finding_id = hashlib.md5(
            f"rego:{account.id}:{rule_file}:{violation_msg}".encode()
        ).hexdigest()[:16]

        rule_name = Path(rule_file).stem

        return Finding(
            id=f"finding-{finding_id}",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.POLICY_VIOLATION,
            account_id=account.id,
            title=f"Policy violation: {violation_msg}",
            description=(
                f"Account {account.username} violates policy defined in "
                f"'{rule_name}.rego': {violation_msg}"
            ),
            remediation=(
                "Review and remediate the policy violation"
                " according to organizational guidelines."
            ),
            metadata={
                "rule_file": rule_file,
                "rule_name": rule_name,
                "violation_message": violation_msg,
                "engine": "opa",
            },
        )
