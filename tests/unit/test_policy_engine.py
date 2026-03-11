"""Tests for OPA policy engine."""

from pathlib import Path
from unittest.mock import patch

import pytest

from accessaudit.analysis.policy_engine import PolicyEngine
from accessaudit.models import Account, FindingCategory


@pytest.fixture
def base_rego(tmp_path):
    rego = tmp_path / "base.rego"
    rego.write_text("""
package accessaudit.rules

deny[msg] {
    input.account.has_admin_role
    not input.account.mfa_enabled
    msg := sprintf("Admin %s has no MFA", [input.account.username])
}
""")
    return str(rego)


@pytest.fixture
def engine(base_rego):
    return PolicyEngine({"rules_dir": str(Path(base_rego).parent)})


class TestPolicyEngine:
    def test_init_loads_rules_dir(self, engine, base_rego):
        assert len(engine.rule_files) >= 1

    @pytest.mark.asyncio
    async def test_evaluate_returns_violations(self, engine):
        """Should detect admin without MFA via Rego rule."""
        account = Account(
            id="u1",
            provider="aws",
            username="admin-user",
            mfa_enabled=False,
            has_admin_role=True,
        )

        opa_result = {"result": [{"expressions": [{"value": ["Admin admin-user has no MFA"]}]}]}

        with (
            patch.object(engine, "_opa_available", return_value=True),
            patch.object(engine, "_run_opa", return_value=opa_result),
        ):
            findings = await engine.evaluate_account(account, [])

        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.POLICY_VIOLATION

    @pytest.mark.asyncio
    async def test_no_violations_returns_empty(self, engine):
        """Account with MFA should pass."""
        account = Account(
            id="u2",
            provider="aws",
            username="good-user",
            mfa_enabled=True,
            has_admin_role=True,
        )

        opa_result = {"result": [{"expressions": [{"value": []}]}]}

        with (
            patch.object(engine, "_opa_available", return_value=True),
            patch.object(engine, "_run_opa", return_value=opa_result),
        ):
            findings = await engine.evaluate_account(account, [])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_opa_not_installed_falls_back(self, engine):
        """Should gracefully handle missing OPA binary."""
        with patch.object(engine, "_opa_available", return_value=False):
            account = Account(
                id="u1",
                provider="aws",
                username="user",
                mfa_enabled=False,
                has_admin_role=True,
            )
            findings = await engine.evaluate_account(account, [])
            assert isinstance(findings, list)
