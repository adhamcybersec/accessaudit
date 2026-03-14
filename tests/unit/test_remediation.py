"""Tests for remediation engine, models, and suggestions."""

import pytest

from accessaudit.models import Finding, FindingCategory, FindingSeverity
from accessaudit.remediation.engine import RemediationEngine
from accessaudit.remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
)
from accessaudit.remediation.suggestions import RemediationSuggester

# ============== State Machine Tests ==============


def test_valid_transition_pending_to_approved():
    action = RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.REMOVE_POLICY,
        provider="aws",
        account_id="user-1",
    )
    action.transition_to(RemediationStatus.APPROVED)
    assert action.status == RemediationStatus.APPROVED


def test_valid_transition_pending_to_rejected():
    action = RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.DISABLE_ACCOUNT,
        provider="aws",
        account_id="user-1",
    )
    action.transition_to(RemediationStatus.REJECTED)
    assert action.status == RemediationStatus.REJECTED


def test_invalid_transition_pending_to_executing():
    action = RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.ENABLE_MFA,
        provider="aws",
        account_id="user-1",
    )
    with pytest.raises(ValueError, match="Invalid transition"):
        action.transition_to(RemediationStatus.EXECUTING)


def test_invalid_transition_rejected_to_approved():
    action = RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.ENABLE_MFA,
        provider="aws",
        account_id="user-1",
        status=RemediationStatus.REJECTED,
    )
    with pytest.raises(ValueError, match="Invalid transition"):
        action.transition_to(RemediationStatus.APPROVED)


def test_can_transition_to():
    action = RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.ENABLE_MFA,
        provider="aws",
        account_id="user-1",
    )
    assert action.can_transition_to(RemediationStatus.APPROVED) is True
    assert action.can_transition_to(RemediationStatus.REJECTED) is True
    assert action.can_transition_to(RemediationStatus.EXECUTING) is False


# ============== Engine Tests ==============


@pytest.fixture
def engine():
    return RemediationEngine()


@pytest.fixture
def pending_action():
    return RemediationAction(
        scan_id="scan-1",
        finding_id="f-1",
        action_type=RemediationActionType.REMOVE_POLICY,
        provider="aws",
        account_id="user-1",
    )


async def test_engine_approve(engine, pending_action):
    engine.register_action(pending_action)
    result = engine.approve(pending_action.id, "admin@test.com")
    assert result.status == RemediationStatus.APPROVED
    assert result.approved_by == "admin@test.com"


async def test_engine_reject(engine, pending_action):
    engine.register_action(pending_action)
    result = engine.reject(pending_action.id)
    assert result.status == RemediationStatus.REJECTED


async def test_engine_execute(engine, pending_action):
    engine.register_action(pending_action)
    engine.approve(pending_action.id, "admin")
    result = await engine.execute(pending_action.id)
    assert result.status == RemediationStatus.COMPLETED
    assert result.result.get("simulated") is True


async def test_engine_execute_without_approval(engine, pending_action):
    engine.register_action(pending_action)
    with pytest.raises(ValueError, match="Invalid transition"):
        await engine.execute(pending_action.id)


async def test_engine_cancel(engine, pending_action):
    engine.register_action(pending_action)
    engine.approve(pending_action.id, "admin")
    result = engine.cancel(pending_action.id)
    assert result.status == RemediationStatus.CANCELLED


async def test_engine_list_actions(engine, pending_action):
    engine.register_action(pending_action)
    actions = engine.list_actions(scan_id="scan-1")
    assert len(actions) == 1
    assert actions[0].id == pending_action.id


# ============== Suggestion Tests ==============


def _make_finding(category: str, severity: str = "high") -> Finding:
    from datetime import datetime

    return Finding(
        id=f"f-{category}",
        severity=FindingSeverity(severity),
        category=FindingCategory(category),
        account_id="user-1",
        title=f"Test finding: {category}",
        description="Test description",
        remediation="Fix it",
        detected_at=datetime.now(),
    )


def test_suggest_dormant_account():
    suggester = RemediationSuggester()
    findings = [_make_finding("dormant_account")]
    suggestions = suggester.suggest("scan-1", findings, "aws")
    assert len(suggestions) == 1
    assert suggestions[0].action_type == RemediationActionType.DISABLE_ACCOUNT


def test_suggest_missing_mfa():
    suggester = RemediationSuggester()
    findings = [_make_finding("missing_mfa")]
    suggestions = suggester.suggest("scan-1", findings, "aws")
    assert len(suggestions) == 1
    assert suggestions[0].action_type == RemediationActionType.ENABLE_MFA


def test_suggest_excessive_permissions():
    suggester = RemediationSuggester()
    findings = [_make_finding("excessive_permissions")]
    suggestions = suggester.suggest("scan-1", findings, "aws")
    assert len(suggestions) == 1
    assert suggestions[0].action_type == RemediationActionType.REDUCE_PERMISSIONS


def test_suggest_all_pending():
    """All suggestions should start in PENDING state."""
    suggester = RemediationSuggester()
    findings = [
        _make_finding("dormant_account"),
        _make_finding("missing_mfa"),
    ]
    suggestions = suggester.suggest("scan-1", findings, "aws")
    assert all(s.status == RemediationStatus.PENDING for s in suggestions)
