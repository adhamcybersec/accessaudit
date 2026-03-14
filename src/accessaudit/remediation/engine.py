"""Remediation execution engine."""

import logging
from datetime import datetime
from typing import Any

from accessaudit.remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
)

logger = logging.getLogger(__name__)


class RemediationEngine:
    """Executes approved remediation actions with rollback support.

    Actions must be APPROVED before execution. Never auto-executes.
    """

    def __init__(self) -> None:
        self.actions: dict[str, RemediationAction] = {}

    def register_action(self, action: RemediationAction) -> None:
        self.actions[action.id] = action

    def get_action(self, action_id: str) -> RemediationAction | None:
        return self.actions.get(action_id)

    def list_actions(self, scan_id: str | None = None) -> list[RemediationAction]:
        actions = list(self.actions.values())
        if scan_id:
            actions = [a for a in actions if a.scan_id == scan_id]
        return actions

    def approve(self, action_id: str, approved_by: str) -> RemediationAction:
        """Approve a pending action."""
        action = self._get_or_raise(action_id)
        action.transition_to(RemediationStatus.APPROVED)
        action.approved_by = approved_by
        return action

    def reject(self, action_id: str) -> RemediationAction:
        """Reject a pending action."""
        action = self._get_or_raise(action_id)
        action.transition_to(RemediationStatus.REJECTED)
        return action

    def cancel(self, action_id: str) -> RemediationAction:
        """Cancel an approved action before execution."""
        action = self._get_or_raise(action_id)
        action.transition_to(RemediationStatus.CANCELLED)
        return action

    async def execute(self, action_id: str) -> RemediationAction:
        """Execute an approved action.

        The action must be in APPROVED state.
        """
        action = self._get_or_raise(action_id)
        action.transition_to(RemediationStatus.EXECUTING)
        action.executed_at = datetime.now()

        try:
            result = await self._run_action(action)
            action.result = result
            action.transition_to(RemediationStatus.COMPLETED)
            action.completed_at = datetime.now()
            logger.info("Remediation %s completed: %s", action_id, action.action_type)
        except Exception as e:
            action.result = {"error": str(e)}
            action.transition_to(RemediationStatus.FAILED)
            action.completed_at = datetime.now()
            logger.error("Remediation %s failed: %s", action_id, e)

        return action

    async def rollback(self, action_id: str) -> RemediationAction:
        """Rollback a completed action using stored rollback data."""
        action = self._get_or_raise(action_id)
        if action.status != RemediationStatus.COMPLETED:
            raise ValueError("Can only rollback completed actions")
        if not action.rollback_data:
            raise ValueError("No rollback data available")

        # Re-enter pending state for re-execution
        action.status = RemediationStatus.PENDING
        action.result = {"rollback_requested": True, "original_result": action.result}
        action.updated_at = datetime.now()
        return action

    async def _run_action(self, action: RemediationAction) -> dict[str, Any]:
        """Execute the actual remediation. Calls connector methods."""
        # Build rollback data before making changes
        action.rollback_data = {
            "action_type": action.action_type.value,
            "account_id": action.account_id,
            "resource_arn": action.resource_arn,
            "timestamp": datetime.now().isoformat(),
        }

        # Dispatch to appropriate handler
        handlers = {
            RemediationActionType.REMOVE_POLICY: self._remove_policy,
            RemediationActionType.DISABLE_ACCOUNT: self._disable_account,
            RemediationActionType.ENABLE_MFA: self._enable_mfa,
            RemediationActionType.REDUCE_PERMISSIONS: self._reduce_permissions,
            RemediationActionType.ROTATE_CREDENTIALS: self._rotate_credentials,
        }

        handler = handlers.get(action.action_type)
        if handler:
            return await handler(action)
        return {"status": "no_handler", "action_type": action.action_type.value}

    async def _remove_policy(self, action: RemediationAction) -> dict[str, Any]:
        """Remove a policy from an account."""
        logger.info(
            "Removing policy %s from account %s",
            action.parameters.get("policy_arn", ""),
            action.account_id,
        )
        return {"action": "remove_policy", "simulated": True}

    async def _disable_account(self, action: RemediationAction) -> dict[str, Any]:
        """Disable an account."""
        logger.info("Disabling account %s", action.account_id)
        return {"action": "disable_account", "simulated": True}

    async def _enable_mfa(self, action: RemediationAction) -> dict[str, Any]:
        """Enable MFA for an account."""
        logger.info("Enabling MFA for account %s", action.account_id)
        return {"action": "enable_mfa", "simulated": True}

    async def _reduce_permissions(self, action: RemediationAction) -> dict[str, Any]:
        """Reduce permissions for an account."""
        logger.info("Reducing permissions for account %s", action.account_id)
        return {"action": "reduce_permissions", "simulated": True}

    async def _rotate_credentials(self, action: RemediationAction) -> dict[str, Any]:
        """Rotate credentials for an account."""
        logger.info("Rotating credentials for account %s", action.account_id)
        return {"action": "rotate_credentials", "simulated": True}

    def _get_or_raise(self, action_id: str) -> RemediationAction:
        action = self.actions.get(action_id)
        if not action:
            raise ValueError(f"Action not found: {action_id}")
        return action
