"""Policy rules endpoints."""

import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from accessaudit.analysis.policy_engine import PolicyEngine

router = APIRouter(prefix="/api/v1", tags=["rules"])


class ValidateRequest(BaseModel):
    """Request body for policy validation."""

    policy: str


@router.get("/rules")
async def list_rules() -> list[dict[str, Any]]:
    """List all available policy rules."""
    engine = PolicyEngine()
    rules = []
    for rule_file in engine.rule_files:
        rules.append(
            {
                "file": rule_file,
                "name": Path(rule_file).stem,
            }
        )
    return rules


@router.post("/rules/validate")
async def validate_rule(body: ValidateRequest) -> dict[str, Any]:
    """Validate a Rego policy string.

    Checks if the policy text is syntactically valid.
    If OPA is available, runs opa check against the policy.
    Otherwise, performs basic structural validation.
    """
    import asyncio
    import shutil

    policy_text = body.policy.strip()

    # Basic structural validation
    if not policy_text:
        return {"valid": False, "error": "Empty policy"}

    if "package" not in policy_text:
        return {"valid": False, "error": "Policy must contain a 'package' declaration"}

    # If OPA binary is available, do a real syntax check
    if shutil.which("opa"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
            f.write(policy_text)
            f.flush()
            tmp_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "opa",
                "check",
                tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode == 0:
                return {"valid": True}
            else:
                return {"valid": False, "error": stderr.decode().strip()}
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # No OPA binary -- basic check passed
    return {"valid": True, "note": "OPA binary not available; only basic validation performed"}
