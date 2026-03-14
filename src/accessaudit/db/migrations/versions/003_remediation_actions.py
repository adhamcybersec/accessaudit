"""Add remediation_actions table.

Revision ID: 003
Revises: 002
Create Date: 2026-03-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create remediation_actions table."""
    op.create_table(
        "remediation_actions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", sa.String(50), nullable=False),
        sa.Column("finding_id", sa.String(50), nullable=False),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("account_id", sa.String(255), nullable=False),
        sa.Column("resource_arn", sa.Text, server_default=""),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("parameters", JSONB, nullable=True),
        sa.Column("rollback_data", JSONB, nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_remediation_actions_scan_id", "remediation_actions", ["scan_id"])
    op.create_index("ix_remediation_actions_status", "remediation_actions", ["status"])


def downgrade() -> None:
    """Drop remediation_actions table."""
    op.drop_table("remediation_actions")
