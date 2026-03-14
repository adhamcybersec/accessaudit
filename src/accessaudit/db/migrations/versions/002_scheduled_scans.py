"""Add scheduled_scans table.

Revision ID: 002
Revises: 001
Create Date: 2026-03-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create scheduled_scans table."""
    op.create_table(
        "scheduled_scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("config", JSONB, nullable=True),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("notify_on_complete", sa.Boolean, default=True),
        sa.Column("notify_on_failure", sa.Boolean, default=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Drop scheduled_scans table."""
    op.drop_table("scheduled_scans")
