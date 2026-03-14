"""Initial schema: users, scans, analyses.

Revision ID: 001
Revises:
Create Date: 2026-03-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial tables."""
    # Users table
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("api_key", sa.String(64), unique=True, nullable=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"])

    # Scans table
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("account_count", sa.Integer, default=0),
        sa.Column("permission_count", sa.Integer, default=0),
        sa.Column("policy_count", sa.Integer, default=0),
        sa.Column("errors", JSONB, nullable=True),
        sa.Column("scan_data", JSONB, nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
    )
    op.create_index("ix_scans_provider", "scans", ["provider"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_started_at", "scans", ["started_at"])

    # Analyses table
    op.create_table(
        "analyses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), unique=True, nullable=False
        ),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_count", sa.Integer, default=0),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("summary", JSONB, nullable=True),
    )
    op.create_index("ix_analyses_scan_id", "analyses", ["scan_id"])


def downgrade() -> None:
    """Drop initial tables."""
    op.drop_table("analyses")
    op.drop_table("scans")
    op.drop_table("users")
