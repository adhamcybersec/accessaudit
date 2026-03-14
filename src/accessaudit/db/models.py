"""SQLAlchemy 2.0 database models."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class UserDB(Base):
    """Application user for authentication."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scans: Mapped[list["ScanDB"]] = relationship(back_populates="user")

    __table_args__ = (Index("ix_users_email", "email"),)


class ScanDB(Base):
    """Persisted scan result."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    account_count: Mapped[int] = mapped_column(default=0)
    permission_count: Mapped[int] = mapped_column(default=0)
    policy_count: Mapped[int] = mapped_column(default=0)
    errors: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    scan_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    user: Mapped[UserDB | None] = relationship(back_populates="scans")
    analysis: Mapped["AnalysisDB | None"] = relationship(back_populates="scan")

    __table_args__ = (
        Index("ix_scans_provider", "provider"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_started_at", "started_at"),
    )


class AnalysisDB(Base):
    """Persisted analysis result."""

    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False
    )
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finding_count: Mapped[int] = mapped_column(default=0)
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    scan: Mapped[ScanDB] = relationship(back_populates="analysis")

    __table_args__ = (Index("ix_analyses_scan_id", "scan_id"),)
