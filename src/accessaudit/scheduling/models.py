"""Scheduled scan models."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from accessaudit.db.models import Base


class ScheduledScan(BaseModel):
    """Pydantic model for scheduled scan configuration."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: str
    config: dict[str, Any] = {}
    cron_expression: str
    enabled: bool = True
    notify_on_complete: bool = True
    notify_on_failure: bool = True
    created_by: str | None = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None


class ScheduledScanCreate(BaseModel):
    """Request body for creating a scheduled scan."""

    name: str
    provider: str
    config: dict[str, Any] = {}
    cron_expression: str
    enabled: bool = True
    notify_on_complete: bool = True
    notify_on_failure: bool = True


class ScheduledScanUpdate(BaseModel):
    """Request body for updating a scheduled scan."""

    name: str | None = None
    cron_expression: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    notify_on_complete: bool | None = None
    notify_on_failure: bool | None = None


class ScheduledScanDB(Base):
    """SQLAlchemy model for scheduled scans."""

    __tablename__ = "scheduled_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    notify_on_complete: Mapped[bool] = mapped_column(default=True)
    notify_on_failure: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
