"""
CyberRecon persistence model.

Stores completed authorized reconnaissance assessments as JSON payloads
so results survive page refreshes and container restarts.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, JSON
from sqlmodel import Field

from app.models.base import TimestampedModel


class ReconScan(TimestampedModel, table=True):
    """A completed reconnaissance scan."""

    __tablename__ = "recon_scans"

    target: str = Field(index=True, max_length=253)
    scan_type: str = Field(default="full", max_length=32)
    status: str = Field(default="completed", max_length=20)
    duration_ms: int = Field(default=0)
    authorized_use: bool = Field(default=False)
    result: dict = Field(sa_column=Column(JSON, nullable=False))
    error: str | None = Field(default=None, max_length=2000)
    completed_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
