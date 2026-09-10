"""Analyst-managed alert state and audit information."""

import uuid
from sqlalchemy import Column, JSON
from sqlmodel import Field
from app.models.base import TimestampedModel


class AlertRecord(TimestampedModel, table=True):
    __tablename__ = "alert_records"

    threat_id: uuid.UUID = Field(index=True, unique=True)
    acknowledged: bool = False
    resolved: bool = False
    assigned_to: str | None = Field(default=None, max_length=80)
    severity_override: str | None = Field(default=None, max_length=10)
    comment: str = ""
    actions: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
