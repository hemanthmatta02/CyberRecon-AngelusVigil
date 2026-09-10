"""SOC incident model for analyst workflow and response tracking."""

import uuid
from datetime import datetime

from sqlalchemy import Column, JSON
from sqlmodel import Field

from app.models.base import TimestampedModel


class Incident(TimestampedModel, table=True):
    __tablename__ = "incidents"

    title: str = Field(max_length=255)
    description: str = ""
    severity: str = Field(default="MEDIUM", max_length=10)
    status: str = Field(default="OPEN", max_length=20)
    assigned_to: str | None = Field(default=None, max_length=120)
    source_ip: str | None = Field(default=None, max_length=45)
    threat_id: uuid.UUID | None = Field(default=None, index=True)
    notes: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    evidence: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    response_actions: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    resolved_at: datetime | None = None
