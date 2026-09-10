"""Persistent history for the Manual Request workspace."""
from sqlalchemy import Column, JSON
from sqlmodel import Field
from app.models.base import TimestampedModel

class ManualRequestRecord(TimestampedModel, table=True):
    __tablename__ = "manual_request_records"
    target_url: str = Field(max_length=1000)
    method: str = Field(max_length=10)
    path: str = Field(max_length=500)
    status_code: int | None = None
    reason: str | None = Field(default=None, max_length=255)
    body_preview: str = ""
    response_headers: dict[str, object] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    simulated_source_ip: str | None = Field(default=None, max_length=45)
