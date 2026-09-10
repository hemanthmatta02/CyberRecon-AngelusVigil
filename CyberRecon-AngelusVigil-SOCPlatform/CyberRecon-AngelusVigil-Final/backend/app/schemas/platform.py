"""Schemas for the operational SOC platform APIs."""
from typing import Literal
from pydantic import BaseModel, Field

IncidentStatus = Literal["NEW", "QUEUED", "OPEN", "INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = ""
    severity: Severity = "MEDIUM"
    source_ip: str | None = None
    threat_id: str | None = None
    assigned_to: str | None = None
    status: IncidentStatus = "NEW"

class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assigned_to: str | None = None
    note: str | None = Field(default=None, max_length=1000)
    action: str | None = Field(default=None, max_length=1000)

class SimulationRequest(BaseModel):
    mode: Literal["normal", "sqli", "xss", "traversal", "cmdi", "scanner", "flood", "mixed"]
    count: int = Field(default=10, ge=1, le=100)
    delay_ms: int = Field(default=120, ge=0, le=2000)
