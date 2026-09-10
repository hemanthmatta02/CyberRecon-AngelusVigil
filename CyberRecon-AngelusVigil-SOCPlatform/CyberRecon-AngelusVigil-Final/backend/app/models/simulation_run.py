"""Persistent record of controlled local attack simulations."""

from sqlalchemy import Column, JSON
from sqlmodel import Field

from app.models.base import TimestampedModel


class SimulationRun(TimestampedModel, table=True):
    __tablename__ = "simulation_runs"

    mode: str = Field(max_length=30)
    requested: int
    completed: int
    duration_ms: int
    target: str = Field(max_length=255)
    statuses: dict[str, int] = Field(sa_column=Column(JSON, nullable=False))
    result_note: str = ""
