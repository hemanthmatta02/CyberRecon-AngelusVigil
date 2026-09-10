"""Team user model for the CyberSentinel demo RBAC layer."""

from sqlalchemy import Column, JSON
from sqlmodel import Field
from app.models.base import TimestampedModel


class User(TimestampedModel, table=True):
    __tablename__ = "users"

    username: str = Field(index=True, unique=True, max_length=80)
    password_hash: str = Field(max_length=255)
    role: str = Field(default="viewer", max_length=20)
    display_name: str = Field(default="Team Member", max_length=120)
    active: bool = Field(default=True)
    permissions: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
