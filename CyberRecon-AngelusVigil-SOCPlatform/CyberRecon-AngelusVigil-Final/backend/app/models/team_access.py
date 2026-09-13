"""Approval and invitation records for team access management."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime
from sqlmodel import Field

from app.models.base import TimestampedModel


class UserApproval(TimestampedModel, table=True):
    """Track the review state for self-registered users."""

    __tablename__ = "user_approvals"

    user_id: uuid.UUID = Field(foreign_key="users.id", index=True, unique=True)
    status: str = Field(default="pending", index=True, max_length=20)
    reviewed_by: str | None = Field(default=None, max_length=80)
    reviewed_at: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        nullable=True,
    )
    note: str | None = Field(default=None, max_length=500)


class TeamInvite(TimestampedModel, table=True):
    """One-time, hashed invitation tokens issued by an administrator."""

    __tablename__ = "team_invites"

    token_hash: str = Field(index=True, unique=True, max_length=64)
    display_name: str = Field(max_length=120)
    role: str = Field(default="viewer", max_length=20)
    created_by: str = Field(max_length=80)
    expires_at: datetime = Field(
        sa_type=DateTime(timezone=True),
        nullable=False,
    )
    used_at: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        nullable=True,
    )
