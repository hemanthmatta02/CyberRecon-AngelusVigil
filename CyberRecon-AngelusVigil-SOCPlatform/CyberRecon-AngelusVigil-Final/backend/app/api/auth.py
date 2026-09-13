"""Authentication, registration, recovery and RBAC helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.deps import get_session
from app.config import settings
from app.models.team_access import TeamInvite, UserApproval
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["authentication"])
SECRET = settings.auth_secret or "cybersentinel-local-demo-secret-change-me"
ROLES = {
    "admin": ["read", "scan", "manage_alerts", "manage_incidents", "manage_team", "reports"],
    "analyst": ["read", "scan", "manage_alerts", "manage_incidents", "reports"],
    "viewer": ["read", "reports"],
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=6, max_length=128)


class LoginResponse(BaseModel):
    token: str
    username: str
    display_name: str
    role: str
    permissions: list[str]


class RegistrationRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=2, max_length=120)
    role: Literal["analyst", "viewer"] = "viewer"
    invite_token: str | None = Field(default=None, min_length=16, max_length=256)


class ForgotPasswordRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)


class TeamCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=2, max_length=120)
    email: str | None = Field(default=None, max_length=255)
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class InviteCreate(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)
    role: Literal["analyst", "viewer"] = "viewer"
    expires_in_days: int = Field(default=7, ge=1, le=30)


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return base64.urlsafe_b64encode(salt + digest).decode()


def _check_password(password: str, stored: str) -> bool:
    raw = base64.urlsafe_b64decode(stored.encode())
    salt, digest = raw[:16], raw[16:]
    probe = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return hmac.compare_digest(digest, probe)


def _sign(payload: dict[str, object]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"CS.{body}.{sig}"


def verify_token(token: str) -> dict[str, object]:
    try:
        prefix, body, sig = token.split(".", 2)
        expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if prefix != "CS" or not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode((body + "===").encode()))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def current_user_from_request(request: Request) -> dict[str, object]:
    """Resolve a bearer token, with demo auth allowed only in development."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return verify_token(header[7:].strip())
    if settings.allow_demo_auth and settings.env.lower() != "production":
        return {
            "sub": "demo-admin",
            "role": "admin",
            "display_name": "Demo Administrator",
            "permissions": ROLES["admin"],
        }
    raise HTTPException(status_code=401, detail="Authentication required")


def _require_admin(request: Request) -> dict[str, object]:
    actor = current_user_from_request(request)
    if actor.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return actor


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _normalise_email(value: str | None, required: bool = True) -> str | None:
    cleaned = (value or "").strip().lower()
    if not cleaned:
        if required:
            raise HTTPException(status_code=422, detail="Email is required")
        return None
    if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", cleaned):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return cleaned


def _user_payload(user: User, approval_status: str | None = None) -> dict[str, object]:
    if approval_status is None:
        approval_status = "approved" if user.active else "inactive"
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "active": user.active,
        "approval_status": approval_status,
        "permissions": user.permissions,
    }


async def seed_users(session: AsyncSession) -> None:
    existing = (await session.execute(select(User).limit(1))).scalar_one_or_none()
    if existing:
        return
    defaults = {
        "admin": os.getenv("DEFAULT_ADMIN_PASSWORD", ""),
        "analyst": os.getenv("DEFAULT_ANALYST_PASSWORD", ""),
        "viewer": os.getenv("DEFAULT_VIEWER_PASSWORD", ""),
    }
    if settings.env.lower() == "production" and any(not password for password in defaults.values()):
        raise RuntimeError("DEFAULT_*_PASSWORD values must be configured before first production startup")
    if settings.env.lower() != "production":
        defaults = {
            "admin": defaults["admin"] or "Admin@123",
            "analyst": defaults["analyst"] or "Analyst@123",
            "viewer": defaults["viewer"] or "Viewer@123",
        }
    for username, role, display in [
        ("admin", "admin", "SOC Administrator"),
        ("analyst", "analyst", "SOC Analyst"),
        ("viewer", "viewer", "Security Viewer"),
    ]:
        session.add(User(username=username, password_hash=_hash_password(defaults[role]), role=role, display_name=display, permissions=ROLES[role]))
    await session.commit()


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_session)) -> LoginResponse:
    await seed_users(session)
    user = (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()
    if not user or not _check_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    approval = (await session.execute(select(UserApproval).where(UserApproval.user_id == user.id))).scalar_one_or_none()
    if approval and approval.status == "pending":
        raise HTTPException(status_code=403, detail="Account is pending admin approval")
    if not user.active:
        raise HTTPException(status_code=403, detail="Account is not active")
    token = _sign({"sub": user.username, "role": user.role, "exp": int(time.time()) + 8 * 3600})
    return LoginResponse(token=token, username=user.username, display_name=user.display_name, role=user.role, permissions=user.permissions)


@router.post("/register", status_code=201)
async def register(payload: RegistrationRequest, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    invite: TeamInvite | None = None
    if not settings.allow_public_registration and not payload.invite_token:
        raise HTTPException(status_code=403, detail="Public registration is disabled; use an admin invitation")
    await seed_users(session)
    email = _normalise_email(payload.email)
    if (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")
    if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists")

    if payload.invite_token:
        invite = (await session.execute(select(TeamInvite).where(TeamInvite.token_hash == _hash_invite_token(payload.invite_token)))).scalar_one_or_none()
        if not invite or invite.used_at is not None or invite.expires_at <= _utc_now():
            raise HTTPException(status_code=400, detail="Invitation is invalid or expired")

    role = invite.role if invite else payload.role
    user = User(
        username=payload.username,
        email=email,
        password_hash=_hash_password(payload.password),
        role=role,
        display_name=payload.display_name.strip(),
        active=invite is not None,
        permissions=ROLES[role],
    )
    session.add(user)
    await session.flush()
    if invite:
        invite.used_at = _utc_now()
    else:
        session.add(UserApproval(user_id=user.id, status="pending"))
    await session.commit()
    if invite:
        return {"status": "created", "username": user.username, "message": "Invitation accepted. You can sign in now."}
    return {"status": "pending", "username": user.username, "message": "Registration submitted for admin approval."}


@router.get("/invites/{token}")
async def preview_invite(token: str, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    invite = (await session.execute(select(TeamInvite).where(TeamInvite.token_hash == _hash_invite_token(token)))).scalar_one_or_none()
    if not invite or invite.used_at is not None or invite.expires_at <= _utc_now():
        raise HTTPException(status_code=404, detail="Invitation is invalid or expired")
    return {"display_name": invite.display_name, "role": invite.role, "expires_at": invite.expires_at}


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    await seed_users(session)
    user = (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()
    # Do not reveal whether an account exists. This endpoint only acknowledges the request.
    if user:
        user.password_hash = user.password_hash
    return {"status": "accepted"}


@router.get("/me")
async def me(request: Request) -> dict[str, object]:
    return current_user_from_request(request)


@router.get("/team")
async def team(request: Request, session: AsyncSession = Depends(get_session)) -> list[dict[str, object]]:
    current_user_from_request(request)
    await seed_users(session)
    rows = (await session.execute(select(User).order_by(User.username))).scalars().all()
    approval_rows = (await session.execute(select(UserApproval))).scalars().all()
    approval_by_user = {str(item.user_id): item.status for item in approval_rows}
    return [_user_payload(user, approval_by_user.get(str(user.id))) for user in rows]


@router.get("/team/pending")
async def pending_team_members(request: Request, session: AsyncSession = Depends(get_session)) -> list[dict[str, object]]:
    _require_admin(request)
    rows = (await session.execute(
        select(User, UserApproval)
        .join(UserApproval, UserApproval.user_id == User.id)
        .where(UserApproval.status == "pending")
        .order_by(UserApproval.created_at)
    )).all()
    return [_user_payload(user, approval.status) for user, approval in rows]


@router.post("/team/{user_id}/approve")
async def approve_team_member(user_id: str, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor = _require_admin(request)
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="User not found") from exc
    user = (await session.execute(select(User).where(User.id == parsed_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    approval = (await session.execute(select(UserApproval).where(UserApproval.user_id == user.id))).scalar_one_or_none()
    if approval is None:
        approval = UserApproval(user_id=user.id)
        session.add(approval)
    approval.status = "approved"
    approval.reviewed_by = str(actor.get("sub", "admin"))
    approval.reviewed_at = _utc_now()
    user.active = True
    await session.commit()
    return _user_payload(user, "approved")


@router.post("/team/{user_id}/reject")
async def reject_team_member(user_id: str, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor = _require_admin(request)
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="User not found") from exc
    user = (await session.execute(select(User).where(User.id == parsed_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    approval = (await session.execute(select(UserApproval).where(UserApproval.user_id == user.id))).scalar_one_or_none()
    if approval is None:
        approval = UserApproval(user_id=user.id)
        session.add(approval)
    approval.status = "rejected"
    approval.reviewed_by = str(actor.get("sub", "admin"))
    approval.reviewed_at = _utc_now()
    user.active = False
    await session.commit()
    return _user_payload(user, "rejected")


@router.get("/team/invites")
async def list_team_invites(request: Request, session: AsyncSession = Depends(get_session)) -> list[dict[str, object]]:
    _require_admin(request)
    now = _utc_now()
    rows = (await session.execute(
        select(TeamInvite)
        .where(TeamInvite.used_at.is_(None), TeamInvite.expires_at > now)
        .order_by(TeamInvite.created_at.desc())
    )).scalars().all()
    return [
        {"id": str(invite.id), "display_name": invite.display_name, "role": invite.role, "created_by": invite.created_by, "expires_at": invite.expires_at}
        for invite in rows
    ]


@router.post("/team/invites", status_code=201)
async def create_team_invite(payload: InviteCreate, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor = _require_admin(request)
    raw_token = secrets.token_urlsafe(32)
    expires_at = _utc_now() + timedelta(days=payload.expires_in_days)
    invite = TeamInvite(
        token_hash=_hash_invite_token(raw_token),
        display_name=payload.display_name.strip(),
        role=payload.role,
        created_by=str(actor.get("sub", "admin")),
        expires_at=expires_at,
    )
    session.add(invite)
    await session.commit()
    return {"token": raw_token, "display_name": invite.display_name, "role": invite.role, "expires_at": invite.expires_at}


@router.post("/team", status_code=201)
async def create_team_member(payload: TeamCreate, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    _require_admin(request)
    email = _normalise_email(payload.email, required=False)
    if (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")
    if email and (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(username=payload.username, email=email, password_hash=_hash_password(payload.password), role=payload.role, display_name=payload.display_name, permissions=ROLES[payload.role])
    session.add(user)
    await session.commit(); await session.refresh(user)
    return _user_payload(user, "approved")
