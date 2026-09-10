"""Authentication, registration, recovery and RBAC helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.deps import get_session
from app.config import settings
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
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=2, max_length=120)
    role: Literal["analyst", "viewer"] = "viewer"


class ForgotPasswordRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)


class TeamCreate(RegistrationRequest):
    role: Literal["admin", "analyst", "viewer"] = "viewer"


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
    if not user or not user.active or not _check_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = _sign({"sub": user.username, "role": user.role, "exp": int(time.time()) + 8 * 3600})
    return LoginResponse(token=token, username=user.username, display_name=user.display_name, role=user.role, permissions=user.permissions)


@router.post("/register", status_code=201)
async def register(payload: RegistrationRequest, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    if not settings.allow_public_registration:
        raise HTTPException(status_code=403, detail="Public registration is disabled")
    await seed_users(session)
    if (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=_hash_password(payload.password), role=payload.role, display_name=payload.display_name, permissions=ROLES[payload.role])
    session.add(user)
    await session.commit()
    return {"status": "created", "username": user.username}


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
    return [{"id": str(u.id), "username": u.username, "display_name": u.display_name, "role": u.role, "active": u.active, "permissions": u.permissions} for u in rows]


@router.post("/team", status_code=201)
async def create_team_member(payload: TeamCreate, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor = current_user_from_request(request)
    if actor.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if (await session.execute(select(User).where(User.username == payload.username))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=_hash_password(payload.password), role=payload.role, display_name=payload.display_name, permissions=ROLES[payload.role])
    session.add(user)
    await session.commit(); await session.refresh(user)
    return {"id": str(user.id), "username": user.username, "display_name": user.display_name, "role": user.role, "active": user.active, "permissions": user.permissions}
