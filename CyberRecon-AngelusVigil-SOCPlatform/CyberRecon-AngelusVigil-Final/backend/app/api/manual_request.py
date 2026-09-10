"""Controlled manual HTTP request console for authorized lab targets."""
from __future__ import annotations

import ipaddress
import os
import secrets
from collections import deque
from urllib.parse import urlencode, urljoin, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.deps import get_session
from app.models.manual_request import ManualRequestRecord

router = APIRouter(prefix="/manual-request", tags=["manual-request"])
DEFAULT_TARGET = os.getenv("SIM_TARGET_URL", "http://devlog-nginx")
ALLOWED_HOSTS = {x.strip().lower() for x in os.getenv("MANUAL_ALLOWED_HOSTS", "devlog-nginx,vigil-devlog-nginx,localhost,127.0.0.1").split(",") if x.strip()}
ALLOWED_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"}
RECENT_LAB_IPS: deque[str] = deque(maxlen=64)

# These are harmless paths handled by the bundled local dev-log target.  They
# exercise a range of rule signatures without executing a payload anywhere.
LAB_REQUEST_PROFILES = (
    ("baseline", "GET", "/health", "CyberSentinel-Lab/1.0"),
    ("scanner", "GET", "/admin", "Nmap Scripting Engine"),
    ("path-traversal", "GET", "/..%2f..%2fetc%2fpasswd", "CyberSentinel-Lab/1.0"),
    ("sql-injection", "GET", "/api/search?q=1%20UNION%20SELECT%201", "CyberSentinel-Lab/1.0"),
    ("xss", "GET", "/api/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "CyberSentinel-Lab/1.0"),
    ("command-injection", "GET", "/api/search?q=%3Bid", "CyberSentinel-Lab/1.0"),
)
LAST_RANDOM_PROFILE: str | None = None

class ManualRequest(BaseModel):
    target_url: str = Field(default=DEFAULT_TARGET, min_length=1, max_length=1000)
    method: str = "GET"
    path: str = Field(default="/", max_length=500)
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, object] | None = None
    simulate_source_ip: bool = True
    randomize_request: bool = True


def _validate_target(target_url: str) -> str:
    parsed = urlparse(target_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Target must be a valid HTTP/HTTPS URL.")
    host = parsed.hostname.lower()
    allowed = host in ALLOWED_HOSTS
    try:
        ip = ipaddress.ip_address(host)
        allowed = allowed or ip.is_private or ip.is_loopback
    except ValueError:
        pass
    if not allowed:
        raise HTTPException(403, "Target is not allowlisted. Add it to MANUAL_ALLOWED_HOSTS for authorized testing.")
    return target_url.strip().rstrip("/")


def _lab_ip() -> str:
    # Avoid immediately reusing a source address so consecutive manual runs
    # remain distinct in the telemetry, SOC queue, and intelligence views.
    while True:
        candidate = f"10.10.{secrets.randbelow(250) + 1}.{secrets.randbelow(250) + 1}"
        if candidate not in RECENT_LAB_IPS:
            RECENT_LAB_IPS.append(candidate)
            return candidate


def _random_profile() -> tuple[str, str, str, str]:
    global LAST_RANDOM_PROFILE
    choices = tuple(profile for profile in LAB_REQUEST_PROFILES if profile[0] != LAST_RANDOM_PROFILE) or LAB_REQUEST_PROFILES
    selected = choices[secrets.randbelow(len(choices))]
    LAST_RANDOM_PROFILE = selected[0]
    return selected


@router.get("/history")
async def history(session: AsyncSession = Depends(get_session)) -> list[dict[str, object]]:
    rows=(await session.execute(select(ManualRequestRecord).order_by(ManualRequestRecord.created_at.desc()).limit(100))).scalars().all()
    return [{"id":str(r.id),"created_at":r.created_at.isoformat(),"target_url":r.target_url,"method":r.method,"path":r.path,"status_code":r.status_code,"reason":r.reason,"simulated_source_ip":r.simulated_source_ip} for r in rows]


@router.post("")
async def send_manual_request(payload: ManualRequest, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    target = _validate_target(payload.target_url)
    method = payload.method.upper()
    if method not in ALLOWED_METHODS:
        raise HTTPException(400, f"Method {method} is not enabled.")
    profile = "custom"
    profile_agent = "CyberSentinel-Lab/1.0"
    if payload.randomize_request:
        profile, method, path, profile_agent = _random_profile()
    else:
        path = payload.path if payload.path.startswith("/") else f"/{payload.path}"
    url = urljoin(f"{target}/", path.lstrip("/"))
    if payload.query: url = f"{url}?{urlencode(payload.query)}"
    headers={k:v for k,v in payload.headers.items() if len(k)<100 and len(v)<1000}
    header_names = {key.lower() for key in headers}
    if "user-agent" not in header_names:
        headers["User-Agent"] = profile_agent
    headers["X-CyberSentinel-Profile"] = profile
    simulated_ip=_lab_ip() if payload.simulate_source_ip else None
    if simulated_ip and "x-simulated-source-ip" not in header_names: headers["X-Simulated-Source-IP"]=simulated_ip
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response=await client.request(method,url,headers=headers,json=payload.body)
    except httpx.TimeoutException as exc:
        raise HTTPException(504, f"Target timeout after 15 seconds: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Target request failed: {exc}") from exc
    record=ManualRequestRecord(target_url=target,method=method,path=path,status_code=response.status_code,reason=response.reason_phrase,body_preview=response.text[:10000],response_headers=dict(response.headers),simulated_source_ip=simulated_ip)
    session.add(record); await session.commit(); await session.refresh(record)
    return {"id":str(record.id),"ok":response.is_success,"status_code":response.status_code,"reason":response.reason_phrase,"url":str(response.url),"headers":dict(response.headers),"body":response.text[:10000],"simulated_source_ip":simulated_ip,"profile":profile,"method":method,"path":path}
