"""CyberRecon API endpoints for authorized reconnaissance assessments."""

import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.core.recon.dns_enum import run_full_scan
from app.models.recon_scan import ReconScan
from app.models.vulnerability import VulnerabilityFinding
from app.schemas.recon import (
    ReconHistoryItem,
    ReconHistoryResponse,
    ReconRequest,
    ReconResponse,
)

router = APIRouter(prefix="/recon", tags=["CyberRecon"])


@router.post("/scan", response_model=ReconResponse)
async def start_recon(
    payload: ReconRequest,
    session: AsyncSession = Depends(get_session),
) -> ReconResponse:
    """Run a bounded authorized reconnaissance assessment."""
    if not payload.domain.strip():
        raise HTTPException(status_code=400, detail="Target is required.")

    ports = tuple(payload.ports)
    if payload.include_ports and not ports:
        # Safe/common baseline. The engine caps the total count.
        from app.core.recon.dns_enum import DEFAULT_PORTS
        ports = DEFAULT_PORTS

    started = time.perf_counter()
    try:
        result = await run_full_scan(
            payload.domain,
            include_subdomains=payload.include_subdomains,
            include_ports=payload.include_ports,
            include_http=payload.include_http,
            ports=ports,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Recon failed: {exc}") from exc

    duration_ms = round((time.perf_counter() - started) * 1000)
    result["summary"]["duration_ms"] = duration_ms

    history = ReconScan(
        target=result["target"],
        scan_type="full",
        status="completed",
        duration_ms=duration_ms,
        authorized_use=True,
        result=result,
        completed_at=datetime.now(timezone.utc),
    )
    session.add(history)
    for finding in result.get("vulnerabilities", []):
        session.add(VulnerabilityFinding(
            target=result["target"], name=finding["name"], description=finding["description"],
            asset=finding["affected_asset"], severity=finding["severity"],
            evidence=finding["evidence"], recommendation=finding["recommended_fix"],
            status=finding.get("status", "OPEN"), category=finding.get("category", "MISCONFIGURATION"),
        ))
    await session.commit()

    return ReconResponse.model_validate(result)


@router.get("/history", response_model=ReconHistoryResponse)
async def recon_history(
    limit: int = Query(default=20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> ReconHistoryResponse:
    query = select(ReconScan).order_by(ReconScan.created_at.desc()).limit(limit)
    result = await session.execute(query)
    rows = result.scalars().all()
    items = [
        ReconHistoryItem(
            id=str(row.id),
            target=row.target,
            scan_type=row.scan_type,
            status=row.status,
            duration_ms=row.duration_ms,
            authorized_use=row.authorized_use,
            created_at=row.created_at.isoformat(),
            completed_at=row.completed_at.isoformat() if row.completed_at else None,
        )
        for row in rows
    ]
    return ReconHistoryResponse(total=len(items), items=items)


@router.get("/history/{scan_id}", response_model=ReconResponse)
async def recon_history_item(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ReconResponse:
    row = await session.get(ReconScan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recon scan not found.")
    return ReconResponse.model_validate(row.result)
