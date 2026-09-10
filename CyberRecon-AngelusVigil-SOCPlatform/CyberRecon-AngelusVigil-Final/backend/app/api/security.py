"""Security assessment, alert management, searchable telemetry and reports."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import current_user_from_request
from app.api.deps import get_session
from app.models.alert_record import AlertRecord
from app.models.incident import Incident
from app.models.recon_scan import ReconScan
from app.models.threat_event import ThreatEvent
from app.models.vulnerability import VulnerabilityFinding
from app.core.recon.dns_enum import run_full_scan

router = APIRouter(prefix="/security", tags=["security"])


def _classify(event: ThreatEvent) -> str:
    text = (event.request_path + " " + " ".join(event.matched_rules or [])).lower()
    mapping = [("sql", "SQL Injection"), ("xss", "XSS"), ("travers", "Path Traversal"), ("cmd", "Command Injection"), ("ssrf", "SSRF"), ("brute", "Brute Force"), ("bot", "Bot Activity"), ("scan", "Port Scanning")]
    for key, label in mapping:
        if key in text:
            return label
    if event.status_code in {401, 403} and "login" in text:
        return "Brute Force"
    return "Suspicious Web Activity"


def _finding_dict(row: VulnerabilityFinding) -> dict[str, object]:
    return {"id": str(row.id), "created_at": row.created_at.isoformat(), "target": row.target, "name": row.name, "description": row.description, "affected_asset": row.asset, "severity": row.severity, "evidence": row.evidence, "recommended_fix": row.recommendation, "status": row.status, "category": row.category, "metadata": row.finding_metadata}

@router.get("/threat-classifications")
async def threat_classifications(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    rows = (await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(500))).scalars().all()
    counts: dict[str, int] = {}
    items = []
    for row in rows:
        kind = _classify(row); counts[kind] = counts.get(kind, 0) + 1
        items.append({"id": str(row.id), "time": row.created_at.isoformat(), "type": kind, "ip": row.source_ip, "path": row.request_path, "severity": row.severity, "score": round(row.threat_score, 3), "rules": row.matched_rules or []})
    return {"counts": counts, "items": items[:100]}

@router.get("/alerts")
async def alerts(
    session: AsyncSession = Depends(get_session),
    severity: str | None = None,
    q: str | None = None,
    classification: str | None = None,
) -> list[dict[str, object]]:
    rows = (await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(300))).scalars().all()
    records = {str(r.threat_id): r for r in (await session.execute(select(AlertRecord))).scalars().all()}
    incidents = {str(i.threat_id): i for i in (await session.execute(select(Incident).where(Incident.threat_id.is_not(None)))).scalars().all()}
    out=[]
    for event in rows:
        if severity and event.severity != severity: continue
        event_type = _classify(event)
        searchable = f"{event.source_ip} {event.request_path} {event_type} {' '.join(event.matched_rules or [])}".lower()
        if q and q.lower() not in searchable: continue
        if classification and event_type != classification: continue
        rec=records.get(str(event.id))
        incident = incidents.get(str(event.id))
        out.append({"id": str(event.id), "time": event.created_at.isoformat(), "ip": event.source_ip, "request": f"{event.request_method} {event.request_path}", "type": event_type, "severity": rec.severity_override if rec and rec.severity_override else event.severity, "score": event.threat_score, "acknowledged": bool(rec and rec.acknowledged), "resolved": bool(rec and rec.resolved), "assigned_to": rec.assigned_to if rec else None, "comment": rec.comment if rec else "", "feedback": event.review_label, "rules": event.matched_rules or [], "incident_id": str(incident.id) if incident else None, "incident_status": incident.status if incident else None})
    return out

@router.patch("/alerts/{threat_id}")
async def update_alert(threat_id: uuid.UUID, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor = current_user_from_request(request)
    if actor.get("role") == "viewer": raise HTTPException(status_code=403, detail="Analyst or admin role required")
    event = await session.get(ThreatEvent, threat_id)
    if not event: raise HTTPException(status_code=404, detail="Alert not found")
    payload = await request.json()
    rec = (await session.execute(select(AlertRecord).where(AlertRecord.threat_id == threat_id))).scalar_one_or_none()
    if not rec:
        rec = AlertRecord(threat_id=threat_id); session.add(rec)
    if "acknowledged" in payload: rec.acknowledged = bool(payload["acknowledged"]); rec.actions = [*rec.actions, f"{actor.get('sub')} acknowledged={rec.acknowledged}"]
    if "resolved" in payload: rec.resolved = bool(payload["resolved"]); rec.actions = [*rec.actions, f"{actor.get('sub')} resolved={rec.resolved}"]
    if "assigned_to" in payload: rec.assigned_to = payload.get("assigned_to"); rec.actions = [*rec.actions, f"assigned to {rec.assigned_to}"]
    if "severity" in payload: rec.severity_override = payload.get("severity"); rec.actions = [*rec.actions, f"severity changed to {rec.severity_override}"]
    if "comment" in payload: rec.comment = str(payload.get("comment") or "")
    if payload.get("feedback") in {"TRUE_POSITIVE", "FALSE_POSITIVE"}:
        event.reviewed = True
        event.review_label = payload["feedback"]
        rec.actions = [*rec.actions, f"feedback={event.review_label}"]
    await session.commit(); await session.refresh(rec)
    return {"status": "updated", "actions": rec.actions, "acknowledged": rec.acknowledged, "resolved": rec.resolved, "assigned_to": rec.assigned_to, "severity": rec.severity_override or event.severity, "comment": rec.comment}

@router.get("/vulnerabilities")
async def vulnerabilities(session: AsyncSession = Depends(get_session), status: str | None = None, severity: str | None = None) -> list[dict[str, object]]:
    query = select(VulnerabilityFinding).order_by(VulnerabilityFinding.created_at.desc()).limit(500)
    if status: query = query.where(VulnerabilityFinding.status == status)
    if severity: query = query.where(VulnerabilityFinding.severity == severity)
    return [_finding_dict(r) for r in (await session.execute(query)).scalars().all()]

@router.patch("/vulnerabilities/{finding_id}")
async def update_vulnerability(finding_id: uuid.UUID, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor=current_user_from_request(request)
    if actor.get("role") == "viewer": raise HTTPException(status_code=403, detail="Analyst or admin role required")
    row=await session.get(VulnerabilityFinding,finding_id)
    if not row: raise HTTPException(status_code=404, detail="Finding not found")
    payload=await request.json()
    if payload.get("status") in {"OPEN","RESOLVED","ACCEPTED"}: row.status=payload["status"]
    await session.commit(); await session.refresh(row)
    return _finding_dict(row)

@router.post("/vulnerability-scan")
async def vulnerability_scan(request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    actor=current_user_from_request(request)
    if actor.get("role") == "viewer": raise HTTPException(status_code=403, detail="Analyst or admin role required")
    payload=await request.json(); target=str(payload.get("target", "")).strip()
    if not target: raise HTTPException(status_code=400, detail="Target is required")
    result=await run_full_scan(target, include_subdomains=False, include_ports=False, include_http=True, ports=())
    findings=[]
    for item in result.get("vulnerabilities", []):
        row=VulnerabilityFinding(target=result["target"], name=item["name"], description=item["description"], asset=item["affected_asset"], severity=item["severity"], evidence=item["evidence"], recommendation=item["recommended_fix"], status=item["status"], category=item.get("category", "MISCONFIGURATION"))
        session.add(row); findings.append(row)
    await session.commit()
    return {"target": result["target"], "count": len(findings), "findings": [_finding_dict(x) for x in findings]}

@router.get("/search")
async def search(session: AsyncSession = Depends(get_session), q: str | None = None, severity: str | None = None, days: int = Query(30, ge=1, le=365)) -> dict[str, object]:
    cutoff=datetime.now(UTC)-timedelta(days=days)
    query=select(ThreatEvent).where(ThreatEvent.created_at>=cutoff).order_by(ThreatEvent.created_at.desc()).limit(500)
    if severity: query=query.where(ThreatEvent.severity==severity)
    events=(await session.execute(query)).scalars().all()
    if q:
        needle=q.lower(); events=[e for e in events if needle in f"{e.source_ip} {e.request_path} {' '.join(e.matched_rules or [])}".lower()]
    return {"count":len(events),"items":[{"id":str(e.id),"time":e.created_at.isoformat(),"ip":e.source_ip,"path":e.request_path,"severity":e.severity,"score":e.threat_score} for e in events]}

@router.get("/reports/export/{fmt}")
async def report_export(fmt: Literal["json","csv","pdf"], target: str | None = None, session: AsyncSession = Depends(get_session)) -> Response:
    threats=(await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(500))).scalars().all()
    vulns=(await session.execute(select(VulnerabilityFinding).order_by(VulnerabilityFinding.created_at.desc()).limit(500))).scalars().all()
    incidents=(await session.execute(select(Incident).order_by(Incident.created_at.desc()).limit(200))).scalars().all()
    payload={"generated_at":datetime.now(UTC).isoformat(),"target":target,"assets":[r.target for r in (await session.execute(select(ReconScan).order_by(ReconScan.created_at.desc()).limit(50))).scalars().all()],"threats":[{"id":str(t.id),"time":t.created_at.isoformat(),"ip":t.source_ip,"path":t.request_path,"type":_classify(t),"severity":t.severity,"score":t.threat_score,"evidence":t.matched_rules or []} for t in threats],"vulnerabilities":[_finding_dict(v) for v in vulns],"incidents":[{"id":str(i.id),"title":i.title,"severity":i.severity,"status":i.status,"assigned_to":i.assigned_to} for i in incidents]}
    if fmt=="json": return Response(json.dumps(payload,indent=2),media_type="application/json",headers={"Content-Disposition":"attachment; filename=cybersentinel-report.json"})
    if fmt=="csv":
        out=io.StringIO(); w=csv.writer(out); w.writerow(["time","ip","path","type","severity","score"])
        for t in payload["threats"]: w.writerow([t["time"],t["ip"],t["path"],t["type"],t["severity"],t["score"]])
        return Response(out.getvalue(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=cybersentinel-threats.csv"})
    # Minimal self-contained PDF generated without an extra dependency.
    lines=["CYBERSENTINEL SECURITY REPORT",f"Generated: {payload['generated_at']}",f"Threats: {len(payload['threats'])}",f"Vulnerabilities: {len(payload['vulnerabilities'])}",f"Incidents: {len(payload['incidents'])}","","Severity / Type summary:"]
    counts={}
    for t in payload["threats"]: counts[t["severity"]]=counts.get(t["severity"],0)+1
    for k,v in counts.items(): lines.append(f"{k}: {v}")
    def esc(x:str)->str: return x.replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
    y=760; stream="BT /F1 12 Tf 45 780 Td 14 TL\n"
    for line in lines[:42]: stream += f"({esc(line[:105])}) Tj T*\n"
    stream += "ET"
    objects=[]
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream")
    pdf=b"%PDF-1.4\n"; offsets=[]
    for i,obj in enumerate(objects,1): offsets.append(len(pdf)); pdf += f"{i} 0 obj\n{obj}\nendobj\n".encode()
    xref=len(pdf); pdf+=f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode(); pdf += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets); pdf+=f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return Response(pdf,media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=cybersentinel-report.pdf"})
