"""Operational APIs for the separate CyberSentinel SOC workspaces."""
from __future__ import annotations

import asyncio
import os
import secrets
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import current_user_from_request
from app.api.deps import get_session
from app.models.incident import Incident
from app.models.recon_scan import ReconScan
from app.models.simulation_run import SimulationRun
from app.models.threat_event import ThreatEvent
from app.schemas.platform import IncidentCreate, IncidentUpdate, SimulationRequest

router = APIRouter(prefix="/platform", tags=["platform"])

INTELLIGENCE_SOURCE_NOTES: dict[str, str] = {
    "telemetry": "Live nginx telemetry is retained locally and scored by the detection pipeline.",
    "recon": "Technology and DNS observations are populated by authorized CyberRecon scans.",
    "findings": "CVE and exposure counts come from local vulnerability assessment findings.",
}


def _window(hours: int = 24) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


async def _threat_counts(session: AsyncSession, cutoff: datetime) -> dict[str, int]:
    rows = (await session.execute(select(ThreatEvent.severity, func.count()).where(ThreatEvent.created_at >= cutoff).group_by(ThreatEvent.severity))).all()
    return {str(severity): int(count) for severity, count in rows}


@router.get("/overview")
async def overview(request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    cutoff = _window(24)
    counts = await _threat_counts(session, cutoff)
    open_incidents = (await session.execute(select(func.count()).select_from(Incident).where(Incident.status.in_(["NEW", "QUEUED", "OPEN", "INVESTIGATING", "ESCALATED"])))).scalar_one()
    recent = (await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(12))).scalars().all()
    buckets: dict[datetime, int] = {
        cutoff.replace(minute=0, second=0, microsecond=0) + timedelta(hours=hour): 0
        for hour in range(25)
    }
    for event in recent:
        created = event.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        hour = created.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        if hour in buckets:
            buckets[hour] += 1
    timeline = [
        {"label": hour.strftime("%H:%M"), "value": count, "time": hour.isoformat()}
        for hour, count in sorted(buckets.items())
    ]
    pipeline = getattr(request.app.state, "pipeline", None)
    return {"window":"24h", "threats":sum(counts.values()), "critical":counts.get("CRITICAL",0), "high":counts.get("HIGH",0), "medium":counts.get("MEDIUM",0), "low":counts.get("LOW",0), "open_incidents":int(open_incidents), "live_requests":int(getattr(pipeline,"stats",{}).get("parsed",0)) if pipeline else 0, "recent_events":[{"id":str(e.id),"time":e.created_at.isoformat(),"ip":e.source_ip,"method":e.request_method,"path":e.request_path,"score":round(e.threat_score,3),"severity":e.severity,"rules":e.matched_rules or []} for e in recent], "threat_timeline":timeline, "pipeline":{"running":bool(getattr(request.app.state,"pipeline_running",False)),"stats":getattr(pipeline,"stats",{}) if pipeline else {}}}


def _event_detection_type(event: ThreatEvent) -> str:
    """Describe the evidence actually available for a stored event."""
    rules = event.matched_rules or []
    components = event.component_scores or {}
    if rules and event.model_version == "hybrid":
        return "HYBRID"
    if rules:
        return "SIGNATURE"
    if components.get("ae", 0.0) >= 0.6:
        return "ANOMALY"
    if components:
        return "BEHAVIOURAL"
    return "OBSERVATION"


@router.get("/detection")
async def detection(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    events = (await session.execute(select(ThreatEvent).where(ThreatEvent.created_at >= _window(24)).order_by(ThreatEvent.created_at.asc()).limit(1000))).scalars().all()
    rules: Counter[str] = Counter(); ips: Counter[str] = Counter()
    timeline = [{"id":str(e.id),"time":e.created_at.isoformat(),"ip":e.source_ip,"method":e.request_method,"path":e.request_path,"score":round(e.threat_score,3),"severity":e.severity,"detection_type":_event_detection_type(e),"status":"DETECTED","response_action":"Operation created in SOC","rules":e.matched_rules or []} for e in events]
    for e in events: rules.update(e.matched_rules or []); ips[e.source_ip] += 1
    return {"events":len(events),"high_confidence":sum(e.threat_score>=0.80 for e in events),"average_score":round(sum(e.threat_score for e in events)/len(events),3) if events else 0,"rule_hits":[{"name":k,"count":v} for k,v in rules.most_common(10)],"top_sources":[{"ip":k,"count":v} for k,v in ips.most_common(10)],"timeline":timeline[-100:]}


@router.get("/intelligence")
async def intelligence(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    events = (await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(500))).scalars().all()
    vulns = (await session.execute(select(func.count()).select_from(__import__('app.models.vulnerability', fromlist=['VulnerabilityFinding']).VulnerabilityFinding))).scalar_one()
    recon = (await session.execute(select(ReconScan).order_by(ReconScan.created_at.desc()).limit(100))).scalars().all()
    ip_groups: dict[str,list[ThreatEvent]] = {}
    for e in events: ip_groups.setdefault(e.source_ip, []).append(e)
    ip_rep=[]
    for ip, rows in sorted(ip_groups.items(), key=lambda x: max(e.threat_score for e in x[1]), reverse=True)[:50]:
        peak=max(e.threat_score for e in rows); rep="MALICIOUS" if peak>=0.85 or len(rows)>=5 else "SUSPICIOUS" if peak>=0.60 or len(rows)>=2 else "LOW_RISK"
        geo=[e.geo_country for e in rows if e.geo_country]
        ip_rep.append({"ip":ip,"reputation":rep,"confidence":round(min(.99,.45+peak*.45+min(len(rows),10)*.01),2),"observations":len(rows),"country":geo[0] if geo else None,"last_seen":max(e.created_at for e in rows).isoformat()})
    dns_records=0; http_endpoints=0; technologies: Counter[str] = Counter(); subdomains=0
    for row in recon:
        result=row.result or {}; dns_records += sum(len(v) for v in (result.get("dns",{}).get("records",{}) or {}).values()); http_endpoints += len([h for h in result.get("http",[]) if h.get("status_code") is not None]); subdomains += int(result.get("summary",{}).get("subdomain_count",0)); technologies.update(t for h in result.get("http",[]) for t in h.get("technologies",[]))
    data_sources = [
        {"id": "telemetry", "name": "Observed telemetry", "status": "ACTIVE", "coverage": f"{len(events)} retained events", "note": INTELLIGENCE_SOURCE_NOTES["telemetry"]},
        {"id": "recon", "name": "Authorized recon", "status": "ACTIVE" if recon else "WAITING", "coverage": f"{len(recon)} completed scans", "note": INTELLIGENCE_SOURCE_NOTES["recon"]},
        {"id": "findings", "name": "Vulnerability findings", "status": "ACTIVE" if vulns else "WAITING", "coverage": f"{vulns} local findings", "note": INTELLIGENCE_SOURCE_NOTES["findings"]},
    ]
    inventory = [{"name": name, "observations": count} for name, count in technologies.most_common(50)]
    return {"source":"Local observed telemetry + persisted authorized recon results","counts":{"ip_reputation":len(ip_rep),"dns_records":dns_records,"whois":0,"cve_findings":int(vulns),"geolocated_ips":sum(bool(x.get('country')) for x in ip_rep),"technologies":len(technologies),"subdomains":subdomains},"external_feeds":{"whois":"Not configured for this local lab","ip_reputation":"Derived from observed telemetry","cve":"Derived from local assessment findings"},"data_sources":data_sources,"indicators":ip_rep,"technology_inventory":inventory,"recent_targets":[r.target for r in recon[:20]]}


@router.patch("/intelligence/sources/{source_id}")
async def update_intelligence_source(source_id: str, request: Request) -> dict[str, str]:
    if source_id not in INTELLIGENCE_SOURCE_NOTES:
        raise HTTPException(404, "Unknown intelligence source")
    payload = await request.json()
    note = str(payload.get("note", "")).strip()
    if not note or len(note) > 1000:
        raise HTTPException(400, "A note between 1 and 1000 characters is required")
    INTELLIGENCE_SOURCE_NOTES[source_id] = note
    return {"id": source_id, "note": note}


@router.get("/ml")
async def ml_status(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    events=(await session.execute(select(ThreatEvent).order_by(ThreatEvent.created_at.desc()).limit(300))).scalars().all()
    modes=Counter(_event_detection_type(e) for e in events)
    reasons=[]
    for e in events[:20]:
        pieces=[]
        if e.matched_rules: pieces.append("Rules: " + ", ".join(e.matched_rules[:3]))
        if e.component_scores: pieces.append("Components: " + ", ".join(f"{k}={v:.2f}" for k,v in e.component_scores.items()))
        reasons.append({"id":str(e.id),"time":e.created_at.isoformat(),"reason":"; ".join(pieces) or "No component evidence recorded.","score":round(e.threat_score,3),"severity":e.severity,"mode":_event_detection_type(e)})
    return {"detection_mode":"HYBRID" if modes.get("HYBRID") else "RULE","events_sampled":len(events),"ml_component_observations":sum(len(e.component_scores) for e in events),"average_component_score":round(sum(sum(e.component_scores.values()) for e in events)/max(1,sum(len(e.component_scores) for e in events)),3),"anomaly_events":sum(_event_detection_type(e)=="ANOMALY" for e in events),"mode_counts":dict(modes),"explanations":reasons}


@router.get("/soc")
async def soc(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    rows=(await session.execute(select(Incident).order_by(Incident.created_at.desc()).limit(100))).scalars().all()
    status_counts=Counter(i.status for i in rows); sev_counts=Counter(i.severity for i in rows)
    return {"open":sum(status_counts[s] for s in ["NEW","QUEUED","OPEN","INVESTIGATING","ESCALATED"]),"status":{s:status_counts[s] for s in ["NEW","QUEUED","OPEN","INVESTIGATING","ESCALATED","RESOLVED","CLOSED"]},"severity":dict(sev_counts),"queue":sum(status_counts[s] for s in ["NEW","QUEUED"]),"analyst_workflow":["NEW → QUEUED","QUEUED → OPEN","OPEN → INVESTIGATING","INVESTIGATING → ESCALATED","INVESTIGATING → RESOLVED","RESOLVED → CLOSED"]}


@router.get("/assets")
async def assets(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    rows=(await session.execute(select(ReconScan).order_by(ReconScan.created_at.desc()).limit(100))).scalars().all(); seen=set(); items=[]
    for row in rows:
        target=row.target
        if target in seen: continue
        seen.add(target); result=row.result or {}; summary=result.get("summary",{})
        items.append({"target":target,"status":row.status,"authorized":row.authorized_use,"created_at":row.created_at.isoformat(),"subdomains":summary.get("subdomain_count",0),"open_ports":summary.get("open_port_count",0),"http":bool(result.get("http")),"error":row.error})
    return {"total_targets":len(items),"successful_scans":sum(i["status"]=="completed" for i in items),"assets":items}


@router.get("/reports")
async def reports(session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    return {"generated_at":datetime.now(UTC).isoformat(),"last_24h_threats":int((await session.execute(select(func.count()).select_from(ThreatEvent).where(ThreatEvent.created_at>=_window(24)))).scalar_one()),"incidents_total":int((await session.execute(select(func.count()).select_from(Incident))).scalar_one()),"recon_scans_total":int((await session.execute(select(func.count()).select_from(ReconScan))).scalar_one()),"formats":["JSON","CSV","PDF"]}


@router.get("/incidents")
async def list_incidents(session: AsyncSession = Depends(get_session), status: str | None = Query(None)) -> list[dict[str, object]]:
    query=select(Incident).order_by(Incident.created_at.desc()).limit(100)
    if status: query=query.where(Incident.status==status)
    return [_incident_dict(x) for x in (await session.execute(query)).scalars().all()]


def _incident_dict(row: Incident)->dict[str,object]:
    return {"id":str(row.id),"created_at":row.created_at.isoformat(),"title":row.title,"description":row.description,"severity":row.severity,"status":row.status,"assigned_to":row.assigned_to,"source_ip":row.source_ip,"threat_id":str(row.threat_id) if row.threat_id else None,"notes":row.notes,"response_actions":row.response_actions,"resolved_at":row.resolved_at.isoformat() if row.resolved_at else None}


@router.post("/incidents", status_code=201)
async def create_incident(payload: IncidentCreate, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str,object]:
    current_user_from_request(request)
    row=Incident(title=payload.title,description=payload.description,severity=payload.severity,status=payload.status,assigned_to=payload.assigned_to,source_ip=payload.source_ip,threat_id=uuid.UUID(payload.threat_id) if payload.threat_id else None)
    session.add(row); await session.commit(); await session.refresh(row); return _incident_dict(row)


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: uuid.UUID, payload: IncidentUpdate, request: Request, session: AsyncSession = Depends(get_session))->dict[str,object]:
    current_user_from_request(request); row=await session.get(Incident,incident_id)
    if row is None: raise HTTPException(404,"Incident not found")
    if payload.status is not None: row.status=payload.status; row.response_actions=[*row.response_actions,f"status → {payload.status}"]
    if payload.severity is not None: row.severity=payload.severity
    if payload.assigned_to is not None: row.assigned_to=payload.assigned_to; row.response_actions=[*row.response_actions,f"assigned → {payload.assigned_to}"]
    if payload.note: row.notes=[*row.notes,payload.note]
    if payload.action: row.response_actions=[*row.response_actions,payload.action]
    if row.status in {"RESOLVED","CLOSED"}: row.resolved_at=row.resolved_at or datetime.now(UTC)
    await session.commit(); await session.refresh(row); return _incident_dict(row)


@router.post("/incidents/from-threat/{threat_id}", status_code=201)
async def incident_from_threat(threat_id: uuid.UUID, request: Request, session: AsyncSession = Depends(get_session))->dict[str,object]:
    current_user_from_request(request); threat=await session.get(ThreatEvent,threat_id)
    if not threat: raise HTTPException(404,"Threat event not found")
    existing=(await session.execute(select(Incident).where(Incident.threat_id==threat_id))).scalars().first()
    if existing: return _incident_dict(existing)
    row=Incident(title=f"{threat.severity} activity from {threat.source_ip}",description=f"{threat.request_method} {threat.request_path}",severity=threat.severity,status="NEW",source_ip=threat.source_ip,threat_id=threat.id,notes=[f"Rules: {', '.join(threat.matched_rules or []) or 'none'}"])
    session.add(row); await session.commit(); await session.refresh(row); return _incident_dict(row)


SIM_TARGET=os.getenv("SIM_TARGET_URL","http://devlog-nginx")
SIM_PATHS={"normal":["/","/health","/api/users","/api/products"],"sqli":["/api/search?q=1%3D1","/api/search?q=UNION%20SELECT%201"],"xss":["/api/search?q=javascript%3Aalert(1)","/api/search?q=onerror%3Dalert(1)"],"traversal":["/..%2f..%2fetc%2fpasswd"],"cmdi":["/api/search?q=%3Bcat%20%2Fetc%2Fpasswd"],"scanner":["/admin","/admin/dashboard","/.env"],"flood":["/health","/api/users"]}

@router.get("/simulation/history")
async def simulation_history(session: AsyncSession=Depends(get_session))->list[dict[str,object]]:
    rows=(await session.execute(select(SimulationRun).order_by(SimulationRun.created_at.desc()).limit(50))).scalars().all()
    return [{"id":str(r.id),"mode":r.mode,"requested":r.requested,"completed":r.completed,"duration_ms":r.duration_ms,"target":r.target,"statuses":r.statuses,"created_at":r.created_at.isoformat()} for r in rows]

@router.post("/simulation/run")
async def run_simulation(payload: SimulationRequest, request: Request)->dict[str,object]:
    current_user_from_request(request)
    paths=SIM_PATHS["normal"]+SIM_PATHS["sqli"]+SIM_PATHS["xss"]+SIM_PATHS["scanner"] if payload.mode=="mixed" else SIM_PATHS[payload.mode]
    started=time.perf_counter(); statuses=Counter(); source_ips: list[str] = []
    async with httpx.AsyncClient(timeout=5,follow_redirects=False) as client:
        for i in range(payload.count):
            source_ip=f"10.20.{secrets.randbelow(250) + 1}.{secrets.randbelow(250) + 1}"; source_ips.append(source_ip)
            headers={"X-Simulated-Source-IP": source_ip, "X-CyberSentinel-Profile": payload.mode, "User-Agent": "CyberSentinel-Simulation/1.0" if payload.mode != "scanner" else "Nmap Scripting Engine"}
            try: statuses[str((await client.get(f"{SIM_TARGET}{paths[i%len(paths)]}", headers=headers)).status_code)]+=1
            except httpx.HTTPError: statuses["ERROR"]+=1
            if payload.delay_ms: await asyncio.sleep(payload.delay_ms/1000)
    duration=round((time.perf_counter()-started)*1000); completed=sum(statuses.values())
    async with request.app.state.session_factory() as session:
        session.add(SimulationRun(mode=payload.mode,requested=payload.count,completed=completed,duration_ms=duration,target=SIM_TARGET,statuses=dict(statuses),result_note="Controlled local lab simulation; no exploit execution.")); await session.commit()
    return {"mode":payload.mode,"requested":payload.count,"completed":completed,"statuses":dict(statuses),"duration_ms":duration,"target":SIM_TARGET,"source_ips":source_ips,"telemetry_note":"Controlled local lab simulation feeding the real detection pipeline with a distinct lab source IP per request."}
