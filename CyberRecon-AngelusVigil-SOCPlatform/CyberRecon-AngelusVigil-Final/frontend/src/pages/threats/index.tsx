import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const CLASSIFICATIONS = ['ALL', 'SQL Injection', 'XSS', 'Path Traversal', 'Command Injection', 'SSRF', 'Brute Force', 'Bot Activity', 'Port Scanning', 'Suspicious Web Activity']
type Threat = { id: string; time: string; ip: string; request: string; type: string; score: number; severity: string; rules: string[]; incident_id: string | null; incident_status: string | null; resolved: boolean }

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const [severity, setSeverity] = usePersistentState('tab-history-threats.severity', 'ALL')
  const [classification, setClassification] = usePersistentState('tab-history-threats.classification', 'ALL')
  const [query, setQuery] = usePersistentState('tab-history-threats.search', '')
  const [showResolved, setShowResolved] = usePersistentState('tab-history-threats.showResolved', false)
  const [rows, setRows] = useState<Threat[]>([])
  const [busy, setBusy] = useState(true)

  async function load(): Promise<void> {
    setBusy(true)
    try {
      const response = await apiClient.get<Threat[]>('/security/alerts', { params: { severity: severity === 'ALL' ? undefined : severity, classification: classification === 'ALL' ? undefined : classification, q: query || undefined } })
      setRows(response.data)
    } finally { setBusy(false) }
  }
  useEffect(() => { void load() }, [severity, classification, query])

  async function openIncident(item: Threat): Promise<void> {
    if (!item.incident_id) await apiClient.post(`/platform/incidents/from-threat/${item.id}`)
    navigate('/incidents')
  }
  async function resolve(item: Threat): Promise<void> { await apiClient.patch(`/security/alerts/${item.id}`, { resolved: true }); await load() }
  const visible = rows.filter((item) => (showAssigned || !item.incident_id) && (showResolved || !item.resolved))

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Threat Events</h2><p className={s.sub}>Searchable audit stream with classification filters and a traceable route into Incident Response.</p></div><button className={s.button} onClick={() => void load()}>Refresh</button></div>
    <section className={s.card}><div className={s.row}><select className={s.select} style={{ width: 150 }} value={severity} onChange={(event) => setSeverity(event.target.value)}>{SEVERITIES.map((value) => <option key={value}>{value}</option>)}</select><select className={s.select} style={{ width: 210 }} value={classification} onChange={(event) => setClassification(event.target.value)}>{CLASSIFICATIONS.map((value) => <option key={value}>{value}</option>)}</select><input className={s.input} style={{ flex: 1, minWidth: 220 }} placeholder="Search IP, path, rule or classification" value={query} onChange={(event) => setQuery(event.target.value)} /><label className={s.muted}><input type="checkbox" checked={showResolved} onChange={(event) => setShowResolved(event.target.checked)} /> Show resolved</label></div></section>
    <section className={s.card}><table className={s.table}><thead><tr><th>Time</th><th>IP</th><th>Request</th><th>Classification</th><th>Evidence</th><th>Score</th><th>Route</th><th>Action</th></tr></thead><tbody>{busy ? <tr><td colSpan={8}>Loading events…</td></tr> : visible.map((item) => <tr key={item.id}><td>{new Date(item.time).toLocaleString()}</td><td>{item.ip}</td><td>{item.request}</td><td>{item.type}</td><td>{item.rules.length ? item.rules.join(', ') : 'Behavioural telemetry'}</td><td>{item.score.toFixed(2)}<br /><span className={s.badge}>{item.severity}</span></td><td>{item.incident_id ? <span className={s.notice}>Assigned · {item.incident_status}</span> : <span className={s.muted}>Unassigned</span>}</td><td><div className={s.row}><button className={s.button} onClick={() => void openIncident(item)}>{item.incident_id ? 'Open response' : 'Create incident'}</button>{!item.resolved && <button className={`${s.button} ${s.secondary}`} onClick={() => void resolve(item)}>Resolve alert</button>}</div></td></tr>)}</tbody></table>{!busy && !visible.length && <div className={s.empty}>No threat events match these filters.</div>}</section>
  </div>
}

Component.displayName = 'ThreatsPage'
