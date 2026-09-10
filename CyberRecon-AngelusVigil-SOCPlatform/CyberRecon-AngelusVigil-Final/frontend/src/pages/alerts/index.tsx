import { useEffect, useState } from 'react'
import { apiClient } from '@/core/api'
import s from '../shared.module.scss'

type Alert = { id: string; time: string; type: string; ip: string; request: string; severity: string; score: number; acknowledged: boolean; resolved: boolean; assigned_to: string | null; comment: string; feedback: string | null }
type View = 'QUEUE' | 'ASSIGNED' | 'RESOLVED'
const ANALYSTS = [{ value: 'admin', label: 'SOC Administrator' }, { value: 'analyst', label: 'SOC Analyst' }]

export function Component(): React.ReactElement {
  const [items, setItems] = useState<Alert[]>([])
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [view, setView] = useState<View>('QUEUE')
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')

  async function load(): Promise<void> {
    try { setItems((await apiClient.get<Alert[]>('/security/alerts', { params: { q: query || undefined, severity: severity || undefined } })).data) } catch { setError('Unable to load alert management data.') }
  }
  useEffect(() => { void load() }, [query, severity])

  async function act(id: string, payload: Record<string, string | boolean | null>): Promise<void> {
    setBusy(id)
    setError('')
    try { await apiClient.patch(`/security/alerts/${id}`, payload); await load() } catch { setError('The alert update was not saved. Please retry.') } finally { setBusy(null) }
  }

  const visible = items.filter((item) => view === 'QUEUE' ? !item.assigned_to && !item.resolved : view === 'ASSIGNED' ? Boolean(item.assigned_to) && !item.resolved : item.resolved)
  const counts = { QUEUE: items.filter((item) => !item.assigned_to && !item.resolved).length, ASSIGNED: items.filter((item) => Boolean(item.assigned_to) && !item.resolved).length, RESOLVED: items.filter((item) => item.resolved).length }

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Alert Management</h2><p className={s.sub}>The action queue intentionally contains only unassigned, unresolved alerts. Assigning moves an item to its own tab.</p></div><button className={s.button} onClick={() => void load()}>Refresh</button></div>
    <div className={s.kpis}><div className={s.kpi}><small>Unassigned / unresolved</small><strong>{counts.QUEUE}</strong></div><div className={s.kpi}><small>Assigned</small><strong>{counts.ASSIGNED}</strong></div><div className={s.kpi}><small>Resolved</small><strong>{counts.RESOLVED}</strong></div><div className={s.kpi}><small>Matching alerts</small><strong>{items.length}</strong></div><div className={s.kpi}><small>Current view</small><strong>{view}</strong></div></div>
    <section className={s.card}><div className={s.row}><div className={s.tabs}>{(['QUEUE', 'ASSIGNED', 'RESOLVED'] as View[]).map((item) => <button className={`${s.tab} ${view === item ? s.active : ''}`} key={item} onClick={() => setView(item)}>{item} ({counts[item]})</button>)}</div><input className={s.input} style={{ maxWidth: 300 }} placeholder="Search IP, path or classification" value={query} onChange={(event) => setQuery(event.target.value)} /><select className={s.select} style={{ width: 150 }} value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>{error && <div className={s.callout} style={{ marginTop: 10 }}>{error}</div>}</section>
    <section className={s.card}><table className={s.table}><thead><tr><th>Time</th><th>Threat</th><th>Severity</th><th>State</th><th>Assignee</th><th>Actions</th></tr></thead><tbody>{visible.map((item) => <tr key={item.id}><td>{new Date(item.time).toLocaleString()}</td><td><strong>{item.type}</strong><br /><span className={s.muted}>{item.ip} · {item.request} · score {item.score.toFixed(2)}</span>{item.comment ? <><br /><span className={s.muted}>Note: {item.comment}</span></> : null}</td><td><span className={s.badge}>{item.severity}</span></td><td>{item.resolved ? 'RESOLVED' : item.acknowledged ? 'ACKNOWLEDGED' : 'OPEN'}</td><td><select className={s.select} style={{ minWidth: 150 }} value={item.assigned_to ?? ''} disabled={busy === item.id} onChange={(event) => void act(item.id, { assigned_to: event.target.value || null })}><option value="">Unassigned</option>{ANALYSTS.map((analyst) => <option key={analyst.value} value={analyst.value}>{analyst.label}</option>)}</select></td><td><div className={s.row}><button className={s.button} disabled={busy === item.id} onClick={() => void act(item.id, { acknowledged: !item.acknowledged })}>{item.acknowledged ? 'Unacknowledge' : 'Acknowledge'}</button>{!item.resolved && <button className={`${s.button} ${s.success}`} disabled={busy === item.id} onClick={() => void act(item.id, { resolved: true })}>Resolve</button>}<select className={s.select} style={{ width: 115 }} value="" disabled={busy === item.id} onChange={(event) => { if (event.target.value) void act(item.id, { severity: event.target.value }) }}><option value="">Severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><button className={`${s.button} ${s.secondary}`} disabled={busy === item.id} onClick={() => { const comment = window.prompt('Analyst comment', item.comment); if (comment !== null) void act(item.id, { comment }) }}>Comment</button><button className={`${s.button} ${item.feedback === 'TRUE_POSITIVE' ? s.active : s.secondary}`} disabled={busy === item.id} onClick={() => void act(item.id, { feedback: 'TRUE_POSITIVE' })}>TP</button><button className={`${s.button} ${item.feedback === 'FALSE_POSITIVE' ? s.active : s.secondary}`} disabled={busy === item.id} onClick={() => void act(item.id, { feedback: 'FALSE_POSITIVE' })}>FP</button></div></td></tr>)}</tbody></table>{!visible.length && <div className={s.empty}>No alerts in this view.</div>}</section>
  </div>
}

Component.displayName = 'AlertManagement'
