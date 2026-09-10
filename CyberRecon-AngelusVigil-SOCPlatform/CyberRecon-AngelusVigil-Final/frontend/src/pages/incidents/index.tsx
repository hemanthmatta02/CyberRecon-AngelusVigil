import { useEffect, useState } from 'react'
import { apiClient } from '@/core/api'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

const STATUSES = ['NEW', 'QUEUED', 'OPEN', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'CLOSED'] as const
type Status = typeof STATUSES[number]
type Incident = { id: string; title: string; description: string; severity: string; status: Status; assigned_to: string | null; source_ip: string | null; notes: string[]; response_actions: string[] }

export function Component(): React.ReactElement {
  const [rows, setRows] = useState<Incident[]>([])
  const [status, setStatus] = usePersistentState<Status | 'ALL'>('tab-history-incidents.status', 'ALL')
  const [notes, setNotes] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)

  async function load(): Promise<void> { setLoading(true); try { setRows((await apiClient.get<Incident[]>('/platform/incidents', { params: status === 'ALL' ? undefined : { status } })).data) } finally { setLoading(false) } }
  useEffect(() => { void load() }, [status])
  async function save(id: string, payload: Record<string, string>): Promise<void> { await apiClient.patch(`/platform/incidents/${id}`, payload); await load() }

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Incident Response</h2><p className={s.sub}>The same operational records shown in SOC Operations, with evidence, ownership and response actions.</p></div><button className={s.button} onClick={() => void load()}>Refresh</button></div>
    <section className={s.card}><div className={s.tabs}><button className={`${s.tab} ${status === 'ALL' ? s.active : ''}`} onClick={() => setStatus('ALL')}>All</button>{STATUSES.map((item) => <button className={`${s.tab} ${status === item ? s.active : ''}`} key={item} onClick={() => setStatus(item)}>{item}</button>)}</div></section>
    {loading ? <section className={s.card}>Loading operations…</section> : rows.map((item) => <section className={s.card} key={item.id}><div className={s.row}><h3 style={{ margin: 0 }}>{item.title}</h3><span className={s.badge}>{item.severity}</span><span className={s.badge}>{item.status}</span></div><p className={s.sub}>{item.description}</p><div className={s.row}><span className={s.notice}>Source: {item.source_ip ?? '—'}</span><label className={s.muted}>Owner <select className={s.select} style={{ width: 180, display: 'inline-block', marginLeft: 6 }} value={item.assigned_to ?? ''} onChange={(event) => void save(item.id, { assigned_to: event.target.value || null })}><option value="">Unassigned</option><option value="admin">SOC Administrator</option><option value="analyst">SOC Analyst</option></select></label></div><div className={s.row} style={{ marginTop: 10, flexWrap: 'wrap' }}>{STATUSES.map((next) => <button key={next} className={`${s.tab} ${item.status === next ? s.active : ''}`} onClick={() => void save(item.id, { status: next })}>{next}</button>)}</div><div className={s.grid} style={{ marginTop: 14 }}><div><h4>Timeline / notes</h4>{item.notes.map((note, index) => <p className={s.notice} key={`${item.id}-note-${index}`}>{note}</p>)}{item.response_actions.map((action, index) => <p className={s.muted} key={`${item.id}-action-${index}`}>Action: {action}</p>)}</div><div><h4>Add evidence note</h4><textarea className={s.textarea} value={notes[item.id] ?? ''} onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))} placeholder="Analyst observation, containment evidence, or handoff" /><button className={s.button} style={{ marginTop: 8 }} onClick={() => { const note = notes[item.id]?.trim(); if (note) { void save(item.id, { note }); setNotes((current) => ({ ...current, [item.id]: '' })) } }}>Save note</button></div></div></section>)}
    {!loading && !rows.length && <section className={s.card}><div className={s.empty}>No operations found. Manual traffic and simulations create new operations automatically.</div></section>}
  </div>
}

Component.displayName = 'IncidentResponse'
