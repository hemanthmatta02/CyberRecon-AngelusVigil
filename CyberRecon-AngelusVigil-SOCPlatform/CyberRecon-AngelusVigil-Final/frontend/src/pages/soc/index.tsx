import { useEffect, useState } from 'react'
import { apiClient } from '@/core/api'
import { usePlatform } from '@/api/hooks'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

const STATUSES = ['NEW', 'QUEUED', 'OPEN', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'CLOSED'] as const
type Status = typeof STATUSES[number]
type Operation = { id: string; title: string; description: string; severity: string; status: Status; assigned_to: string | null; source_ip: string | null }
type SocData = { status: Record<Status, number>; analyst_workflow: string[] }

export function Component(): React.ReactElement {
  const { data, isLoading, refetch } = usePlatform<SocData>('soc', '/platform/soc')
  const [operations, setOperations] = useState<Operation[]>([])
  const [notes, setNotes] = useState<Record<string, string>>({})
  const [filter, setFilter] = usePersistentState<Status | 'ACTIVE'>('tab-history-soc.filter', 'ACTIVE')

  async function load(): Promise<void> { setOperations((await apiClient.get<Operation[]>('/platform/incidents')).data) }
  useEffect(() => { void load() }, [])

  async function update(id: string, payload: Record<string, string | null>): Promise<void> {
    await apiClient.patch(`/platform/incidents/${id}`, payload)
    await Promise.all([load(), refetch()])
  }

  if (isLoading || !data) return <div className={s.page} />
  const visible = operations.filter((item) => filter === 'ACTIVE' ? !['RESOLVED', 'CLOSED'].includes(item.status) : item.status === filter)

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>SOC Operations</h2><p className={s.sub}>Every observed request creates a new operation. Move it through the queue without leaving the SOC workspace.</p></div><button className={s.button} onClick={() => void Promise.all([load(), refetch()])}>Refresh queue</button></div>
    <div className={s.kpis}>{STATUSES.map((status) => <div className={s.kpi} key={status}><small>{status}</small><strong>{data.status[status] ?? 0}</strong></div>)}</div>
    <section className={s.card}><div className={s.row} style={{ justifyContent: 'space-between' }}><h3 style={{ margin: 0 }}>Queue view</h3><div className={s.tabs}><button className={`${s.tab} ${filter === 'ACTIVE' ? s.active : ''}`} onClick={() => setFilter('ACTIVE')}>Active</button>{STATUSES.map((status) => <button className={`${s.tab} ${filter === status ? s.active : ''}`} key={status} onClick={() => setFilter(status)}>{status}</button>)}</div></div></section>
    <section className={s.card}><h3>{filter === 'ACTIVE' ? 'Active operation queue' : `${filter} operations`}</h3>{visible.map((item) => <article className={s.finding} style={{ marginBottom: 10 }} key={item.id}><div className={s.row}><strong>{item.title}</strong><span className={s.badge}>{item.severity}</span><span className={s.badge}>{item.status}</span><span className={s.muted}>{item.source_ip ?? 'No source IP'}</span></div><p>{item.description}</p><div className={s.row}><label className={s.muted}>Move to <select className={s.select} style={{ width: 160, display: 'inline-block', marginLeft: 6 }} value={item.status} onChange={(event) => void update(item.id, { status: event.target.value })}>{STATUSES.map((status) => <option key={status}>{status}</option>)}</select></label><label className={s.muted}>Owner <select className={s.select} style={{ width: 170, display: 'inline-block', marginLeft: 6 }} value={item.assigned_to ?? ''} onChange={(event) => void update(item.id, { assigned_to: event.target.value })}><option value="">Unassigned</option><option value="admin">SOC Administrator</option><option value="analyst">SOC Analyst</option></select></label></div><div className={s.row} style={{ marginTop: 8 }}><input className={s.input} style={{ flex: 1, minWidth: 220 }} placeholder="Add analyst note" value={notes[item.id] ?? ''} onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))} /><button className={`${s.button} ${s.secondary}`} onClick={() => { const note = notes[item.id]?.trim(); if (note) { void update(item.id, { note }); setNotes((current) => ({ ...current, [item.id]: '' })) } }}>Add note</button></div></article>)}{!visible.length && <div className={s.empty}>No operations in this queue. New observed traffic appears here automatically.</div>}</section>
    <section className={s.card}><h3>Workflow</h3><div className={s.row}>{data.analyst_workflow.map((item) => <span className={s.notice} key={item}>{item}</span>)}</div></section>
  </div>
}

Component.displayName = 'SOCOperationsDashboard'
