import { useState } from 'react'
import { apiClient } from '@/core/api'
import { usePlatform } from '@/api/hooks/usePlatform'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

type Indicator = { ip: string; reputation: string; confidence: number; observations: number; country: string | null; last_seen: string }
type Source = { id: string; name: string; status: string; coverage: string; note: string }
type Intel = {
  counts: Record<string, number>
  indicators: Indicator[]
  technology_inventory: Array<{ name: string; observations: number }>
  data_sources: Source[]
  recent_targets: string[]
}

const labels: Array<[string, string]> = [['ip_reputation', 'Observed IPs'], ['dns_records', 'DNS records'], ['cve_findings', 'Findings'], ['technologies', 'Technologies'], ['subdomains', 'Subdomains']]

export function Component(): React.ReactElement {
  const { data, isLoading, error, refetch } = usePlatform<Intel>('intel', '/platform/intelligence')
  const [query, setQuery] = usePersistentState('tab-history-intelligence.search', '')
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<string | null>(null)

  async function saveSource(source: Source): Promise<void> {
    const note = drafts[source.id] ?? source.note
    setSaving(source.id)
    try {
      await apiClient.patch(`/platform/intelligence/sources/${source.id}`, { note })
      await refetch()
      setDrafts((current) => { const next = { ...current }; delete next[source.id]; return next })
    } finally { setSaving(null) }
  }

  if (isLoading) return <div className={s.page}>Loading threat intelligence…</div>

  const indicators = (data?.indicators ?? []).filter((item) => !query || `${item.ip} ${item.reputation} ${item.country ?? ''}`.toLowerCase().includes(query.toLowerCase()))
  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Threat Intelligence</h2><p className={s.sub}>Observed source reputation, asset technologies and locally configured data sources.</p></div><button className={s.button} onClick={() => void refetch()}>Refresh intelligence</button></div>
    <div className={s.kpis}>{labels.map(([key, label]) => <div className={s.kpi} key={key}><small>{label}</small><strong>{data?.counts[key] ?? 0}</strong></div>)}</div>
    <section className={s.card}>
      <div className={s.row}><h3 style={{ margin: 0 }}>Observed indicators</h3><input className={s.input} style={{ maxWidth: 280 }} placeholder="Search IP, reputation or country" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
      {error ? <div className={s.callout}>{error.message}</div> : <table className={s.table}><thead><tr><th>IP</th><th>Reputation</th><th>Confidence</th><th>Observations</th><th>Country</th><th>Last seen</th></tr></thead><tbody>{indicators.map((item) => <tr key={item.ip}><td>{item.ip}</td><td><span className={s.badge}>{item.reputation}</span></td><td>{Math.round(item.confidence * 100)}%</td><td>{item.observations}</td><td>{item.country ?? '—'}</td><td>{new Date(item.last_seen).toLocaleString()}</td></tr>)}</tbody></table>}
      {!indicators.length && <div className={s.empty}>No observed indicators yet. Run a varied manual request or simulation to populate this table.</div>}
    </section>
    <div className={s.grid}>
      <section className={s.card}><h3>Technology inventory</h3>{data?.technology_inventory.length ? <table className={s.table}><thead><tr><th>Technology</th><th>Observed endpoints</th></tr></thead><tbody>{data.technology_inventory.map((item) => <tr key={item.name}><td>{item.name}</td><td>{item.observations}</td></tr>)}</tbody></table> : <div className={s.muted}>Run an authorized Asset Discovery or CyberRecon HTTP scan to populate the inventory.</div>}{data?.recent_targets.length ? <p className={s.muted}>Recent targets: {data.recent_targets.join(', ')}</p> : null}</section>
      <section className={s.card}><h3>Configured data sources</h3>{(data?.data_sources ?? []).map((source) => <div className={s.notice} style={{ marginBottom: 10 }} key={source.id}><div className={s.row} style={{ justifyContent: 'space-between' }}><strong>{source.name}</strong><span className={s.badge}>{source.status}</span></div><p className={s.muted} style={{ margin: '7px 0' }}>{source.coverage}</p><textarea className={s.textarea} aria-label={`${source.name} note`} value={drafts[source.id] ?? source.note} onChange={(event) => setDrafts((current) => ({ ...current, [source.id]: event.target.value }))} /><button className={`${s.button} ${s.secondary}`} style={{ marginTop: 8 }} disabled={saving === source.id} onClick={() => void saveSource(source)}>{saving === source.id ? 'Saving…' : 'Save note'}</button></div>)}</section>
    </div>
  </div>
}

Component.displayName = 'ThreatIntelligence'
