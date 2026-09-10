import { useEffect, useMemo, useState } from 'react'
import { apiClient } from '@/core/api'
import s from '../shared.module.scss'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
type Status = 'OPEN' | 'RESOLVED' | 'ACCEPTED'
type Filter = 'ALL' | Severity | Status

type Finding = {
  id: string
  created_at: string
  target: string
  name: string
  description: string
  affected_asset: string
  severity: Severity
  evidence: string
  recommended_fix: string
  status: Status
  category: string
}

function messageFrom(error: unknown, fallback: string): string {
  const response = error as { response?: { data?: { detail?: string } }; message?: string }
  return response.response?.data?.detail ?? response.message ?? fallback
}

export function Component(): React.ReactElement {
  const [target, setTarget] = useState('')
  const [items, setItems] = useState<Finding[]>([])
  const [filter, setFilter] = useState<Filter>('ALL')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadFindings(): Promise<void> {
    try {
      const response = await apiClient.get<Finding[]>('/security/vulnerabilities')
      setItems(response.data)
      if (!target && response.data[0]?.target) setTarget(response.data[0].target)
    } catch (cause: unknown) {
      setError(messageFrom(cause, 'Unable to load vulnerability findings.'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadFindings() }, [])

  async function scan(): Promise<void> {
    const value = target.trim()
    if (!value) { setError('Enter a target before starting the assessment.'); return }
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const response = await apiClient.post<{ target: string; count: number; findings: Finding[] }>('/security/vulnerability-scan', { target: value })
      setItems(response.data.findings)
      setMessage(`${response.data.count} finding${response.data.count === 1 ? '' : 's'} returned for ${response.data.target}.`)
    } catch (cause: unknown) {
      setError(messageFrom(cause, 'Assessment failed. Check that the backend is running and the target is reachable.'))
    } finally {
      setBusy(false)
    }
  }

  async function update(id: string, status: Status): Promise<void> {
    setError('')
    try {
      const response = await apiClient.patch<Finding>(`/security/vulnerabilities/${id}`, { status })
      setItems((current) => current.map((item) => item.id === id ? response.data : item))
      setMessage(`Finding marked ${status.toLowerCase()}.`)
    } catch (cause: unknown) {
      setError(messageFrom(cause, 'Could not update this finding.'))
    }
  }

  const shown = useMemo(() => items.filter((item) => filter === 'ALL' || item.severity === filter || item.status === filter), [filter, items])
  const openCount = items.filter((item) => item.status === 'OPEN').length
  const highCount = items.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH').length
  const resolvedCount = items.filter((item) => item.status === 'RESOLVED' || item.status === 'ACCEPTED').length

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Vulnerability Assessment</h2><p className={s.sub}>Run an authorized HTTP assessment, review evidence, and move findings through a clear remediation workflow.</p></div><span className={s.notice}>Authorized targets only</span></div>
    <section className={s.card}><div className={s.grid}><label className={s.label}>Target domain / hostname<input className={s.input} value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com or 127.0.0.1" /></label><div className={s.notice}>The assessment checks common security headers, transport controls, exposed files, directory listing, and cookie configuration.</div></div><div className={s.row} style={{ marginTop: 14 }}><button type="button" className={s.button} disabled={busy} onClick={() => void scan()}>{busy ? 'Assessing…' : 'Run assessment'}</button><button type="button" className={`${s.button} ${s.secondary}`} disabled={loading} onClick={() => { setLoading(true); void loadFindings() }}>Refresh findings</button><span className={s.muted}>Findings remain available for SOC and report workflows.</span></div>{error && <div className={s.notice} style={{ marginTop: 12, borderColor: '#7f3540', color: '#ffb2ba' }}>{error}</div>}{message && <div className={s.notice} style={{ marginTop: 12 }}>{message}</div>}</section>
    <div className={s.kpis}><div className={s.kpi}><small>Total findings</small><strong>{items.length}</strong></div><div className={s.kpi}><small>Open</small><strong>{openCount}</strong></div><div className={s.kpi}><small>High / critical</small><strong>{highCount}</strong></div><div className={s.kpi}><small>Resolved / accepted</small><strong>{resolvedCount}</strong></div><div className={s.kpi}><small>Showing</small><strong>{shown.length}</strong></div></div>
    <section className={s.card}><div className={s.row} style={{ justifyContent: 'space-between' }}><div><h3 style={{ margin: 0 }}>Findings</h3><span className={s.muted}>Use a filter to focus the review queue.</span></div><div className={s.tabs}>{(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'OPEN', 'RESOLVED', 'ACCEPTED'] as Filter[]).map((value) => <button key={value} type="button" className={`${s.tab} ${filter === value ? s.active : ''}`} onClick={() => setFilter(value)}>{value}</button>)}</div></div></section>
    {loading ? <section className={s.card}><div className={s.empty}>Loading findings…</div></section> : shown.length ? <div className={s.grid3}>{shown.map((item) => <article className={s.finding} key={item.id}><div className={s.row}><span className={`${s.badge} ${s[item.severity as keyof typeof s]}`}>{item.severity}</span><span className={`${s.badge} ${s[item.status as keyof typeof s]}`}>{item.status}</span><span className={s.muted}>{item.category}</span></div><h4>{item.name}</h4><p>{item.description}</p><p><strong>Affected:</strong> {item.affected_asset}</p><p><strong>Evidence:</strong> {item.evidence}</p><p><strong>Recommended fix:</strong> {item.recommended_fix}</p><div className={s.row}>{item.status !== 'RESOLVED' && <button type="button" className={`${s.button} ${s.success}`} onClick={() => void update(item.id, 'RESOLVED')}>Resolve</button>}{item.status !== 'ACCEPTED' && <button type="button" className={`${s.button} ${s.secondary}`} onClick={() => void update(item.id, 'ACCEPTED')}>Accept</button>}{item.status !== 'OPEN' && <button type="button" className={`${s.button} ${s.danger}`} onClick={() => void update(item.id, 'OPEN')}>Reopen</button>}</div></article>)}</div> : <section className={s.card}><div className={s.empty}>{items.length ? 'No findings match this filter.' : 'No findings yet. Run an authorized assessment to populate this queue.'}</div></section>}
  </div>
}

Component.displayName = 'VulnerabilityAssessment'
