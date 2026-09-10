import { useEffect, useState } from 'react'
import { apiClient } from '@/core/api'
import { usePlatform } from '@/api/hooks/usePlatform'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

type Explanation = { id: string; time: string; reason: string; score: number; severity: string; mode: string }
type ML = { detection_mode: string; events_sampled: number; anomaly_events: number; average_component_score: number; ml_component_observations: number; mode_counts: Record<string, number>; explanations: Explanation[] }
type Alert = { id: string; type: string; ip: string; score: number; feedback: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | null }

export function Component(): React.ReactElement {
  const { data, isLoading, refetch } = usePlatform<ML>('ml', '/platform/ml')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [mode, setMode] = usePersistentState('tab-history-ml.mode', 'ALL')
  const [updating, setUpdating] = useState<string | null>(null)
  const [feedbackError, setFeedbackError] = useState('')

  async function loadAlerts(): Promise<void> {
    try { setAlerts((await apiClient.get<Alert[]>('/security/alerts')).data) } catch { setFeedbackError('Unable to load analyst feedback items.') }
  }

  useEffect(() => { void loadAlerts() }, [])

  async function feedback(id: string, label: 'TRUE_POSITIVE' | 'FALSE_POSITIVE'): Promise<void> {
    setUpdating(id)
    setFeedbackError('')
    try {
      await apiClient.patch(`/security/alerts/${id}`, { feedback: label })
      setAlerts((current) => current.map((item) => item.id === id ? { ...item, feedback: label } : item))
    } catch { setFeedbackError('Feedback could not be saved. Please retry.') } finally { setUpdating(null) }
  }

  if (isLoading || !data) return <div className={s.page} />
  const filtered = data.explanations.filter((item) => mode === 'ALL' || item.mode === mode)
  const modes = ['ALL', 'SIGNATURE', 'BEHAVIOURAL', 'ANOMALY', 'HYBRID', 'OBSERVATION']

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>ML / AI Analysis</h2><p className={s.sub}>Explainable evidence and analyst feedback for every stored event.</p></div><button className={s.button} onClick={() => void Promise.all([refetch(), loadAlerts()])}>Refresh analysis</button></div>
    <div className={s.kpis}>
      <div className={s.kpi}><small>Evidence view</small><select className={s.select} value={mode} onChange={(event) => setMode(event.target.value)}>{modes.map((value) => <option key={value}>{value}</option>)}</select></div>
      <div className={s.kpi}><small>Events sampled</small><strong>{data.events_sampled}</strong></div>
      <div className={s.kpi}><small>Anomaly events</small><strong>{data.anomaly_events}</strong></div>
      <div className={s.kpi}><small>ML components</small><strong>{data.ml_component_observations}</strong></div>
      <div className={s.kpi}><small>Avg component score</small><strong>{data.average_component_score.toFixed(2)}</strong></div>
    </div>
    <section className={s.card}><h3>Per-event evidence</h3>{filtered.map((item) => <details key={item.id} style={{ marginBottom: 8 }}><summary><strong>{item.mode}</strong> · {item.severity} · score {item.score.toFixed(2)} · {new Date(item.time).toLocaleString()}</summary><p className={s.sub}>{item.reason}</p></details>)}{!filtered.length && <div className={s.empty}>No events match this evidence mode.</div>}</section>
    <section className={s.card}><div className={s.row} style={{ justifyContent: 'space-between' }}><h3 style={{ margin: 0 }}>True / False Positive Feedback</h3><button className={`${s.button} ${s.secondary}`} onClick={() => void loadAlerts()}>Refresh feedback items</button></div>{feedbackError && <div className={s.callout} style={{ marginTop: 10 }}>{feedbackError}</div>}<table className={s.table}><thead><tr><th>Classification</th><th>IP</th><th>Score</th><th>Saved label</th><th>Feedback</th></tr></thead><tbody>{alerts.slice(0, 100).map((item) => <tr key={item.id}><td>{item.type}</td><td>{item.ip}</td><td>{item.score.toFixed(2)}</td><td>{item.feedback?.replace('_', ' ') ?? 'Not reviewed'}</td><td><div className={s.row}><button className={`${s.button} ${item.feedback === 'TRUE_POSITIVE' ? s.active : ''}`} aria-pressed={item.feedback === 'TRUE_POSITIVE'} disabled={updating === item.id} onClick={() => void feedback(item.id, 'TRUE_POSITIVE')}>True positive</button><button className={`${s.button} ${s.secondary} ${item.feedback === 'FALSE_POSITIVE' ? s.active : ''}`} aria-pressed={item.feedback === 'FALSE_POSITIVE'} disabled={updating === item.id} onClick={() => void feedback(item.id, 'FALSE_POSITIVE')}>False positive</button></div></td></tr>)}</tbody></table>{!alerts.length && <div className={s.empty}>No stored alerts are available for review.</div>}</section>
  </div>
}

Component.displayName = 'MLAnalysis'
