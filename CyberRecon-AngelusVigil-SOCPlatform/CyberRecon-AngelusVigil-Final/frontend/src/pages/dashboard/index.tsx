import { usePlatform } from '@/api/hooks'
import { useAlerts } from '@/api/hooks/useAlerts'
import s from '../shared.module.scss'

type Overview = {
  threats: number
  critical: number
  high: number
  medium: number
  low: number
  open_incidents: number
  recent_events: Array<{ id: string; time: string; ip: string; method: string; path: string; score: number; severity: string }>
}

type ChartPoint = { label: string; value: number; time: string }

function BarChart({ items }: { items: ChartPoint[] }): React.ReactElement {
  const max = Math.max(1, ...items.map((item) => item.value))
  return <div className={s.chart} aria-label="Threats by severity">{items.map((item) => <div key={item.time} className={s.bar} style={{ height: `${Math.max(4, (item.value / max) * 165)}px` }} title={`${item.label}: ${item.value} events`}><span>{item.value}</span><label>{item.label}</label></div>)}</div>
}

export function Component(): React.ReactElement {
  const { data, isLoading } = usePlatform<Overview>('overview', '/platform/overview')
  const { data: detection } = usePlatform<{ top_sources: Array<{ ip: string; count: number }> }>('detection-dashboard', '/platform/detection')
  const { data: soc } = usePlatform<{ status: Record<string, number> }>('soc-dashboard', '/platform/soc')
  const { alerts, isConnected } = useAlerts()

  if (isLoading) return <div className={s.page} />

  const severity: ChartPoint[] = [
    { label: 'CRIT', value: data?.critical ?? 0, time: 'critical' },
    { label: 'HIGH', value: data?.high ?? 0, time: 'high' },
    { label: 'MED', value: data?.medium ?? 0, time: 'medium' },
    { label: 'LOW', value: data?.low ?? 0, time: 'low' },
  ]

  return <div className={s.page}>
    <div className={s.hero}>
      <div><h2 className={s.title}>CyberSentinel SOC Dashboard</h2></div>
      <span className={s.notice}>{isConnected ? '● Live telemetry connected' : '○ Reconnecting telemetry'}</span>
    </div>
    <div className={s.kpis}>
      <div className={s.kpi}><small>Observed requests / 24h</small><strong>{data?.threats ?? 0}</strong></div>
      <div className={s.kpi}><small>Critical / high</small><strong>{(data?.critical ?? 0) + (data?.high ?? 0)}</strong></div>
      <div className={s.kpi}><small>Active operations</small><strong>{data?.open_incidents ?? 0}</strong></div>
      <div className={s.kpi}><small>Source IPs</small><strong>{detection?.top_sources?.length ?? 0}</strong></div>
      <div className={s.kpi}><small>Alerts in session</small><strong>{alerts.length}</strong></div>
    </div>
    <section className={s.card}><h3>Threats by severity</h3><BarChart items={severity} /></section>
    <div className={s.grid}>
      <section className={s.card}><h3>Top source IPs</h3><table className={s.table}><thead><tr><th>IP</th><th>Events</th></tr></thead><tbody>{(detection?.top_sources ?? []).map((item) => <tr key={item.ip}><td>{item.ip}</td><td>{item.count}</td></tr>)}</tbody></table></section>
      <section className={s.card}><h3>Operation status</h3><table className={s.table}><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>{Object.entries(soc?.status ?? {}).map(([status, count]) => <tr key={status}><td>{status}</td><td>{count}</td></tr>)}</tbody></table></section>
    </div>
    <section className={s.card}><h3>Recent observed events</h3><table className={s.table}><thead><tr><th>Time</th><th>IP</th><th>Request</th><th>Score</th><th>Severity</th></tr></thead><tbody>{(data?.recent_events ?? []).map((event) => <tr key={event.id}><td>{new Date(event.time).toLocaleTimeString()}</td><td>{event.ip}</td><td>{event.method} {event.path}</td><td>{event.score.toFixed(2)}</td><td><span className={`${s.badge} ${s[event.severity as keyof typeof s]}`}>{event.severity}</span></td></tr>)}</tbody></table></section>
  </div>
}

Component.displayName = 'SecurityDashboard'
