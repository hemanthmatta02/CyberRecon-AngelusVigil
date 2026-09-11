import { Link } from 'react-router-dom'
import { LuActivity, LuArrowUpRight, LuBug, LuRadar, LuShieldAlert } from 'react-icons/lu'
import { usePlatform } from '@/api/hooks'
import { useAlerts } from '@/api/hooks/useAlerts'
import { ROUTES } from '@/config'
import s from './dashboard.module.scss'

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
  return (
    <div className={s.chart} aria-label="Threats by severity">
      {items.map((item) => (
        <div key={item.time} className={s.barColumn}>
          <div className={s.bar} style={{ height: `${Math.max(5, (item.value / max) * 170)}px` }} title={`${item.label}: ${item.value} events`}>
            <span>{item.value}</span>
          </div>
          <label>{item.label}</label>
        </div>
      ))}
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading } = usePlatform<Overview>('overview', '/platform/overview')
  const { data: detection } = usePlatform<{ top_sources: Array<{ ip: string; count: number }> }>('detection-dashboard', '/platform/detection')
  const { data: soc } = usePlatform<{ status: Record<string, number> }>('soc-dashboard', '/platform/soc')
  const { alerts, isConnected } = useAlerts()

  if (isLoading) return <div className={s.page}><div className={s.loading}>Loading security telemetry…</div></div>

  const severity: ChartPoint[] = [
    { label: 'CRITICAL', value: data?.critical ?? 0, time: 'critical' },
    { label: 'HIGH', value: data?.high ?? 0, time: 'high' },
    { label: 'MEDIUM', value: data?.medium ?? 0, time: 'medium' },
    { label: 'LOW', value: data?.low ?? 0, time: 'low' },
  ]

  const quickActions = [
    { to: ROUTES.RECON, title: 'Launch Recon', description: 'Enumerate targets and surface exposed services.', icon: LuRadar },
    { to: ROUTES.DETECTION, title: 'Live Detection', description: 'Inspect active traffic, signals, and detections.', icon: LuActivity },
    { to: ROUTES.VULNERABILITIES, title: 'Assess Risk', description: 'Review vulnerabilities and prioritize findings.', icon: LuBug },
  ]

  return (
    <div className={s.page}>
      <section className={s.hero}>
        <div>
          <div className={s.eyebrow}><span className={s.pulseDot} /> LIVE SECURITY TELEMETRY</div>
          <h2 className={s.title}>CyberSentinel Command Center</h2>
          <p className={s.subtitle}>A single operational view of threats, telemetry, assets, and response activity.</p>
        </div>
        <div className={s.heroStatus}>
          <span className={isConnected ? s.online : s.offline} />
          {isConnected ? 'Telemetry connected' : 'Reconnecting telemetry'}
        </div>
      </section>

      <section className={s.kpis}>
        <div className={s.kpi}><span>Observed requests / 24h</span><strong>{data?.threats ?? 0}</strong><small>Total observed activity</small></div>
        <div className={s.kpi}><span>Critical + high</span><strong>{(data?.critical ?? 0) + (data?.high ?? 0)}</strong><small>Priority findings</small></div>
        <div className={s.kpi}><span>Active operations</span><strong>{data?.open_incidents ?? 0}</strong><small>Open incidents</small></div>
        <div className={s.kpi}><span>Source IPs</span><strong>{detection?.top_sources?.length ?? 0}</strong><small>Observed sources</small></div>
        <div className={s.kpi}><span>Session alerts</span><strong>{alerts.length}</strong><small>Current console</small></div>
      </section>

      <section className={s.quickGrid}>
        {quickActions.map((action) => (
          <Link key={action.title} to={action.to} className={s.quickCard}>
            <div className={s.quickIcon}><action.icon /></div>
            <div><h3>{action.title}</h3><p>{action.description}</p></div>
            <LuArrowUpRight className={s.quickArrow} />
          </Link>
        ))}
      </section>

      <div className={s.mainGrid}>
        <section className={s.card}>
          <div className={s.cardHeader}><div><span className={s.cardEyebrow}>THREAT DISTRIBUTION</span><h3>Threats by severity</h3></div><LuShieldAlert className={s.cardIcon} /></div>
          <BarChart items={severity} />
        </section>

        <section className={s.card}>
          <div className={s.cardHeader}><div><span className={s.cardEyebrow}>SOURCE ACTIVITY</span><h3>Top source IPs</h3></div></div>
          <div className={s.tableWrap}>
            <table className={s.table}><thead><tr><th>IP</th><th>Events</th></tr></thead><tbody>
              {(detection?.top_sources ?? []).slice(0, 6).map((item) => <tr key={item.ip}><td className={s.mono}>{item.ip}</td><td>{item.count}</td></tr>)}
              {!(detection?.top_sources?.length) && <tr><td colSpan={2} className={s.empty}>No source telemetry available.</td></tr>}
            </tbody></table>
          </div>
        </section>
      </div>

      <div className={s.mainGrid}>
        <section className={s.card}>
          <div className={s.cardHeader}><div><span className={s.cardEyebrow}>SOC WORKFLOW</span><h3>Operation status</h3></div></div>
          <div className={s.statusList}>
            {Object.entries(soc?.status ?? {}).slice(0, 8).map(([status, count]) => (
              <div key={status} className={s.statusRow}><span>{status.replaceAll('_', ' ')}</span><strong>{count}</strong></div>
            ))}
            {!(Object.keys(soc?.status ?? {}).length) && <div className={s.empty}>No operation status available.</div>}
          </div>
        </section>

        <section className={s.card}>
          <div className={s.cardHeader}><div><span className={s.cardEyebrow}>RECENT TELEMETRY</span><h3>Observed events</h3></div></div>
          <div className={s.eventList}>
            {(data?.recent_events ?? []).slice(0, 6).map((event) => (
              <div key={event.id} className={s.eventRow}>
                <div><span className={s.eventTime}>{new Date(event.time).toLocaleTimeString()}</span><span className={s.mono}>{event.ip}</span><span className={s.request}>{event.method} {event.path}</span></div>
                <span className={`${s.badge} ${s[event.severity as keyof typeof s]}`}>{event.severity}</span>
              </div>
            ))}
            {!(data?.recent_events?.length) && <div className={s.empty}>No recent events available.</div>}
          </div>
        </section>
      </div>
    </div>
  )
}

Component.displayName = 'SecurityDashboard'
