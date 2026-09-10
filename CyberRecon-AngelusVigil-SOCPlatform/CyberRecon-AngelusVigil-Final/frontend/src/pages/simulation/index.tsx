import { useState } from 'react'
import { apiClient } from '@/core/api'
import { usePlatform } from '@/api/hooks/usePlatform'
import { API_ENDPOINTS } from '@/config'
import { usePersistentState } from '@/core/persistence'
import { Card, Grid, PlatformPage, Stats, platformStyles as styles } from '@/components/platform-dashboard'

type Result = { mode: string; requested: number; completed: number; statuses: Record<string, number>; duration_ms: number; target: string; source_ips: string[]; telemetry_note: string }
type History = { id: string; mode: string; requested: number; completed: number; duration_ms: number; target: string; created_at: string }
type Detection = { events: number; high_confidence: number; average_score: number }

export function Component(): React.ReactElement {
  const [mode, setMode] = usePersistentState('tab-history-simulation.mode', 'mixed')
  const [count, setCount] = usePersistentState('tab-history-simulation.count', 20)
  const [delay, setDelay] = usePersistentState('tab-history-simulation.delay', 80)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<Result | null>(null)
  const [error, setError] = useState('')
  const detection = usePlatform<Detection>('detection', '/platform/detection')
  const history = usePlatform<History[]>('simulation-history', '/platform/simulation/history')

  async function run(): Promise<void> {
    setRunning(true)
    setError('')
    try {
      const response = await apiClient.post<Result>(API_ENDPOINTS.PLATFORM.SIMULATION, { mode, count, delay_ms: delay })
      setResult(response.data)
      window.setTimeout(() => { void Promise.all([detection.refetch(), history.refetch()]) }, 500)
    } catch { setError('Simulation failed. Verify the controlled local target is running and retry.') } finally { setRunning(false) }
  }

  return <PlatformPage title="Attack Replay / Simulation" subtitle="Controlled requests travel through nginx, detection, alerting and the SOC queue — no UI-only mock alerts.">
    <Stats items={[{ label: 'Last run', value: result?.completed ?? 0, meta: 'Requests completed' }, { label: 'Detected events', value: detection.data?.events ?? 0, meta: 'Stored telemetry' }, { label: 'High confidence', value: detection.data?.high_confidence ?? 0, meta: 'Score ≥ 0.80' }, { label: 'Sources in last run', value: result ? new Set(result.source_ips).size : 0, meta: 'Distinct lab IPs' }]} />
    <Grid>
      <Card title="Simulation control"><div className={styles.formGrid}><div className={styles.field}><label>Scenario</label><select value={mode} onChange={(event) => setMode(event.target.value)}>{['normal', 'sqli', 'xss', 'traversal', 'cmdi', 'scanner', 'flood', 'mixed'].map((item) => <option key={item}>{item}</option>)}</select></div><div className={styles.field}><label>Requests</label><input type="number" min={1} max={100} value={count} onChange={(event) => setCount(Number(event.target.value))} /></div><div className={styles.field}><label>Delay (ms)</label><input type="number" min={0} max={2000} value={delay} onChange={(event) => setDelay(Number(event.target.value))} /></div></div><div className={styles.actions} style={{ marginTop: 12 }}><button className={styles.button} disabled={running} onClick={() => void run()}>{running ? 'Running simulation…' : 'Run simulation'}</button></div>{error && <div className={styles.callout} style={{ marginTop: 12 }}>{error}</div>}</Card>
      <Card title="Live pipeline behavior"><div className={styles.callout}>Every simulated request includes a distinct private source IP. The nginx log tailer stores the event, detection assigns evidence and score, and a new SOC operation is created from that persisted event.</div></Card>
    </Grid>
    {result && <Card title="Last simulation result"><table className={styles.table}><tbody><tr><td>Scenario</td><td>{result.mode}</td></tr><tr><td>Completed</td><td>{result.completed}/{result.requested}</td></tr><tr><td>HTTP statuses</td><td>{Object.entries(result.statuses).map(([status, total]) => <span key={status} style={{ marginRight: 10 }}>{status}: {total}</span>)}</td></tr><tr><td>Duration</td><td>{result.duration_ms} ms</td></tr><tr><td>Source sample</td><td>{result.source_ips.slice(0, 5).join(', ')}</td></tr></tbody></table></Card>}
    {history.data && <Card title="Recent simulation runs"><table className={styles.table}><thead><tr><th>Time</th><th>Scenario</th><th>Requests</th><th>Duration</th></tr></thead><tbody>{history.data.map((item) => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString()}</td><td>{item.mode}</td><td>{item.completed}/{item.requested}</td><td>{item.duration_ms} ms</td></tr>)}</tbody></table></Card>}
  </PlatformPage>
}

Component.displayName = 'AttackSimulationDashboard'
