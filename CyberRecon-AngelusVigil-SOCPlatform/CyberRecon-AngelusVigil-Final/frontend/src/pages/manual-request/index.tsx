import { useEffect, useState } from 'react'
import { apiClient } from '@/core/api'
import { API_ENDPOINTS, STORAGE_KEYS } from '@/config'
import { usePersistentState } from '@/core/persistence'
import { Card, Grid, PlatformPage, Stats, platformStyles as styles } from '@/components/platform-dashboard'

type Result = {
  id: string
  ok: boolean
  status_code: number
  reason: string
  url: string
  headers: Record<string, string>
  body: string
  simulated_source_ip?: string
  profile: string
  method: string
  path: string
}
type HistoryItem = Omit<Result, 'profile' | 'headers' | 'body' | 'ok' | 'url'> & { created_at: string; target_url: string }

export function Component(): React.ReactElement {
  const [targetUrl, setTargetUrl] = usePersistentState(`${STORAGE_KEYS.MANUAL}.target`, 'http://devlog-nginx')
  const [method, setMethod] = usePersistentState(`${STORAGE_KEYS.MANUAL}.method`, 'GET')
  const [path, setPath] = usePersistentState(`${STORAGE_KEYS.MANUAL}.path`, '/health')
  const [query, setQuery] = usePersistentState(`${STORAGE_KEYS.MANUAL}.query`, '{}')
  const [headers, setHeaders] = usePersistentState(`${STORAGE_KEYS.MANUAL}.headers`, '{}')
  const [body, setBody] = usePersistentState(`${STORAGE_KEYS.MANUAL}.body`, '{}')
  const [simulateIp, setSimulateIp] = usePersistentState(`${STORAGE_KEYS.MANUAL}.simulateIp`, true)
  const [randomizeRequest, setRandomizeRequest] = usePersistentState(`${STORAGE_KEYS.MANUAL}.randomize`, true)
  const [result, setResult] = useState<Result | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function loadHistory(): Promise<void> {
    try { setHistory((await apiClient.get<HistoryItem[]>('/manual-request/history')).data) } catch { /* request errors surface on send */ }
  }

  useEffect(() => { void loadHistory() }, [])

  async function send(): Promise<void> {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const parsedQuery = JSON.parse(query || '{}') as Record<string, string>
      const parsedHeaders = JSON.parse(headers || '{}') as Record<string, string>
      const parsedBody = randomizeRequest || ['GET', 'HEAD', 'OPTIONS'].includes(method) ? undefined : JSON.parse(body || '{}') as Record<string, unknown>
      const { data } = await apiClient.post<Result>(API_ENDPOINTS.MANUAL_REQUEST, {
        target_url: targetUrl,
        method,
        path,
        query: parsedQuery,
        headers: parsedHeaders,
        body: parsedBody,
        simulate_source_ip: simulateIp,
        randomize_request: randomizeRequest,
      })
      setResult(data)
      await loadHistory()
    } catch (cause: unknown) {
      const response = cause as { response?: { data?: { detail?: string } }; message?: string }
      setError(response.response?.data?.detail ?? response.message ?? 'Request failed')
    } finally { setLoading(false) }
  }

  return <PlatformPage title="Manual Request Console" subtitle="Each run receives a new private lab IP and can use a varied, safe local traffic profile.">
    <Stats items={[
      { label: 'Requests stored', value: history.length, meta: 'Backend history' },
      { label: 'Traffic mode', value: randomizeRequest ? 'VARIED' : 'CUSTOM', meta: randomizeRequest ? 'Profile selected per request' : 'Your request fields' },
      { label: 'Source simulation', value: simulateIp ? 'RANDOM IP' : 'SERVER IP', meta: 'Telemetry source' },
      { label: 'Last response', value: result?.status_code ?? '—', meta: result?.reason ?? 'No request yet' },
    ]} />
    <Card title="Request builder">
      <label style={{ display: 'flex', gap: 8, marginBottom: 14 }}><input type="checkbox" checked={randomizeRequest} onChange={(event) => setRandomizeRequest(event.target.checked)} /> <span><strong>Vary each request automatically</strong> — rotates safe baseline, scanner, traversal, SQLi, XSS and command-pattern lab paths.</span></label>
      <div className={styles.formGrid}>
        <div className={styles.field}><label>Target URL</label><input value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://devlog-nginx" /></div>
        <div className={styles.field}><label>Method</label><select value={method} disabled={randomizeRequest} onChange={(event) => setMethod(event.target.value)}>{['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'].map((value) => <option key={value}>{value}</option>)}</select></div>
        <div className={styles.field}><label>Path</label><input value={path} disabled={randomizeRequest} onChange={(event) => setPath(event.target.value)} placeholder="/health" /></div>
        <div className={styles.field}><label>Query JSON</label><textarea value={query} disabled={randomizeRequest} onChange={(event) => setQuery(event.target.value)} /></div>
        <div className={styles.field}><label>Headers JSON</label><textarea value={headers} disabled={randomizeRequest} onChange={(event) => setHeaders(event.target.value)} /></div>
        <div className={styles.field}><label>Body JSON</label><textarea value={body} disabled={randomizeRequest || ['GET', 'HEAD', 'OPTIONS'].includes(method)} onChange={(event) => setBody(event.target.value)} /></div>
      </div>
      <label style={{ display: 'flex', gap: 8, marginTop: 12 }}><input type="checkbox" checked={simulateIp} onChange={(event) => setSimulateIp(event.target.checked)} /> Use a distinct private lab source IP for telemetry</label>
      <div className={styles.actions} style={{ marginTop: 12 }}><button className={styles.button} disabled={loading} onClick={() => void send()}>{loading ? 'Sending…' : 'Send request'}</button><span className={styles.muted}>Only allowlisted local targets can receive traffic.</span></div>
      {error && <div className={styles.callout} style={{ marginTop: 12 }}>{error}</div>}
    </Card>
    <Grid>
      <Card title="Response"><pre style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>{result ? result.body : (error || 'No response yet.')}</pre></Card>
      <Card title="Telemetry metadata">{result ? <table className={styles.table}><tbody><tr><td>Profile</td><td>{result.profile}</td></tr><tr><td>Request</td><td>{result.method} {result.path}</td></tr><tr><td>Lab source</td><td>{result.simulated_source_ip || 'Server IP'}</td></tr><tr><td>Status</td><td>{result.status_code} {result.reason}</td></tr></tbody></table> : <div className={styles.callout}>The pipeline scores the observed request and creates a linked SOC operation automatically. Profiles produce varied evidence and severities; no UI severity is forced.</div>}</Card>
    </Grid>
    <Card title="Manual request history"><table className={styles.table}><thead><tr><th>Time</th><th>Target</th><th>Method</th><th>Path</th><th>Status</th><th>Lab IP</th></tr></thead><tbody>{history.map((item) => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString()}</td><td>{item.target_url}</td><td>{item.method}</td><td>{item.path}</td><td>{item.status_code} {item.reason}</td><td>{item.simulated_source_ip || '—'}</td></tr>)}</tbody></table>{!history.length && <div className={styles.muted}>No manual requests yet.</div>}</Card>
  </PlatformPage>
}

Component.displayName = 'ManualRequestPage'
