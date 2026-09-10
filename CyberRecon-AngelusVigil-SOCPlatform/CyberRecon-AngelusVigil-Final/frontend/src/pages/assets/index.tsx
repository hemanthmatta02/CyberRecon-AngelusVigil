import { useState } from 'react'
import { useReconHistory, useReconScan } from '@/api/hooks'
import type { ReconResponse } from '@/api/types'
import { usePersistentState } from '@/core/persistence'
import s from '../shared.module.scss'

const PORTS = [22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]
type Assessment = 'full' | 'subdomains' | 'dns' | 'ports' | 'http'

export function Component(): React.ReactElement {
  const scan = useReconScan()
  const history = useReconHistory()
  const [target, setTarget] = usePersistentState('tab-history-assets.target', '')
  const [assessment, setAssessment] = usePersistentState<Assessment>('tab-history-assets.assessment', 'full')
  const [selectedPorts, setSelectedPorts] = usePersistentState<number[]>('tab-history-assets.ports', [22, 80, 443, 8080])
  const [result, setResult] = useState<ReconResponse | null>(null)
  const [error, setError] = useState('')

  function togglePort(port: number): void {
    setSelectedPorts((current) => current.includes(port) ? current.filter((item) => item !== port) : [...current, port].sort((a, b) => a - b))
  }

  async function run(): Promise<void> {
    const domain = target.trim()
    if (!domain) { setError('Enter a domain, hostname, or authorized private target.'); return }
    if ((assessment === 'full' || assessment === 'ports') && !selectedPorts.length) { setError('Select at least one port for this assessment.'); return }
    setError('')
    try {
      setResult(await scan.mutateAsync({
        domain,
        include_subdomains: assessment === 'full' || assessment === 'subdomains',
        include_ports: assessment === 'full' || assessment === 'ports',
        include_http: assessment === 'full' || assessment === 'http',
        ports: selectedPorts,
      }))
    } catch (cause: unknown) {
      const response = cause as { response?: { data?: { detail?: string } }; message?: string }
      setError(response.response?.data?.detail ?? response.message ?? 'Asset discovery failed.')
    }
  }

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Asset Discovery</h2><p className={s.sub}>A clean inventory view for authorized DNS, subdomain, port, and HTTP discovery.</p></div><span className={s.notice}>Authorized targets only</span></div>
    <section className={s.card}><div className={s.grid}><label className={s.label}>Target domain / hostname<input className={s.input} value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com or 127.0.0.1" /></label><label className={s.label}>Discovery scope<select className={s.select} value={assessment} onChange={(event) => setAssessment(event.target.value as Assessment)}><option value="full">Full inventory</option><option value="subdomains">Subdomains</option><option value="dns">DNS only</option><option value="ports">TCP ports</option><option value="http">HTTP technologies</option></select></label></div>{(assessment === 'full' || assessment === 'ports') && <div style={{ marginTop: 14 }}><div className={s.label}>TCP ports</div><div className={s.tabs} style={{ marginTop: 8 }}>{PORTS.map((port) => <button key={port} type="button" className={`${s.tab} ${selectedPorts.includes(port) ? s.active : ''}`} onClick={() => togglePort(port)}>{port}</button>)}</div></div>}<div className={s.row} style={{ marginTop: 14 }}><button type="button" className={s.button} disabled={scan.isPending} onClick={() => void run()}>{scan.isPending ? 'Discovering…' : 'Run discovery'}</button><span className={s.muted}>Results are stored in the shared recon history.</span></div>{error && <div className={s.notice} style={{ marginTop: 12, borderColor: '#7f3540', color: '#ffb2ba' }}>{error}</div>}</section>
    {result && <><div className={s.kpis}><div className={s.kpi}><small>IP addresses</small><strong>{result.summary.ip_count}</strong></div><div className={s.kpi}><small>Subdomains</small><strong>{result.summary.subdomain_count}</strong></div><div className={s.kpi}><small>Open ports</small><strong>{result.summary.open_port_count}</strong></div><div className={s.kpi}><small>HTTP endpoints</small><strong>{result.summary.http_endpoint_count}</strong></div><div className={s.kpi}><small>Duration</small><strong>{result.summary.duration_ms} ms</strong></div></div><div className={s.grid}><section className={s.card}><h3>DNS records</h3><table className={s.table}><tbody>{Object.entries(result.dns.records).map(([type, values]) => <tr key={type}><th>{type}</th><td>{values.length ? values.map((value) => <code key={value} style={{ display: 'block' }}>{value}</code>) : <span className={s.muted}>No record</span>}</td></tr>)}</tbody></table></section><section className={s.card}><h3>Subdomains</h3>{result.subdomains.length ? <table className={s.table}><thead><tr><th>Host</th><th>Status</th><th>Addresses</th></tr></thead><tbody>{result.subdomains.map((item) => <tr key={item.subdomain}><td>{item.subdomain}</td><td>{item.status ?? '—'}</td><td>{item.addresses.join(', ') || '—'}</td></tr>)}</tbody></table> : <div className={s.empty}>No subdomains returned for this scope.</div>}</section></div><section className={s.card}><h3>Open TCP services</h3>{result.ports.length ? <table className={s.table}><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>{result.ports.map((item) => <tr key={`${item.ip}-${item.port}`}><td>{item.ip}</td><td>{item.port}</td><td>{item.service}</td><td>{item.version ?? 'No banner'}</td></tr>)}</tbody></table> : <div className={s.empty}>No selected ports responded.</div>}</section><section className={s.card}><h3>HTTP technologies</h3>{result.http.length ? result.http.map((item) => <div className={s.notice} style={{ marginBottom: 8 }} key={item.url}><strong>{item.status_code ?? '—'}</strong> {item.url}<br /><span className={s.muted}>{item.technologies.join(', ') || item.server || 'Technology not disclosed'}{item.title ? ` · ${item.title}` : ''}</span></div>) : <div className={s.empty}>HTTP discovery was not selected.</div>}</section></>}
    <section className={s.card}><div className={s.row} style={{ justifyContent: 'space-between' }}><h3 style={{ margin: 0 }}>Recent discovery runs</h3><span className={s.muted}>{history.data?.total ?? 0} total</span></div>{history.isLoading ? <div className={s.muted}>Loading history…</div> : history.data?.items.length ? <table className={s.table}><thead><tr><th>Time</th><th>Target</th><th>Scope</th><th>Status</th><th>Duration</th></tr></thead><tbody>{history.data.items.map((item) => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString()}</td><td>{item.target}</td><td>{item.scan_type}</td><td>{item.status}</td><td>{item.duration_ms} ms</td></tr>)}</tbody></table> : <div className={s.empty}>No discovery runs yet.</div>}</section>
  </div>
}

Component.displayName = 'AssetDiscovery'
