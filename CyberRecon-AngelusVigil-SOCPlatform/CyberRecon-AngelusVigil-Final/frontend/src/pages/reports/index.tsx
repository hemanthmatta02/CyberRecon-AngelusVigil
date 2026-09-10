import { useState } from 'react'
import { usePlatform } from '@/api/hooks/usePlatform'
import { apiClient } from '@/core/api'
import s from '../shared.module.scss'

type ReportSummary = { generated_at: string; last_24h_threats: number; incidents_total: number; recon_scans_total: number; formats: string[] }
type Format = 'pdf' | 'json' | 'csv'

export function Component(): React.ReactElement {
  const { data, isLoading, refetch } = usePlatform<ReportSummary>('reports', '/platform/reports')
  const [downloading, setDownloading] = useState<Format | null>(null)
  const [message, setMessage] = useState('')

  async function exportReport(format: Format): Promise<void> {
    setDownloading(format)
    setMessage('')
    try {
      const response = await apiClient.get(`/security/reports/export/${format}`, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data as Blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `cybersentinel-report.${format}`
      anchor.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 500)
      setMessage(`${format.toUpperCase()} report downloaded.`)
    } catch { setMessage('Report export failed. Check the API connection and retry.') } finally { setDownloading(null) }
  }

  return <div className={s.page}>
    <div className={s.hero}><div><h2 className={s.title}>Reports & Evidence</h2><p className={s.sub}>A compact export center for the current local SOC evidence set.</p></div><button className={`${s.button} ${s.secondary}`} onClick={() => void refetch()}>Refresh summary</button></div>
    <section className={s.card}><div className={s.kpis}><div className={s.kpi}><small>Threats / 24h</small><strong>{isLoading ? '—' : data?.last_24h_threats ?? 0}</strong></div><div className={s.kpi}><small>Total operations</small><strong>{isLoading ? '—' : data?.incidents_total ?? 0}</strong></div><div className={s.kpi}><small>Recon scans</small><strong>{isLoading ? '—' : data?.recon_scans_total ?? 0}</strong></div><div className={s.kpi}><small>Formats</small><strong>{data?.formats.length ?? 3}</strong></div><div className={s.kpi}><small>Snapshot</small><strong>{data ? new Date(data.generated_at).toLocaleTimeString() : '—'}</strong></div></div></section>
    <div className={s.grid}>
      <section className={s.card}><h3>Export package</h3><p className={s.sub}>Exports include observed threat evidence, assessed vulnerabilities, discovered assets and incident status at generation time.</p><div className={s.row} style={{ marginTop: 16 }}><button className={s.button} disabled={downloading !== null} onClick={() => void exportReport('pdf')}>{downloading === 'pdf' ? 'Preparing PDF…' : 'Download PDF'}</button><button className={s.button} disabled={downloading !== null} onClick={() => void exportReport('json')}>{downloading === 'json' ? 'Preparing JSON…' : 'Download JSON'}</button><button className={`${s.button} ${s.secondary}`} disabled={downloading !== null} onClick={() => void exportReport('csv')}>{downloading === 'csv' ? 'Preparing CSV…' : 'Download CSV'}</button></div>{message && <div className={s.callout} style={{ marginTop: 12 }}>{message}</div>}</section>
      <section className={s.card}><h3>Format guide</h3><div className={s.notice}><strong>PDF</strong><br />Executive-ready human summary.</div><div className={s.notice} style={{ marginTop: 8 }}><strong>JSON</strong><br />Complete machine-readable evidence package.</div><div className={s.notice} style={{ marginTop: 8 }}><strong>CSV</strong><br />Threat event data for spreadsheets and SIEM import.</div></section>
    </div>
    <section className={s.card}><h3>Evidence scope</h3><div className={s.grid3}><div className={s.notice}>Threat events and matched evidence</div><div className={s.notice}>Vulnerability findings and recommendations</div><div className={s.notice}>Asset discovery and incident workflow state</div></div></section>
  </div>
}

Component.displayName = 'ReportsEvidence'
