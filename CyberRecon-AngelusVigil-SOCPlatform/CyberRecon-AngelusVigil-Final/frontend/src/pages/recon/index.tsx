import { type FormEvent, useMemo, useState } from 'react'
import {
  LuActivity,
  LuCircleAlert,
  LuClock3,
  LuGlobe,
  LuLoaderCircle,
  LuNetwork,
  LuRadar,
  LuServer,
} from 'react-icons/lu'
import { toast } from 'sonner'
import { usePersistentState } from '@/core/persistence'

import { useReconHistory, useReconScan } from '@/api/hooks'
import type { ReconResponse } from '@/api/types'
import styles from './recon.module.scss'

const COMMON_PORTS = [22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]

function Metric({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof LuGlobe
  label: string
  value: string | number
}): React.ReactElement {
  return (
    <div className={styles.metric}>
      <Icon className={styles.metricIcon} />
      <div>
        <span className={styles.metricValue}>{value}</span>
        <span className={styles.metricLabel}>{label}</span>
      </div>
    </div>
  )
}

export function Component(): React.ReactElement {
  const scan = useReconScan()
  const history = useReconHistory()

  const [domain, setDomain] = usePersistentState('tab-history-recon.domain', '')
  const [subdomains, setSubdomains] = usePersistentState('tab-history-recon.subdomains', true)
  const [ports, setPorts] = usePersistentState('tab-history-recon.ports', true)
  const [http, setHttp] = usePersistentState('tab-history-recon.http', true)
  const [selectedPorts, setSelectedPorts] = usePersistentState('tab-history-recon.selectedPorts', COMMON_PORTS)
  const [result, setResult] = useState<ReconResponse | null>(null)

  const openPortRows = useMemo(
    () => result?.ports ?? [],
    [result],
  )

  function togglePort(port: number) {
    setSelectedPorts((current) =>
      current.includes(port)
        ? current.filter((item) => item !== port)
        : [...current, port].sort((a, b) => a - b),
    )
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    const target = domain.trim()

    if (!target) {
      toast.error('Enter a domain or hostname.')
      return
    }

    if (ports && selectedPorts.length === 0) {
      toast.error('Select at least one port.')
      return
    }

    const response = await scan.mutateAsync({
      domain: target,
      include_subdomains: subdomains,
      include_ports: ports,
      include_http: http,
      ports: selectedPorts,
    })
    setResult(response)
  }

  return (
    <div className={styles.page}>
      <section className={styles.hero}>
        <div>
          <div className={styles.kicker}>
            <LuRadar /> Automated reconnaissance
          </div>
          <h2 className={styles.heading}>CyberRecon</h2>
          <p className={styles.description}>
            Discover DNS records, common subdomains, exposed TCP services and
            lightweight HTTP metadata for assets you are authorized to assess.
          </p>
        </div>
        <div className={styles.notice}>
          <LuCircleAlert />
          <span>Use only on systems you own or have explicit permission to assess.</span>
        </div>
      </section>

      <section className={styles.card}>
        <form onSubmit={handleSubmit}>
          <div className={styles.formGrid}>
            <label className={styles.field}>
              <span>Target domain</span>
              <input
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="example.com"
                autoComplete="off"
              />
            </label>

            <div className={styles.options}>
              <label className={styles.checkbox}>
                <input
                  type="checkbox"
                  checked={subdomains}
                  onChange={(event) => setSubdomains(event.target.checked)}
                />
                <span>Subdomain discovery</span>
              </label>
              <label className={styles.checkbox}>
                <input
                  type="checkbox"
                  checked={ports}
                  onChange={(event) => setPorts(event.target.checked)}
                />
                <span>Port discovery</span>
              </label>
              <label className={styles.checkbox}>
                <input
                  type="checkbox"
                  checked={http}
                  onChange={(event) => setHttp(event.target.checked)}
                />
                <span>HTTP metadata</span>
              </label>
            </div>
          </div>

          {ports && (
            <div className={styles.portSelector}>
              <div className={styles.sectionHeader}>
                <span>Common TCP ports</span>
                <span>{selectedPorts.length} selected</span>
              </div>
              <div className={styles.portGrid}>
                {COMMON_PORTS.map((port) => (
                  <button
                    key={port}
                    type="button"
                    className={`${styles.portButton} ${
                      selectedPorts.includes(port) ? styles.selected : ''
                    }`}
                    onClick={() => togglePort(port)}
                  >
                    {port}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className={styles.actions}>
            <button className={styles.scanButton} type="submit" disabled={scan.isPending}>
              {scan.isPending ? (
                <>
                  <LuLoaderCircle className={styles.spin} />
                  Scanning…
                </>
              ) : (
                <>
                  <LuActivity />
                  Start assessment
                </>
              )}
            </button>
          </div>
        </form>
      </section>

      {result && (
        <>
          <section className={styles.metrics}>
            <Metric icon={LuGlobe} label="IP addresses" value={result.summary.ip_count} />
            <Metric icon={LuNetwork} label="Subdomains" value={result.summary.subdomain_count} />
            <Metric icon={LuServer} label="Open ports" value={result.summary.open_port_count} />
            <Metric icon={LuClock3} label="Duration" value={`${result.summary.duration_ms} ms`} />
          </section>

          <div className={styles.resultGrid}>
            <section className={styles.card}>
              <div className={styles.sectionHeader}>
                <span>DNS records</span>
                <span>{result.target}</span>
              </div>
              <div className={styles.dnsList}>
                {Object.entries(result.dns.records).map(([type, values]) => (
                  <div key={type} className={styles.dnsRow}>
                    <span className={styles.recordType}>{type}</span>
                    <div className={styles.recordValues}>
                      {values.length
                        ? values.map((value) => <code key={value}>{value}</code>)
                        : <span className={styles.muted}>No record</span>}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className={styles.card}>
              <div className={styles.sectionHeader}>
                <span>Resolved addresses</span>
                <span>{result.dns.addresses.length}</span>
              </div>
              <div className={styles.addressList}>
                {result.dns.addresses.length ? (
                  result.dns.addresses.map((ip) => (
                    <div key={ip} className={styles.addressRow}>
                      <code>{ip}</code>
                      <span>{result.dns.reverse_dns[ip] ?? 'No PTR'}</span>
                    </div>
                  ))
                ) : (
                  <span className={styles.muted}>No addresses resolved.</span>
                )}
              </div>
            </section>
          </div>

          <div className={styles.resultGrid}>
            <section className={styles.card}>
              <div className={styles.sectionHeader}>
                <span>Subdomains</span>
                <span>{result.subdomains.length}</span>
              </div>
              {result.subdomains.length ? (
                <div className={styles.table}>
                  {result.subdomains.map((item) => (
                    <div className={styles.tableRow} key={item.subdomain}>
                      <code>{item.subdomain}</code>
                      <span>{item.addresses.join(', ')}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <span className={styles.muted}>No common subdomains resolved.</span>
              )}
            </section>

            <section className={styles.card}>
              <div className={styles.sectionHeader}>
                <span>Open TCP services</span>
                <span>{openPortRows.length}</span>
              </div>
              {openPortRows.length ? (
                <div className={styles.table}>
                  {openPortRows.map((item) => (
                    <div className={styles.tableRow} key={`${item.ip}-${item.port}`}>
                      <span>
                        <strong>{item.port}</strong> · {item.service}
                      </span>
                      <code>{item.ip}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <span className={styles.muted}>No selected TCP ports responded.</span>
              )}
            </section>
          </div>

          <section className={styles.card}>
            <div className={styles.sectionHeader}>
              <span>HTTP metadata</span>
              <span>{result.http.length} probes</span>
            </div>
            <div className={styles.table}>
              {result.http.map((item) => (
                <div className={styles.httpRow} key={item.url}>
                  <div>
                    <code>{item.url}</code>
                    <span>{item.title ?? 'No title'} · {item.content_type ?? 'unknown type'}</span>
                  </div>
                  <div className={styles.httpMeta}>
                    <strong>{item.status_code ?? '—'}</strong>
                    <span>{item.server ?? (item.technologies?.join(', ') || 'No server header')}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      <section className={styles.card}>
        <div className={styles.sectionHeader}>
          <span>Recent assessments</span>
          <span>{history.data?.total ?? 0}</span>
        </div>
        {history.isLoading ? (
          <div className={styles.muted}></div>
        ) : history.data?.items.length ? (
          <div className={styles.history}>
            {history.data.items.map((item) => (
              <button
                type="button"
                className={styles.historyRow}
                key={item.id}
                onClick={() => toast.info(`Scan ${item.target} completed in ${item.duration_ms} ms`)}
              >
                <span>
                  <strong>{item.target}</strong>
                  <small>{new Date(item.created_at).toLocaleString()}</small>
                </span>
                <span>{item.duration_ms} ms</span>
              </button>
            ))}
          </div>
        ) : (
          <span className={styles.muted}>No assessments yet.</span>
        )}
      </section>
    </div>
  )
}

Component.displayName = 'ReconPage'
