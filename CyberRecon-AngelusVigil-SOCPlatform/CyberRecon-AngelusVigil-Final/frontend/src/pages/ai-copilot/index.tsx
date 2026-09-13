import { useEffect, useMemo, useState } from 'react'
import { LuBrainCircuit, LuFileSearch, LuLoaderCircle, LuRadar, LuSend, LuShieldCheck, LuSparkles, LuWandSparkles } from 'react-icons/lu'
import { apiClient } from '@/core/api'
import { API_ENDPOINTS } from '@/config'
import { AIAnalysisResponseSchema, AIStatusSchema, type SecurityAnalysis, type AIStatus } from '@/api/types'
import type { ReconResponse } from '@/api/types'
import { usePersistentState } from '@/core/persistence'
import s from './ai-workspace.module.scss'

type Message = { id: number; role: 'user' | 'assistant'; content: string; analysis?: SecurityAnalysis }
type AIContext = { source: 'CyberRecon'; scan: ReconResponse }

const QUICK_PROMPTS = [
  'Summarize the highest-risk findings from this scan.',
  'Explain what I should investigate first and why.',
  'Recommend the safest remediation priorities for this scan.',
]

function AnalysisCard({ analysis }: { analysis: SecurityAnalysis }): React.ReactElement {
  return <div className={s.analysis}>
    <div className={s.risk}><span>Risk</span><strong>{analysis.risk}</strong></div>
    {analysis.findings.length ? analysis.findings.map((finding, index) => <article className={s.finding} key={`${finding.title}-${index}`}>
      <div className={s.findingHeader}><strong>{finding.title}</strong><span>{finding.severity}</span></div>
      <p><b>Impact:</b> {finding.impact}</p>
      <p><b>Remediation:</b> {finding.remediation}</p>
      <div className={s.evidence}><b>Evidence</b>{finding.evidence.map((item) => <code key={`${item.path}-${item.value}`}>{item.path} = {item.value}</code>)}</div>
    </article>) : <p className={s.noFindings}>No evidence-backed findings were returned for this scan.</p>}
    <p className={s.summary}><b>Summary:</b> {analysis.summary}</p>
  </div>
}

export function Component(): React.ReactElement {
  const [question, setQuestion] = useState('')
  const [messages, setMessages] = usePersistentState<Message[]>('ai-workspace.messages', [])
  const [context] = usePersistentState<AIContext | null>('ai-workspace.context', null)
  const [status, setStatus] = useState<AIStatus | null>(null)
  const [busy, setBusy] = useState(false)

  const hasMessages = messages.length > 0
  const scan = context?.scan ?? null
  const contextSummary = useMemo(() => scan ? `${scan.target} • ${scan.vulnerabilities.length} recorded findings • ${scan.summary.open_port_count} open ports` : 'No CyberRecon scan attached', [scan])
  const providerSummary = status?.available && status.model_installed ? `Local Ollama • ${status.model}` : status?.enabled ? 'Ollama unavailable' : 'Ollama disabled'

  useEffect(() => {
    let active = true
    void apiClient.get<unknown>(API_ENDPOINTS.AI.STATUS).then((response) => {
      if (active) setStatus(AIStatusSchema.parse(response.data))
    }).catch(() => {
      if (active) setStatus(null)
    })
    return () => { active = false }
  }, [])

  async function ask(text?: string): Promise<void> {
    const prompt = (text ?? question).trim()
    if (!prompt || busy || !scan) return
    const userMessage: Message = { id: Date.now(), role: 'user', content: prompt }
    setMessages((current) => [...current, userMessage])
    setQuestion('')
    setBusy(true)
    try {
      const response = await apiClient.post<unknown>(API_ENDPOINTS.AI.ANALYZE, { question: prompt, scan_data: scan }, { timeout: 60_000 })
      const result = AIAnalysisResponseSchema.parse(response.data)
      setMessages((current) => [...current, { id: Date.now() + 1, role: 'assistant', content: result.answer, analysis: result.analysis }])
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'Local Ollama analysis failed.'
      setMessages((current) => [...current, { id: Date.now() + 1, role: 'assistant', content: `Unable to complete the grounded analysis. ${detail}` }])
    } finally {
      setBusy(false)
    }
  }

  return <div className={s.page}>
    <div className={s.hero}>
      <div>
        <div className={s.kicker}><LuSparkles /> CYBERSENTINEL // LOCAL INTELLIGENCE</div>
        <h2 className={s.title}>Security AI Workspace</h2>
        <p className={s.subtitle}>Review an actual CyberRecon result with the optional local model. No cloud provider or public Ollama endpoint is used.</p>
      </div>
      <div className={s.status}><i /> {providerSummary}</div>
    </div>

    <div className={s.workspace}>
      <section className={s.chat} aria-label="AI security workspace">
        <div className={s.messages}>
          {!hasMessages ? <div className={s.empty}>
            <div className={s.emptyInner}>
              <div className={s.orb}><LuBrainCircuit /></div>
              <h2>{scan ? 'What should we investigate?' : 'Run a CyberRecon assessment first'}</h2>
              <p>{scan ? `Attached scan: ${contextSummary}. Every displayed finding must be grounded in that result.` : 'The analyzer does not accept free-form telemetry or invent findings. Run CyberRecon, then return here to attach its real result.'}</p>
              <div className={s.quick}>{QUICK_PROMPTS.map((prompt) => <button key={prompt} type="button" disabled={!scan || busy} onClick={() => void ask(prompt)}>{prompt}</button>)}</div>
            </div>
          </div> : messages.map((message) => <div className={`${s.message} ${message.role === 'user' ? s.user : ''}`} key={message.id}><div className={s.bubble}><div className={s.role}>{message.role === 'user' ? 'OPERATOR' : 'CYBERSENTINEL // OLLAMA'}</div>{message.analysis ? <AnalysisCard analysis={message.analysis} /> : message.content}</div></div>)}
        </div>
        <div className={s.composer}>
          <div className={s.composerBox}>
            <textarea className={s.textarea} value={question} disabled={!scan || busy} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void ask() } }} placeholder={scan ? 'Ask about the attached scan…' : 'Run CyberRecon to attach scan data…'} aria-label="Message CyberSentinel" />
            <button type="button" className={s.send} disabled={busy || !scan || !question.trim()} onClick={() => void ask()} aria-label="Send message">{busy ? <LuLoaderCircle className={s.spin} /> : <LuSend />}</button>
          </div>
          <div className={s.controls}>
            <span className={s.control}>Provider <strong>{providerSummary}</strong></span>
            <span className={s.control}>Context <strong>{contextSummary}</strong></span>
            <span className={s.control}>Mode <strong>Grounded defensive analysis</strong></span>
            {busy && <span className={s.control}><strong>Analyzing…</strong></span>}
          </div>
        </div>
      </section>

      <aside className={s.side}>
        <section className={s.panel}><h3>Workspace status</h3><p>The existing recon scanner remains unchanged. Its latest result is passed through the backend only when you request analysis.</p><div className={s.agent}><span className={s.agentDot} /><div className={s.agentText}><div className={s.agentName}>Scan context</div><div className={s.agentMeta}>{contextSummary}</div></div></div></section>
        <section className={s.panel}><h3>Security actions</h3><button className={s.action} type="button" disabled={!scan || busy} onClick={() => void ask('Analyze the most suspicious findings in this scan.')}><LuShieldCheck /> Prioritize suspicious findings</button><button className={s.action} type="button" disabled={!scan || busy} onClick={() => void ask('Explain the likely impact of the highest severity findings.')}><LuRadar /> Explain threat impact</button><button className={s.action} type="button" disabled={!scan || busy} onClick={() => void ask('Suggest the safest next investigative steps for this scan.')}><LuWandSparkles /> Suggest next steps</button><button className={s.action} type="button" disabled={!scan || busy} onClick={() => void ask('Summarize this scan for a security report.')}><LuFileSearch /> Prepare report summary</button></section>
        <section className={s.panel}><h3>Local model</h3><div className={s.agent}><span className={s.agentDot} style={{ background: status?.available && status.model_installed ? '#00e5ff' : '#f59e0b', boxShadow: status?.available && status.model_installed ? '0 0 10px rgba(0,229,255,.65)' : '0 0 10px rgba(245,158,11,.45)' }} /><div className={s.agentText}><div className={s.agentName}>Ollama adapter</div><div className={s.agentMeta}>{status?.model ?? 'Status unavailable'}</div></div></div><div className={s.notice}>{scan ? 'Only the attached scan is sent to the local backend adapter. The adapter rejects ungrounded evidence.' : 'No scan is attached. Existing recon functionality remains available from the CyberRecon page.'}</div></section>
      </aside>
    </div>
  </div>
}

Component.displayName = 'AIWorkspace'
