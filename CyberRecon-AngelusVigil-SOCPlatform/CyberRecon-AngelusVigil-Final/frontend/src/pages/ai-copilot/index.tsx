import { useMemo, useState } from 'react'
import { LuBot, LuBrainCircuit, LuFileSearch, LuRadar, LuSend, LuShieldCheck, LuSparkles, LuWandSparkles } from 'react-icons/lu'
import { apiClient } from '@/core/api'
import { usePersistentState } from '@/core/persistence'
import s from './ai-workspace.module.scss'

type Message = { id: number; role: 'user' | 'assistant'; content: string }

type Context = Record<string, unknown>

const QUICK_PROMPTS = [
  'Summarize the highest-risk findings from the current telemetry.',
  'Explain what I should investigate first and why.',
  'Review this environment for suspicious indicators.',
]

export function Component(): React.ReactElement {
  const [question, setQuestion] = useState('')
  const [messages, setMessages] = usePersistentState<Message[]>('ai-workspace.messages', [])
  const [context] = usePersistentState<Context>('ai-workspace.context', {})
  const [busy, setBusy] = useState(false)

  const hasMessages = messages.length > 0
  const contextSummary = useMemo(() => Object.keys(context).length ? `${Object.keys(context).length} context fields attached` : 'No telemetry context attached', [context])

  async function ask(text?: string): Promise<void> {
    const prompt = (text ?? question).trim()
    if (!prompt || busy) return
    const userMessage: Message = { id: Date.now(), role: 'user', content: prompt }
    setMessages((current) => [...current, userMessage])
    setQuestion('')
    setBusy(true)
    try {
      const response = await apiClient.post('/ai/analyze', { question: prompt, context })
      const answer = response.data?.answer ?? 'The analysis service returned no answer.'
      setMessages((current) => [...current, { id: Date.now() + 1, role: 'assistant', content: answer }])
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'AI request failed.'
      setMessages((current) => [...current, { id: Date.now() + 1, role: 'assistant', content: `Unable to complete the analysis. ${detail}` }])
    } finally {
      setBusy(false)
    }
  }

  return <div className={s.page}>
    <div className={s.hero}>
      <div>
        <div className={s.kicker}><LuSparkles /> CYBERSENTINEL // INTELLIGENCE WORKSPACE</div>
        <h2 className={s.title}>Security AI Workspace</h2>
        <p className={s.subtitle}>Investigate telemetry, explain findings, and prepare defensive decisions from one focused command console.</p>
      </div>
      <div className={s.status}><i /> ANALYSIS CHANNEL ACTIVE</div>
    </div>

    <div className={s.workspace}>
      <section className={s.chat} aria-label="AI security workspace">
        <div className={s.messages}>
          {!hasMessages ? <div className={s.empty}>
            <div className={s.emptyInner}>
              <div className={s.orb}><LuBrainCircuit /></div>
              <h2>What should we investigate?</h2>
              <p>Ask CyberSentinel to explain telemetry, prioritize suspicious activity, or turn security findings into a clear next-action plan.</p>
              <div className={s.quick}>{QUICK_PROMPTS.map((prompt) => <button key={prompt} type="button" onClick={() => void ask(prompt)}>{prompt}</button>)}</div>
            </div>
          </div> : messages.map((message) => <div className={`${s.message} ${message.role === 'user' ? s.user : ''}`} key={message.id}><div className={s.bubble}><div className={s.role}>{message.role === 'user' ? 'OPERATOR' : 'CYBERSENTINEL AI'}</div>{message.content}</div></div>)}
        </div>
        <div className={s.composer}>
          <div className={s.composerBox}>
            <textarea className={s.textarea} value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void ask() } }} placeholder="Message CyberSentinel…" aria-label="Message CyberSentinel" />
            <button type="button" className={s.send} disabled={busy || !question.trim()} onClick={() => void ask()} aria-label="Send message"><LuSend /></button>
          </div>
          <div className={s.controls}>
            <span className={s.control}>Provider <strong>Backend analysis</strong></span>
            <span className={s.control}>Context <strong>{contextSummary}</strong></span>
            <span className={s.control}>Mode <strong>Defensive analysis</strong></span>
            {busy && <span className={s.control}><strong>Analyzing…</strong></span>}
          </div>
        </div>
      </section>

      <aside className={s.side}>
        <section className={s.panel}><h3>Workspace status</h3><p>The current UI is ready for the local-model adapter. Existing backend analysis remains unchanged until Ollama is connected.</p><div className={s.agent}><span className={s.agentDot} /><div className={s.agentText}><div className={s.agentName}>Security analysis channel</div><div className={s.agentMeta}>Connected to existing `/ai/analyze` endpoint</div></div></div></section>
        <section className={s.panel}><h3>Security actions</h3><button className={s.action} type="button" onClick={() => void ask('Analyze the most suspicious findings in the current telemetry.')}><LuShieldCheck /> Prioritize suspicious findings</button><button className={s.action} type="button" onClick={() => void ask('Explain the likely impact of the highest severity events.')}><LuRadar /> Explain threat impact</button><button className={s.action} type="button" onClick={() => void ask('Suggest the safest next investigative steps for the current environment.')}><LuWandSparkles /> Suggest next steps</button><button className={s.action} type="button" onClick={() => void ask('Summarize the current environment for a security report.')}><LuFileSearch /> Prepare report summary</button></section>
        <section className={s.panel}><h3>Local model</h3><div className={s.agent}><span className={s.agentDot} style={{ background: '#c43cff', boxShadow: '0 0 10px rgba(196,60,255,.55)' }} /><div className={s.agentText}><div className={s.agentName}>Ollama adapter</div><div className={s.agentMeta}>UI ready • backend connection next</div></div></div><div className={s.notice}>No local model call is claimed yet. This panel will switch to Ollama once the server-side adapter is added and tested.</div></section>
      </aside>
    </div>
  </div>
}

Component.displayName = 'AIWorkspace'
