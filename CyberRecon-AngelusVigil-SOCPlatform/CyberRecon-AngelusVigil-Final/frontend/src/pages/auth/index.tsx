import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { readStored } from '@/core/persistence'
import s from '../shared.module.scss'

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const token = readStored<string | null>('cybersentinel_token', null)
  const [mode, setMode] = useState<'signin'|'register'|'forgot'>('signin')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('viewer')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  if (token) return <Navigate to="/" replace />

  async function submit() {
    setBusy(true); setMessage('')
    try {
      if (mode === 'signin') {
        const { data } = await apiClient.post('/auth/login', { username, password })
        sessionStorage.setItem('cybersentinel_token', data.token)
        sessionStorage.setItem('cybersentinel_user', JSON.stringify({ username: data.username, display_name: data.display_name, role: data.role, permissions: data.permissions }))
        navigate('/', { replace: true })
      } else if (mode === 'register') {
        await apiClient.post('/auth/register', { username, password, display_name: displayName || username, role })
        setMode('signin'); setMessage('Account created. Sign in to continue.')
      } else {
        await apiClient.post('/auth/forgot-password', { username })
        setMessage('Reset request accepted. Contact the deployment administrator for the reset flow.')
      }
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Request failed')
    } finally { setBusy(false) }
  }

  return <div className={s.page} style={{minHeight:'100vh',display:'grid',placeItems:'center'}}>
    <div className={`${s.card} ${s.auth}`} style={{maxWidth:460,width:'100%'}}>
      <div className={s.hero}><div><h2 className={s.title}>CyberSentinel</h2><p className={s.sub}>{mode==='signin'?'Secure SOC sign in':mode==='register'?'Create secure operator account':'Password recovery'}</p></div><span className={s.notice}>Protected workspace</span></div>
      {mode==='register' && <label className={s.label}>Display name<input className={s.input} value={displayName} onChange={e=>setDisplayName(e.target.value)} /></label>}
      <label className={s.label}>Username<input className={s.input} autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} /></label>
      {mode!=='forgot' && <label className={s.label}>Password<input className={s.input} type="password" autoComplete={mode==='signin'?'current-password':'new-password'} value={password} onChange={e=>setPassword(e.target.value)} /></label>}
      {mode==='register' && <label className={s.label}>Role<select className={s.select} value={role} onChange={e=>setRole(e.target.value)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></label>}
      {message && <div className={s.notice} style={{marginBottom:12}}>{message}</div>}
      <button className={s.button} disabled={busy || !username || (mode!=='forgot'&&!password)} onClick={submit}>{busy?'Please wait…':mode==='signin'?'Sign in':mode==='register'?'Create account':'Send reset request'}</button>
      <div className={s.row} style={{marginTop:12,flexWrap:'wrap'}}>
        <button className={`${s.tab} ${mode==='signin'?s.active:''}`} onClick={()=>setMode('signin')}>Sign in</button>
        <button className={`${s.tab} ${mode==='register'?s.active:''}`} onClick={()=>setMode('register')}>Register</button>
        <button className={`${s.tab} ${mode==='forgot'?s.active:''}`} onClick={()=>setMode('forgot')}>Forgot password</button>
      </div>
      <p className={s.muted} style={{marginTop:14}}>Passwords are hashed server-side and the application never displays seeded credentials.</p>
    </div>
  </div>
}
Component.displayName='AuthPage'
