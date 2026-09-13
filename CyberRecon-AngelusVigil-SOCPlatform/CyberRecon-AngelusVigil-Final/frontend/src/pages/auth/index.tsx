import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { readStored, writeStored } from '@/core/persistence'
import s from '../shared.module.scss'

type AuthMode = 'signin' | 'register'

type SessionUser = {
  username: string
  display_name: string
  role: string
  permissions: string[]
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const token = readStored<string | null>('cybersentinel_token', null)
  const [mode, setMode] = useState<AuthMode>('signin')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('viewer')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  if (token) return <Navigate to="/" replace />

  function switchMode(nextMode: AuthMode): void {
    setMode(nextMode)
    setMessage('')
    setPassword('')
    setConfirmPassword('')
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    try {
      const cleanUsername = username.trim().toLowerCase()
      if (mode === 'signin') {
        const { data } = await apiClient.post('/auth/login', { username: cleanUsername, password })
        const user: SessionUser = {
          username: data.username,
          display_name: data.display_name,
          role: data.role,
          permissions: data.permissions,
        }
        writeStored('cybersentinel_token', data.token)
        writeStored('cybersentinel_user', user)
        navigate('/', { replace: true })
        return
      }

      if (password !== confirmPassword) {
        setMessage('Passwords do not match.')
        return
      }
      await apiClient.post('/auth/register', {
        username: cleanUsername,
        password,
        display_name: displayName.trim() || cleanUsername,
        role,
      })
      setMode('signin')
      setPassword('')
      setConfirmPassword('')
      setDisplayName('')
      setMessage(`Account created for ${cleanUsername}. Sign in with the same username and password.`)
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  const valid = mode === 'signin'
    ? username.trim().length >= 3 && password.length >= 6
    : username.trim().length >= 3 && displayName.trim().length >= 2 && password.length >= 8 && password === confirmPassword

  return (
    <div className={s.page} style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
      <div className={`${s.card} ${s.auth}`} style={{ maxWidth: 440, width: '100%' }}>
        <div className={s.hero}>
          <div>
            <h2 className={s.title}>CyberSentinel</h2>
            <p className={s.sub}>{mode === 'signin' ? 'Sign in to your security workspace' : 'Create a new operator account'}</p>
          </div>
          <span className={s.badge}>Secure access</span>
        </div>

        <div className={s.tabs} role="tablist" aria-label="Authentication mode">
          <button type="button" className={`${s.tab} ${mode === 'signin' ? s.active : ''}`} onClick={() => switchMode('signin')}>Sign in</button>
          <button type="button" className={`${s.tab} ${mode === 'register' ? s.active : ''}`} onClick={() => switchMode('register')}>Register</button>
        </div>

        <form onSubmit={submit}>
          {mode === 'register' && (
            <label className={s.label}>Display name
              <input className={s.input} autoComplete="name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </label>
          )}
          <label className={s.label}>Username
            <input className={s.input} autoComplete="username" autoCapitalize="none" value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label className={s.label}>Password
            <input className={s.input} type="password" autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {mode === 'register' && (
            <>
              <label className={s.label}>Confirm password
                <input className={s.input} type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
              </label>
              <label className={s.label}>Account role
                <select className={s.select} value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                </select>
              </label>
            </>
          )}
          {message && <div className={s.notice} style={{ marginBottom: 12 }}>{message}</div>}
          <button className={s.button} type="submit" disabled={busy || !valid}>
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account'}
          </button>
        </form>

        <p className={s.muted} style={{ marginTop: 14 }}>
          {mode === 'register'
            ? 'New members can register as Viewer or Analyst. Admin access is managed separately.'
            : 'Use the username and password you registered with.'}
        </p>
      </div>
    </div>
  )
}
Component.displayName = 'AuthPage'
