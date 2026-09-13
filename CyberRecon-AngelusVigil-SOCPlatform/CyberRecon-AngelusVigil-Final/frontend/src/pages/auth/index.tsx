import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { readStored, writeStored } from '@/core/persistence'
import s from '../shared.module.scss'

type AuthMode = 'signin' | 'register'
type InviteStatus = '' | 'checking' | 'valid' | 'invalid'

type SessionUser = {
  username: string
  display_name: string
  role: string
  permissions: string[]
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const token = readStored<string | null>('cybersentinel_token', null)
  const inviteToken = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('invite') ?? '' : ''
  const [mode, setMode] = useState<AuthMode>(inviteToken ? 'register' : 'signin')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('viewer')
  const [inviteStatus, setInviteStatus] = useState<InviteStatus>(inviteToken ? 'checking' : '')
  const [inviteRole, setInviteRole] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!inviteToken) return
    void apiClient.get('/auth/invites/' + encodeURIComponent(inviteToken)).then(({ data }) => {
      setInviteStatus('valid')
      setInviteRole(data.role)
      if (data.display_name) setDisplayName(data.display_name)
      if (data.role) setRole(data.role)
    }).catch(() => setInviteStatus('invalid'))
  }, [inviteToken])

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
      const { data } = await apiClient.post('/auth/register', {
        username: cleanUsername,
        password,
        display_name: displayName.trim() || cleanUsername,
        role,
        ...(inviteToken ? { invite_token: inviteToken } : {}),
      })
      setMode('signin')
      setPassword('')
      setConfirmPassword('')
      setDisplayName('')
      setMessage(data.status === 'pending'
        ? 'Registration submitted for ' + cleanUsername + '. An administrator must approve it before you can sign in.'
        : 'Invitation accepted for ' + cleanUsername + '. You can sign in now.')
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  const valid = mode === 'signin'
    ? username.trim().length >= 3 && password.length >= 6
    : username.trim().length >= 3 && displayName.trim().length >= 2 && password.length >= 8 && password === confirmPassword && inviteStatus !== 'invalid'

  return (
    <div className={s.page} style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
      <div className={s.card + ' ' + s.auth} style={{ maxWidth: 440, width: '100%' }}>
        <div className={s.hero}>
          <div>
            <h2 className={s.title}>CyberSentinel</h2>
            <p className={s.sub}>{mode === 'signin' ? 'Sign in to your security workspace' : inviteToken ? 'Accept your team invitation' : 'Request a new operator account'}</p>
          </div>
          <span className={s.badge}>Secure access</span>
        </div>

        <div className={s.tabs} role="tablist" aria-label="Authentication mode">
          <button type="button" className={s.tab + ' ' + (mode === 'signin' ? s.active : '')} onClick={() => switchMode('signin')}>Sign in</button>
          <button type="button" className={s.tab + ' ' + (mode === 'register' ? s.active : '')} onClick={() => switchMode('register')}>Register</button>
        </div>

        {inviteToken && mode === 'register' && (
          <div className={s.callout} style={{ marginBottom: 14 }}>
            {inviteStatus === 'checking' && 'Checking your invitation…'}
            {inviteStatus === 'valid' && <>You were invited as <strong>{inviteRole}</strong>. Complete the form to activate your account.</>}
            {inviteStatus === 'invalid' && 'This invitation is invalid, expired, or already used.'}
          </div>
        )}

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
                <select className={s.select} value={role} disabled={inviteStatus === 'valid'} onChange={(e) => setRole(e.target.value)}>
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                </select>
              </label>
            </>
          )}
          {message && <div className={s.notice} style={{ marginBottom: 12 }}>{message}</div>}
          <button className={s.button} type="submit" disabled={busy || !valid || (inviteToken !== '' && inviteStatus === 'checking')}>
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : inviteToken ? 'Accept invitation' : 'Request account'}
          </button>
        </form>

        <p className={s.muted} style={{ marginTop: 14 }}>
          {mode === 'register'
            ? inviteToken ? 'This invitation sets your role. Your password will be used for future sign-ins.' : 'New registrations stay pending until an administrator reviews and approves them.'
            : 'Use an approved username and password, or accept an administrator invitation first.'}
        </p>
      </div>
    </div>
  )
}
Component.displayName = 'AuthPage'
