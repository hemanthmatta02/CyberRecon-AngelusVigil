import { useEffect, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { readStored, writeStored } from '@/core/persistence'
import s from './auth.module.scss'

type AuthMode = 'signin' | 'register'
type InviteStatus = '' | 'checking' | 'valid' | 'invalid'
type MessageTone = 'notice' | 'error'

type SessionUser = {
  username: string
  display_name: string
  role: string
  permissions: string[]
}

function ShieldMark(): React.ReactElement {
  return (
    <svg className={s.logo} viewBox="0 0 48 48" role="img" aria-label="CyberSentinel shield">
      <path d="M24 4 39 9v12c0 10.4-6.1 18.9-15 23-8.9-4.1-15-12.6-15-23V9l15-5Z" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinejoin="round" />
    </svg>
  )
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const token = readStored<string | null>('cybersentinel_token', null)
  const inviteToken = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('invite') ?? '' : ''
  const verifyToken = typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('verify') ?? '' : ''
  const [mode, setMode] = useState<AuthMode>(inviteToken ? 'register' : 'signin')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [inviteStatus, setInviteStatus] = useState<InviteStatus>(inviteToken ? 'checking' : '')
  const [inviteRole, setInviteRole] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [messageTone, setMessageTone] = useState<MessageTone>('notice')
  const [verificationEmail, setVerificationEmail] = useState('')

  useEffect(() => {
    if (!inviteToken) return
    void apiClient.get('/auth/invites/' + encodeURIComponent(inviteToken)).then(({ data }) => {
      setInviteStatus('valid')
      setInviteRole(data.role)
      if (data.display_name) setFullName(data.display_name)
    }).catch(() => setInviteStatus('invalid'))
  }, [inviteToken])


  useEffect(() => {
    if (!verifyToken) return
    setMode('signin')
    setNotice('Verifying your email…')
    void apiClient.get('/auth/verify-email?token=' + encodeURIComponent(verifyToken)).then(({ data }) => {
      setNotice(data.message || 'Email verified. You can sign in now.')
    }).catch((e: any) => {
      setError(e?.response?.data?.detail || 'This verification link is invalid or expired.')
    })
  }, [verifyToken])

  if (token) return <Navigate to="/" replace />

  function switchMode(nextMode: AuthMode): void {
    setMode(nextMode)
    setMessage('')
    setPassword('')
    setConfirmPassword('')
    setVerificationEmail('')
  }

  function setNotice(value: string): void {
    setMessageTone('notice')
    setMessage(value)
  }

  function setError(value: string): void {
    setMessageTone('error')
    setMessage(value)
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
        setError('Passwords do not match.')
        return
      }
      const { data } = await apiClient.post('/auth/register', {
        username: cleanUsername,
        email: email.trim().toLowerCase(),
        password,
        display_name: fullName.trim() || cleanUsername,
        role: 'viewer',
        ...(inviteToken ? { invite_token: inviteToken } : {}),
      })
      setMode('signin')
      setPassword('')
      setConfirmPassword('')
      setVerificationEmail(email.trim().toLowerCase())
      setNotice(data.status === 'pending'
        ? 'Account created. Check your email to verify the account; an administrator must approve it before you can sign in.'
        : 'Account created. Check your email to verify the account before signing in.')
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || 'Request failed. Please try again.')
    } finally {
      setBusy(false)
    }
  }


  async function resendVerification(): Promise<void> {
    if (!verificationEmail) return
    setBusy(true)
    setMessage('')
    try {
      const { data } = await apiClient.post('/auth/resend-verification', { email: verificationEmail })
      setNotice(data.message || 'A new verification email has been sent.')
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || 'Could not resend the verification email.')
    } finally {
      setBusy(false)
    }
  }

  const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  const valid = mode === 'signin'
    ? username.trim().length >= 3 && password.length >= 6
    : username.trim().length >= 3 && validEmail && (fullName.trim().length === 0 || fullName.trim().length >= 2) && password.length >= 8 && password === confirmPassword && inviteStatus !== 'invalid'

  return (
    <main className={s.authScreen}>
      <section className={s.authCard} aria-labelledby="auth-title">
        <header className={s.brand}>
          <ShieldMark />
          <h1 id="auth-title">CyberSentinel</h1>
          <p>{mode === 'signin' ? 'SOC Operator Console' : 'Create Operator Account'}</p>
        </header>

        {inviteToken && mode === 'register' && (
          <div className={s.callout} aria-live="polite">
            {inviteStatus === 'checking' && 'Checking your invitation…'}
            {inviteStatus === 'valid' && <>You were invited as <strong>{inviteRole}</strong>. Complete the form to activate your account.</>}
            {inviteStatus === 'invalid' && 'This invitation is invalid, expired, or already used.'}
          </div>
        )}

        <form className={s.form} onSubmit={submit}>
          <label className={s.field}>
            <span>Username</span>
            <input className={s.input} autoFocus autoComplete="username" autoCapitalize="none" value={username} onChange={(event) => setUsername(event.target.value)} placeholder={mode === 'signin' ? 'Enter your username' : 'Choose a username'} />
          </label>

          {mode === 'register' && (
            <label className={s.field}>
              <span>Email</span>
              <input className={s.input} type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="operator@example.com" />
            </label>
          )}

          {mode === 'register' && (
            <label className={s.field}>
              <span>Full name</span>
              <input className={s.input} autoComplete="name" value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Jane Doe (optional)" />
            </label>
          )}

          <label className={s.field}>
            <span>Password</span>
            <input className={s.input} type="password" autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={mode === 'signin' ? 'Enter your password' : 'At least 8 characters'} />
          </label>

          {mode === 'register' && (
            <label className={s.field}>
              <span>Confirm password</span>
              <input className={s.input} type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Repeat your password" />
            </label>
          )}

          {message && <div className={messageTone === 'error' ? s.error : s.notice} role={messageTone === 'error' ? 'alert' : 'status'}>{message}</div>}
          {verificationEmail && messageTone === 'notice' && <button className={s.resendButton} type="button" onClick={() => void resendVerification()} disabled={busy}>Resend verification email</button>}

          <button className={s.primaryButton} type="submit" disabled={busy || !valid || (inviteToken !== '' && inviteStatus === 'checking')}>
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign In' : inviteToken ? 'Accept Invitation' : 'Create Account'}
          </button>
        </form>

        <footer className={s.footer}>
          {mode === 'signin' ? (
            <>Don&apos;t have an account? <button type="button" onClick={() => switchMode('register')}>Create one</button></>
          ) : (
            <>Already have an account? <button type="button" onClick={() => switchMode('signin')}>Sign in</button></>
          )}
        </footer>
      </section>
    </main>
  )
}
Component.displayName = 'AuthPage'
