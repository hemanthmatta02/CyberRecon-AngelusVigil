import { useEffect, useMemo, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { apiClient } from '@/core/api'
import { readStored, removeStored } from '@/core/persistence'
import { ROUTES } from '@/config'
import s from '../shared.module.scss'

type SessionUser = {
  username: string
  display_name: string
  role: string
  permissions: string[]
}

type Member = {
  id: string
  username: string
  display_name: string
  role: 'admin' | 'analyst' | 'viewer'
  active: boolean
  permissions: string[]
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const currentUser = readStored<SessionUser | null>('cybersentinel_user', null)
  const [team, setTeam] = useState<Member[]>([])
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Member['role']>('viewer')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  const counts = useMemo(() => ({
    total: team.length,
    active: team.filter((member) => member.active).length,
    analysts: team.filter((member) => member.role === 'analyst').length,
    viewers: team.filter((member) => member.role === 'viewer').length,
  }), [team])

  async function load(): Promise<void> {
    setLoading(true)
    try {
      setTeam((await apiClient.get<Member[]>('/auth/team')).data)
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not load team members.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (currentUser?.role === 'admin') void load()
  }, [currentUser?.role])

  if (!currentUser) return <Navigate to={ROUTES.AUTH} replace />

  if (currentUser.role !== 'admin') {
    return (
      <div className={s.page}>
        <section className={s.card} style={{ maxWidth: 620 }}>
          <h2 className={s.title}>Team Admin</h2>
          <p className={s.sub}>Admin access is required to manage members.</p>
          <div className={s.notice} style={{ marginTop: 16 }}>You are signed in as <strong>{currentUser.username}</strong> ({currentUser.role}).</div>
        </section>
      </div>
    )
  }

  async function createMember(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    setMessage('')
    if (username.trim().length < 3 || displayName.trim().length < 2 || password.length < 8) {
      setMessage('Enter a username, display name, and password of at least 8 characters.')
      return
    }
    setBusy(true)
    try {
      await apiClient.post('/auth/team', {
        username: username.trim().toLowerCase(),
        password,
        display_name: displayName.trim(),
        role,
      })
      setUsername('')
      setDisplayName('')
      setPassword('')
      setRole('viewer')
      setMessage('Member created. They can sign in from the main login page with these credentials.')
      await load()
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not create member.')
    } finally {
      setBusy(false)
    }
  }

  function signOut(): void {
    removeStored('cybersentinel_token')
    removeStored('cybersentinel_user')
    navigate(ROUTES.AUTH, { replace: true })
  }

  return (
    <div className={s.page}>
      <div className={s.hero}>
        <div>
          <h2 className={s.title}>Team Admin</h2>
          <p className={s.sub}>Create and review operator accounts in one place.</p>
        </div>
        <div className={s.row}>
          <button className={`${s.button} ${s.secondary}`} type="button" onClick={() => void load()} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh'}</button>
          <button className={`${s.button} ${s.secondary}`} type="button" onClick={signOut}>Sign out</button>
        </div>
      </div>

      <div className={s.kpis}>
        <div className={s.kpi}><small>Total members</small><strong>{counts.total}</strong></div>
        <div className={s.kpi}><small>Active</small><strong>{counts.active}</strong></div>
        <div className={s.kpi}><small>Analysts</small><strong>{counts.analysts}</strong></div>
        <div className={s.kpi}><small>Viewers</small><strong>{counts.viewers}</strong></div>
      </div>

      <div className={s.grid}>
        <section className={s.card}>
          <div className={s.hero}>
            <div><h3>Team members</h3><p className={s.sub}>Registered users and their current access role.</p></div>
          </div>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className={s.table}>
              <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Permissions</th></tr></thead>
              <tbody>
                {team.map((member) => <tr key={member.id}><td><strong>{member.display_name}</strong><br /><span className={s.muted}>{member.username}</span></td><td><span className={s.badge}>{member.role}</span></td><td>{member.active ? 'Active' : 'Disabled'}</td><td>{member.permissions?.join(', ') || '—'}</td></tr>)}
                {!team.length && <tr><td colSpan={4} className={s.empty}>{loading ? 'Loading members…' : 'No team members found.'}</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className={s.card}>
          <h3>Add a member</h3>
          <p className={s.sub}>Create an account directly, or let a new member register from the login page.</p>
          <form onSubmit={createMember} style={{ marginTop: 14 }}>
            <label className={s.label}>Username<input className={s.input} autoComplete="off" autoCapitalize="none" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
            <label className={s.label}>Display name<input className={s.input} value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
            <label className={s.label}>Temporary password<input className={s.input} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <label className={s.label}>Role<select className={s.select} value={role} onChange={(e) => setRole(e.target.value as Member['role'])}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></label>
            <button className={s.button} type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create member'}</button>
          </form>
        </section>
      </div>
      {message && <div className={s.notice}>{message}</div>}
    </div>
  )
}
Component.displayName = 'Team'
