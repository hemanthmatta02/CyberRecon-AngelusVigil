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
  approval_status?: string
  permissions: string[]
}

type Invite = {
  id: string
  display_name: string
  role: 'analyst' | 'viewer'
  created_by: string
  expires_at: string
}

type InviteResponse = {
  token: string
  display_name: string
  role: string
  expires_at: string
}

export function Component(): React.ReactElement {
  const navigate = useNavigate()
  const currentUser = readStored<SessionUser | null>('cybersentinel_user', null)
  const [team, setTeam] = useState<Member[]>([])
  const [pending, setPending] = useState<Member[]>([])
  const [invites, setInvites] = useState<Invite[]>([])
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Member['role']>('viewer')
  const [inviteName, setInviteName] = useState('')
  const [inviteRole, setInviteRole] = useState<'analyst' | 'viewer'>('viewer')
  const [inviteLink, setInviteLink] = useState('')
  const [busy, setBusy] = useState(false)
  const [reviewing, setReviewing] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  const counts = useMemo(() => ({
    total: team.length,
    active: team.filter((member) => member.active).length,
    pending: pending.length,
    analysts: team.filter((member) => member.role === 'analyst').length,
    viewers: team.filter((member) => member.role === 'viewer').length,
  }), [team, pending])

  async function load(): Promise<void> {
    setLoading(true)
    try {
      const [teamResponse, pendingResponse, inviteResponse] = await Promise.all([
        apiClient.get<Member[]>('/auth/team'),
        apiClient.get<Member[]>('/auth/team/pending'),
        apiClient.get<Invite[]>('/auth/team/invites'),
      ])
      setTeam(teamResponse.data)
      setPending(pendingResponse.data)
      setInvites(inviteResponse.data)
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not load team administration data.')
      try {
        setTeam((await apiClient.get<Member[]>('/auth/team')).data)
      } catch {
        // Keep the existing view if the backend is temporarily unavailable.
      }
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
      setMessage('Member created and approved. They can sign in from the main login page.')
      await load()
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not create member.')
    } finally {
      setBusy(false)
    }
  }

  async function reviewMember(id: string, action: 'approve' | 'reject'): Promise<void> {
    setReviewing(id)
    setMessage('')
    try {
      await apiClient.post('/auth/team/' + id + '/' + action)
      setMessage(action === 'approve' ? 'Registration approved.' : 'Registration rejected.')
      await load()
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not update registration.')
    } finally {
      setReviewing('')
    }
  }

  async function createInvite(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (inviteName.trim().length < 2) {
      setMessage('Enter the invitee display name first.')
      return
    }
    setBusy(true)
    setMessage('')
    try {
      const { data } = await apiClient.post<InviteResponse>('/auth/team/invites', {
        display_name: inviteName.trim(),
        role: inviteRole,
        expires_in_days: 7,
      })
      const link = window.location.origin + '/auth?invite=' + encodeURIComponent(data.token)
      setInviteLink(link)
      setInviteName('')
      setInviteRole('viewer')
      setMessage('Invitation created. Share the one-time link below with the new member.')
      await load()
    } catch (e: any) {
      setMessage(e?.response?.data?.detail || e?.message || 'Could not create invitation.')
    } finally {
      setBusy(false)
    }
  }

  async function copyInvite(): Promise<void> {
    if (!inviteLink) return
    try {
      await navigator.clipboard.writeText(inviteLink)
      setMessage('Invitation link copied to the clipboard.')
    } catch {
      setMessage('Copy was blocked by the browser. Select the link and copy it manually.')
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
          <p className={s.sub}>Create members, review self-registrations, or issue one-time invitations.</p>
        </div>
        <div className={s.row}>
          <button className={s.button + ' ' + s.secondary} type="button" onClick={() => void load()} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh'}</button>
          <button className={s.button + ' ' + s.secondary} type="button" onClick={signOut}>Sign out</button>
        </div>
      </div>

      <div className={s.kpis}>
        <div className={s.kpi}><small>Total members</small><strong>{counts.total}</strong></div>
        <div className={s.kpi}><small>Active</small><strong>{counts.active}</strong></div>
        <div className={s.kpi}><small>Pending approval</small><strong>{counts.pending}</strong></div>
        <div className={s.kpi}><small>Analysts</small><strong>{counts.analysts}</strong></div>
        <div className={s.kpi}><small>Viewers</small><strong>{counts.viewers}</strong></div>
      </div>

      <section className={s.card}>
        <div className={s.hero}>
          <div><h3>Pending registrations</h3><p className={s.sub}>Self-registered users remain blocked until an administrator approves them.</p></div>
        </div>
        <div style={{ overflowX: 'auto', marginTop: 12 }}>
          <table className={s.table}>
            <thead><tr><th>User</th><th>Requested role</th><th>Action</th></tr></thead>
            <tbody>
              {pending.map((member) => <tr key={member.id}><td><strong>{member.display_name}</strong><br /><span className={s.muted}>{member.username}</span></td><td><span className={s.badge}>{member.role}</span></td><td><div className={s.row}><button className={s.button + ' ' + s.success} type="button" onClick={() => void reviewMember(member.id, 'approve')} disabled={reviewing === member.id}>{reviewing === member.id ? 'Saving…' : 'Approve'}</button><button className={s.button + ' ' + s.danger} type="button" onClick={() => void reviewMember(member.id, 'reject')} disabled={reviewing === member.id}>Reject</button></div></td></tr>)}
              {!pending.length && <tr><td colSpan={3} className={s.empty}>{loading ? 'Loading pending registrations…' : 'No registrations are waiting for approval.'}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <div className={s.grid}>
        <section className={s.card}>
          <div className={s.hero}>
            <div><h3>Team members</h3><p className={s.sub}>Registered users and their current access role.</p></div>
          </div>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className={s.table}>
              <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Permissions</th></tr></thead>
              <tbody>
                {team.map((member) => <tr key={member.id}><td><strong>{member.display_name}</strong><br /><span className={s.muted}>{member.username}</span></td><td><span className={s.badge}>{member.role}</span></td><td>{member.active ? 'Active' : member.approval_status === 'rejected' ? 'Rejected' : 'Disabled'}</td><td>{member.permissions?.join(', ') || '—'}</td></tr>)}
                {!team.length && <tr><td colSpan={4} className={s.empty}>{loading ? 'Loading members…' : 'No team members found.'}</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <section className={s.card}>
          <h3>Add a member directly</h3>
          <p className={s.sub}>Directly created members are approved immediately.</p>
          <form onSubmit={createMember} style={{ marginTop: 14 }}>
            <label className={s.label}>Username<input className={s.input} autoComplete="off" autoCapitalize="none" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
            <label className={s.label}>Display name<input className={s.input} value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
            <label className={s.label}>Temporary password<input className={s.input} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <label className={s.label}>Role<select className={s.select} value={role} onChange={(e) => setRole(e.target.value as Member['role'])}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></label>
            <button className={s.button} type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create member'}</button>
          </form>
        </section>
      </div>

      <div className={s.grid}>
        <section className={s.card}>
          <h3>Invite a member</h3>
          <p className={s.sub}>Generate a one-time link valid for 7 days. The invitee sets their own password.</p>
          <form onSubmit={createInvite} style={{ marginTop: 14 }}>
            <label className={s.label}>Invitee display name<input className={s.input} value={inviteName} onChange={(e) => setInviteName(e.target.value)} /></label>
            <label className={s.label}>Role<select className={s.select} value={inviteRole} onChange={(e) => setInviteRole(e.target.value as 'analyst' | 'viewer')}><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></label>
            <button className={s.button} type="submit" disabled={busy}>{busy ? 'Creating…' : 'Generate invitation'}</button>
          </form>
          {inviteLink && <div className={s.callout} style={{ marginTop: 14 }}><strong>New invitation link</strong><input className={s.input} style={{ marginTop: 8 }} readOnly value={inviteLink} onFocus={(event) => event.currentTarget.select()} /><button className={s.button + ' ' + s.secondary} type="button" style={{ marginTop: 8 }} onClick={() => void copyInvite()}>Copy link</button></div>}
        </section>

        <section className={s.card}>
          <h3>Open invitations</h3>
          <p className={s.sub}>Only unused, unexpired invitations are listed here. The raw token is never stored or shown again.</p>
          <div style={{ overflowX: 'auto', marginTop: 12 }}>
            <table className={s.table}>
              <thead><tr><th>Invitee</th><th>Role</th><th>Expires</th></tr></thead>
              <tbody>
                {invites.map((invite) => <tr key={invite.id}><td>{invite.display_name}</td><td><span className={s.badge}>{invite.role}</span></td><td>{new Date(invite.expires_at).toLocaleDateString()}</td></tr>)}
                {!invites.length && <tr><td colSpan={3} className={s.empty}>No open invitations.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      </div>
      {message && <div className={s.notice}>{message}</div>}
    </div>
  )
}
Component.displayName = 'Team'
