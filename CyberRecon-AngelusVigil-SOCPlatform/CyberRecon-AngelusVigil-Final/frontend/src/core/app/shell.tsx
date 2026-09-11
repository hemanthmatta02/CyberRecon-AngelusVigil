import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import {
  LuActivity, LuChevronLeft, LuChevronRight, LuCircleAlert, LuCpu,
  LuFileText, LuGlobe, LuLayoutDashboard, LuMenu, LuPlay, LuRadar,
  LuSend, LuServer, LuShield, LuSiren, LuTarget, LuBug, LuBellRing,
  LuCloudRain, LuScanLine, LuSparkles,
} from 'react-icons/lu'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { ROUTES } from '@/config'
import { useUIStore } from '@/core/lib'
import styles from './shell.module.scss'

const NAV_ITEMS = [
  { path: ROUTES.DASHBOARD, label: 'Overview', icon: LuLayoutDashboard },
  { path: ROUTES.AI, label: 'AI Workspace', icon: LuSparkles },
  { path: ROUTES.MANUAL_REQUEST, label: 'Manual Request', icon: LuSend },
  { path: ROUTES.DETECTION, label: 'Real-Time Detection', icon: LuActivity },
  { path: ROUTES.INTELLIGENCE, label: 'Threat Intelligence', icon: LuTarget },
  { path: ROUTES.ML, label: 'ML / AI Analysis', icon: LuCpu },
  { path: ROUTES.SOC, label: 'SOC Operations', icon: LuShield },
  { path: ROUTES.INCIDENTS, label: 'Incident Response', icon: LuSiren },
  { path: ROUTES.SIMULATION, label: 'Attack Simulation', icon: LuPlay },
  { path: ROUTES.ASSETS, label: 'Asset Discovery', icon: LuGlobe },
  { path: ROUTES.REPORTS, label: 'Reports', icon: LuFileText },
  { path: ROUTES.THREATS, label: 'Threat Events', icon: LuCircleAlert },
  { path: ROUTES.MODELS, label: 'Models', icon: LuServer },
  { path: ROUTES.RECON, label: 'CyberRecon', icon: LuRadar },
  { path: ROUTES.VULNERABILITIES, label: 'Vulnerability Assessment', icon: LuBug },
  { path: ROUTES.ALERTS, label: 'Alert Management', icon: LuBellRing },
]

function ShellErrorFallback({ error }: { error: unknown }): React.ReactElement {
  return <div className={styles.error}><h2>Something went wrong</h2><pre>{error instanceof Error ? error.message : String(error)}</pre></div>
}
function ShellLoading(): React.ReactElement { return <div className={styles.loading}></div> }
function getPageTitle(pathname: string): string { return NAV_ITEMS.find((item) => item.path === pathname)?.label ?? 'Overview' }

export function Shell(): React.ReactElement {
  const location = useLocation()
  const { sidebarOpen, sidebarCollapsed, toggleSidebar, toggleSidebarCollapsed } = useUIStore()
  return (
    <div className={styles.shell}>
      <div className={styles.ambient} aria-hidden="true"><div className={styles.rain} /><div className={styles.scanline} /></div>
      <aside className={`${styles.sidebar} ${sidebarOpen ? styles.open : ''} ${sidebarCollapsed ? styles.collapsed : ''}`}>
        <div className={styles.sidebarHeader}>
          <div className={styles.brand}><span className={styles.brandMark}><LuShield /></span><span className={styles.logo}>{sidebarCollapsed ? 'CS' : 'CyberSentinel'}</span></div>
          <button type="button" className={styles.collapseBtn} onClick={toggleSidebarCollapsed} aria-label="Toggle sidebar">{sidebarCollapsed ? <LuChevronRight /> : <LuChevronLeft />}</button>
        </div>
        <div className={styles.environmentBadge}><LuCloudRain /><span>SECURITY OPERATIONS</span><i aria-hidden="true" /></div>
        <nav className={styles.nav}>
          {NAV_ITEMS.map((item) => <NavLink key={item.path} to={item.path} className={({ isActive }) => `${styles.navItem} ${isActive ? styles.active : ''}`} onClick={() => sidebarOpen && toggleSidebar()}><item.icon className={styles.navIcon} /><span className={styles.navLabel}>{item.label}</span></NavLink>)}
        </nav>
      </aside>
      {sidebarOpen && <button type="button" className={styles.overlay} onClick={toggleSidebar} aria-label="Close sidebar" />}
      <div className={`${styles.main} ${sidebarCollapsed ? styles.collapsed : ''}`}>
        <header className={styles.header}>
          <div className={styles.headerLeft}><button type="button" className={styles.menuBtn} onClick={toggleSidebar} aria-label="Toggle menu"><LuMenu /></button><div className={styles.titleBlock}><span className={styles.systemLabel}><LuScanLine /> CYBERSENTINEL // SECURE CONSOLE</span><h1 className={styles.pageTitle}>{getPageTitle(location.pathname)}</h1></div></div>
          <div className={styles.headerRight}><div className={styles.status}><i aria-hidden="true" /><span>SYSTEM ONLINE</span></div><div className={styles.avatar}>A</div></div>
        </header>
        <main className={styles.content}><ErrorBoundary FallbackComponent={ShellErrorFallback}><Suspense fallback={<ShellLoading />}><Outlet /></Suspense></ErrorBoundary></main>
      </div>
    </div>
  )
}
