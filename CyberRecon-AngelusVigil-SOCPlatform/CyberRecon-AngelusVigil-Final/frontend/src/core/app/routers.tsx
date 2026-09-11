import { Navigate, Outlet, createBrowserRouter } from 'react-router-dom'
import type { RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

function ProtectedLayout(): React.ReactElement {
  const token = typeof window !== 'undefined' ? window.sessionStorage.getItem('cybersentinel_token') : null
  return token ? <Shell /> : <Navigate to={ROUTES.AUTH} replace />
}

const routes: RouteObject[] = [
  { path: ROUTES.AUTH, lazy: () => import('@/pages/auth') },
  {
    element: <ProtectedLayout />,
    children: [{ element: <Outlet />, children: [
      { path: ROUTES.DASHBOARD, lazy: () => import('@/pages/dashboard') },
      { path: ROUTES.MANUAL_REQUEST, lazy: () => import('@/pages/manual-request') },
      { path: ROUTES.DETECTION, lazy: () => import('@/pages/detection') },
      { path: ROUTES.INTELLIGENCE, lazy: () => import('@/pages/threat-intelligence') },
      { path: ROUTES.ML, lazy: () => import('@/pages/ml-analysis') },
      { path: ROUTES.SOC, lazy: () => import('@/pages/soc') },
      { path: ROUTES.INCIDENTS, lazy: () => import('@/pages/incidents') },
      { path: ROUTES.SIMULATION, lazy: () => import('@/pages/simulation') },
      { path: ROUTES.ASSETS, lazy: () => import('@/pages/assets') },
      { path: ROUTES.REPORTS, lazy: () => import('@/pages/reports') },
      { path: ROUTES.THREATS, lazy: () => import('@/pages/threats') },
      { path: ROUTES.MODELS, lazy: () => import('@/pages/models') },
      { path: ROUTES.RECON, lazy: () => import('@/pages/recon') },
      { path: ROUTES.VULNERABILITIES, lazy: () => import('@/pages/vulnerabilities') },
      { path: ROUTES.ALERTS, lazy: () => import('@/pages/alerts') },
      { path: ROUTES.AI, lazy: () => import('@/pages/ai-copilot') },
    ] }],
  },
  { path: '*', element: <Navigate to={ROUTES.DASHBOARD} replace /> },
]

export const router = createBrowserRouter(routes)
