import { Navigate, Outlet, createBrowserRouter } from 'react-router-dom'
import type { RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <Shell />,
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
    ] }],
  },
  { path: '*', element: <Navigate to={ROUTES.DASHBOARD} replace /> },
]

export const router = createBrowserRouter(routes)
