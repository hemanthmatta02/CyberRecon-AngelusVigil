// Central application constants: API paths, cache keys, routes and UI timings.

export const API_ENDPOINTS = {
  HEALTH: '/health',
  READY: '/ready',
  THREATS: { LIST: '/threats', BY_ID: (id: string) => `/threats/${id}` },
  STATS: '/stats',
  MODELS: { STATUS: '/models/status', RETRAIN: '/models/retrain' },
  RECON: { SCAN: '/recon/scan', HISTORY: '/recon/history', BY_ID: (id: string) => `/recon/history/${id}` },
  SECURITY: { ALERTS: '/security/alerts', VULNS: '/security/vulnerabilities', VULN_SCAN: '/security/vulnerability-scan', CLASSIFICATIONS: '/security/threat-classifications' },
  AUTH: { LOGIN: '/auth/login', TEAM: '/auth/team', ME: '/auth/me' },
  MANUAL_REQUEST: '/manual-request',
  AI: '/ai/analyze',
  PLATFORM: {
    OVERVIEW: '/platform/overview',
    DETECTION: '/platform/detection',
    INTELLIGENCE: '/platform/intelligence',
    ML: '/platform/ml',
    SOC: '/platform/soc',
    INCIDENTS: '/platform/incidents',
    INCIDENT_CREATE: '/platform/incidents',
    INCIDENT_UPDATE: (id: string) => `/platform/incidents/${id}`,
    ASSETS: '/platform/assets',
    REPORTS: '/platform/reports',
    SIMULATION: '/platform/simulation/run',
  },
} as const

export const WS_ENDPOINTS = { ALERTS: '/ws/alerts' } as const

export const QUERY_KEYS = {
  THREATS: { ALL: ['threats'] as const, LIST: (params: Record<string, unknown>) => [...QUERY_KEYS.THREATS.ALL, 'list', params] as const, BY_ID: (id: string) => [...QUERY_KEYS.THREATS.ALL, 'detail', id] as const },
  STATS: { ALL: ['stats'] as const, BY_RANGE: (range: string) => [...QUERY_KEYS.STATS.ALL, range] as const },
  MODELS: { ALL: ['models'] as const, STATUS: () => [...QUERY_KEYS.MODELS.ALL, 'status'] as const },
  RECON: { ALL: ['recon'] as const, HISTORY: () => [...QUERY_KEYS.RECON.ALL, 'history'] as const },
  PLATFORM: { ALL: ['platform'] as const, BY_NAME: (name: string) => [...QUERY_KEYS.PLATFORM.ALL, name] as const },
} as const

export const ROUTES = {
  AUTH: '/auth',
  DASHBOARD: '/',
  MANUAL_REQUEST: '/manual-request',
  DETECTION: '/detection',
  INTELLIGENCE: '/threat-intelligence',
  ML: '/ml-analysis',
  SOC: '/soc',
  INCIDENTS: '/incidents',
  SIMULATION: '/simulation',
  ASSETS: '/assets',
  REPORTS: '/reports',
  THREATS: '/threats',
  MODELS: '/models',
  RECON: '/recon',
  VULNERABILITIES: '/vulnerabilities',
  ALERTS: '/alerts',
  TEAM: '/team',
  AI: '/ai-workspace',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
  AUTH: 'cybersentinel_token',
  USER: 'cybersentinel_user',
  MANUAL: 'tab-history-manual',
  DETECTION: 'tab-history-detection',
  INTELLIGENCE: 'tab-history-intelligence',
  ML: 'tab-history-ml',
  SOC: 'tab-history-soc',
  INCIDENTS: 'tab-history-incidents',
  SIMULATION: 'tab-history-simulation',
  ASSETS: 'tab-history-assets',
  THREATS: 'tab-history-threats',
  MODELS: 'tab-history-models',
} as const
export const QUERY_CONFIG = {
  STALE_TIME: { STANDARD: 1000 * 60 * 5, FREQUENT: 1000 * 10, STATIC: Infinity },
  GC_TIME: { DEFAULT: 1000 * 60 * 30, LONG: 1000 * 60 * 60 },
  RETRY: { DEFAULT: 3, NONE: 0 },
} as const
export const PAGINATION = { DEFAULT_LIMIT: 50, MAX_LIMIT: 100 } as const
export const ALERTS = { MAX_ITEMS: 50, RECONNECT_BASE_MS: 1000, RECONNECT_MAX_MS: 30000 } as const
