// ===================
// © AngelaMos | 2026
// api.config.ts
//
// Axios HTTP client singleton with error interceptor
//
// Creates an axios instance with base URL from VITE_API_URL
// env var (defaulting to /api), 15-second timeout, and JSON
// content type. Response interceptor transforms AxiosError
// into typed ApiError via transformAxiosError for consistent
// error handling across all API hooks
// ===================

import axios, { type AxiosError, type AxiosInstance } from 'axios'
import { readStored, removeStored } from '../persistence'
import { transformAxiosError } from './errors'

const getBaseURL = (): string => {
  const configured = (import.meta.env.VITE_API_URL ?? '').trim()
  return configured || '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use((config) => {
  const token = typeof window !== 'undefined'
    ? readStored<string | null>('cybersentinel_token', null)
    : null
  if (token) {
    config.headers.Authorization = 'Bearer ' + token
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError): Promise<never> => {
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      removeStored('cybersentinel_token')
      removeStored('cybersentinel_user')
    }
    return Promise.reject(transformAxiosError(error))
  }
)

