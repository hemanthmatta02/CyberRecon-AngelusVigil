import { useMutation, useQuery } from '@tanstack/react-query'
import { apiClient } from '@/core/api'
import { API_ENDPOINTS, QUERY_KEYS, QUERY_CONFIG } from '@/config'

export function usePlatform<T>(name: string, endpoint: string, enabled = true) {
  return useQuery<T>({
    queryKey: QUERY_KEYS.PLATFORM.BY_NAME(name),
    queryFn: async () => (await apiClient.get<T>(endpoint)).data,
    enabled,
    staleTime: QUERY_CONFIG.STALE_TIME.FREQUENT,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function usePlatformMutation<TPayload extends object, TResult>(endpoint: string) {
  return useMutation({
    mutationFn: async (payload: TPayload) => (await apiClient.post<TResult>(endpoint, payload)).data,
  })
}

export function useIncidentUpdate() {
  return useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      (await apiClient.patch(API_ENDPOINTS.PLATFORM.INCIDENT_UPDATE(id), payload)).data,
  })
}
