import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import type { ReconHistoryResponse, ReconResponse } from '@/api/types'
import { ReconHistoryResponseSchema, ReconResponseSchema } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export interface ReconScanOptions {
  domain: string
  include_subdomains: boolean
  include_ports: boolean
  include_http: boolean
  ports: number[]
}

export function useReconScan() {
  const queryClient = useQueryClient()

  return useMutation<ReconResponse, Error, ReconScanOptions>({
    mutationFn: async (payload) => {
      const { data } = await apiClient.post<unknown>(
        API_ENDPOINTS.RECON.SCAN,
        payload,
        { timeout: 60_000 },
      )
      return ReconResponseSchema.parse(data)
    },
    onSuccess: () => {
      toast.success('Reconnaissance completed')
      queryClient.invalidateQueries({ queryKey: QUERY_KEYS.RECON.HISTORY() })
    },
    onError: (error) => {
      toast.error(error.message || 'Reconnaissance failed')
    },
  })
}

export function useReconHistory() {
  return useQuery<ReconHistoryResponse>({
    queryKey: QUERY_KEYS.RECON.HISTORY(),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(API_ENDPOINTS.RECON.HISTORY)
      return ReconHistoryResponseSchema.parse(data)
    },
    ...QUERY_STRATEGIES.standard,
  })
}
