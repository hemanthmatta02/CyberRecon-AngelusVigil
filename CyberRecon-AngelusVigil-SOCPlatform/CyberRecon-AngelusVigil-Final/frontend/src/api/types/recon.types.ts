import { z } from 'zod'

export const DNSResultSchema = z.object({
  domain: z.string(),
  addresses: z.array(z.string()),
  aliases: z.array(z.string()),
  records: z.record(z.string(), z.array(z.string())),
  reverse_dns: z.record(z.string(), z.string().nullable()),
})

export const ReconSummarySchema = z.object({
  ip_count: z.number().int(),
  subdomain_count: z.number().int(),
  open_port_count: z.number().int(),
  open_ports: z.array(z.number().int()),
  http_endpoint_count: z.number().int(),
  duration_ms: z.number().int(),
  dead_subdomain_count: z.number().int().optional().default(0),
})

export const ReconResponseSchema = z.object({
  target: z.string(),
  dns: DNSResultSchema,
  subdomains: z.array(z.object({
    subdomain: z.string(),
    addresses: z.array(z.string()),
    status: z.string().optional(),
  })),
  ports: z.array(z.object({
    ip: z.string(),
    port: z.number().int(),
    state: z.string(),
    service: z.string(),
    version: z.string().nullable().optional(),
  })),
  dns_alerts: z.array(z.record(z.string(), z.string())).optional().default([]),
  vulnerabilities: z.array(z.record(z.string(), z.unknown())).optional().default([]),
  http: z.array(z.object({
    url: z.string(),
    final_url: z.string().nullable(),
    status_code: z.number().int().nullable(),
    server: z.string().nullable(),
    content_type: z.string().nullable(),
    title: z.string().nullable(),
    technologies: z.array(z.string()),
    error: z.string().nullable(),
  })),
  summary: ReconSummarySchema,
})

export const ReconHistoryItemSchema = z.object({
  id: z.string(),
  target: z.string(),
  scan_type: z.string(),
  status: z.string(),
  duration_ms: z.number().int(),
  authorized_use: z.boolean(),
  created_at: z.string(),
  completed_at: z.string().nullable().optional(),
})

export const ReconHistoryResponseSchema = z.object({
  total: z.number().int(),
  items: z.array(ReconHistoryItemSchema),
})

export type ReconResponse = z.infer<typeof ReconResponseSchema>
export type ReconHistoryItem = z.infer<typeof ReconHistoryItemSchema>
export type ReconHistoryResponse = z.infer<typeof ReconHistoryResponseSchema>
