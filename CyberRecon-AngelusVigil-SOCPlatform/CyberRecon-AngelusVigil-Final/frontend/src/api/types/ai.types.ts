import { z } from 'zod'

export const AISeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])

export const AIEvidenceSchema = z.object({
  path: z.string(),
  value: z.string(),
})

export const AIFindingSchema = z.object({
  title: z.string(),
  severity: AISeveritySchema,
  evidence: z.array(AIEvidenceSchema),
  impact: z.string(),
  remediation: z.string(),
})

export const SecurityAnalysisSchema = z.object({
  risk: AISeveritySchema,
  findings: z.array(AIFindingSchema),
  summary: z.string(),
})

export const AIAnalysisResponseSchema = z.object({
  mode: z.literal('OLLAMA'),
  provider: z.literal('OLLAMA_LOCAL'),
  model: z.string(),
  answer: z.string(),
  analysis: SecurityAnalysisSchema,
})

export const AIStatusSchema = z.object({
  provider: z.literal('OLLAMA_LOCAL'),
  enabled: z.boolean(),
  configured: z.boolean(),
  available: z.boolean(),
  model: z.string(),
  model_installed: z.boolean(),
})

export type SecurityAnalysis = z.infer<typeof SecurityAnalysisSchema>
export type AIStatus = z.infer<typeof AIStatusSchema>
