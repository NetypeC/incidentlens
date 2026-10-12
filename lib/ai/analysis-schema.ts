import { z } from "zod";

export const IncidentAnalysisSchema = z.object({
  summary: z.string(),

  facts: z.array(z.string()),

  interpretation: z.string(),

  confidence: z.enum(["low", "medium", "high"]),

  uncertainties: z.array(z.string()),

  recommendations: z.array(
    z.object({
      priority: z.enum(["low", "medium", "high"]),
      action: z.string(),
      reason: z.string(),
    })
  ),

  conclusion: z.string(),
});

export type IncidentAnalysis = z.infer<
  typeof IncidentAnalysisSchema
>;