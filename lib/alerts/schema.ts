import { z } from "zod";

const TimestampSchema = z.string().refine(
  (value) => !Number.isNaN(Date.parse(value)),
  "Timestamp must be a valid date and time."
);

const RuleSchema = z
  .object({
    id: z.string().min(1, "Rule ID is required."),
    level: z.number().int().min(0).max(15),
    description: z.string().min(1, "Rule description is required."),
    groups: z.array(z.string()).optional(),
  })
  .passthrough();

const AgentSchema = z
  .object({
    id: z.string().min(1, "Agent ID is required."),
    name: z.string().min(1, "Agent name is required."),
    ip: z.string().optional(),
  })
  .passthrough();

export const WazuhAlertSchema = z
  .object({
    id: z.string().min(1, "Alert ID is required."),
    timestamp: TimestampSchema,
    rule: RuleSchema,
    agent: AgentSchema,

    manager: z
      .object({
        name: z.string().min(1),
      })
      .passthrough()
      .optional(),

    location: z.string().optional(),
    full_log: z.string().optional(),

    data: z.record(z.string(), z.unknown()).optional(),
    syscheck: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();

export const SampleImportRequestSchema = z
  .object({
    source: z.literal("sample"),
  })
  .strict();