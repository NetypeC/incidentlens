import { z } from "zod";

import { sampleWazuhAlerts } from "@/lib/alerts/sample-wazuh-alerts";
import {
  SampleImportRequestSchema,
  WazuhAlertSchema,
} from "@/lib/alerts/schema";

export async function POST(request: Request) {
  if (process.env.NODE_ENV === "production") {
    return Response.json(
      { error: "Not found." },
      { status: 404 }
    );
  }

  let requestBody: unknown;

  try {
    requestBody = await request.json();
  } catch {
    return Response.json(
      { error: "Request body must be valid JSON." },
      { status: 400 }
    );
  }

  const requestResult =
    SampleImportRequestSchema.safeParse(requestBody);

  if (!requestResult.success) {
    return Response.json(
      {
        error: "Invalid request.",
        expected: {
          source: "sample",
        },
      },
      { status: 400 }
    );
  }

  const acceptedAlerts: z.infer<typeof WazuhAlertSchema>[] = [];

  const rejectedAlerts: Array<{
    alertId: string;
    issues: Array<{
      path: string;
      message: string;
    }>;
  }> = [];

  for (const alert of sampleWazuhAlerts) {
    const result = WazuhAlertSchema.safeParse(alert);

    if (result.success) {
      acceptedAlerts.push(result.data);
    } else {
      rejectedAlerts.push({
        alertId: alert.id,
        issues: result.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      });
    }
  }

  const rejected = rejectedAlerts.length;

  return Response.json(
    {
      success: rejected === 0,
      source: "sample",
      mode: "dry-run",
      stored: false,
      message:
        "Test alerts were validated. No database records were created.",
      counts: {
        received: sampleWazuhAlerts.length,
        accepted: acceptedAlerts.length,
        rejected,
      },
      alerts: acceptedAlerts.map((alert) => ({
        id: alert.id,
        timestamp: alert.timestamp,
        agentName: alert.agent.name,
        ruleId: alert.rule.id,
        ruleLevel: alert.rule.level,
      })),
      rejectedAlerts,
    },
    {
      status: rejected === 0 ? 200 : 422,
    }
  );
}