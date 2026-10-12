import { z } from "zod";

import { sampleWazuhAlerts } from "@/lib/alerts/sample-wazuh-alerts";
import { normalizeWazuhAlert } from "@/lib/alerts/normalizer";

import {
  correlateRepeatedFailedLogins,
  correlateFailedThenSuccessfulLogin,
} from "@/lib/alerts/correlation";

import {
  analyzeIncident,
  type IncidentEvidence,
} from "@/lib/ai/analyze-incident";

const RequestSchema = z
  .object({
    source: z.literal("sample"),
    ruleId: z.enum([
      "repeated_failed_logins_v1",
      "failed_then_successful_login_v1",
    ]),
  })
  .strict();

export async function POST(request: Request) {
  // Development-only endpoint. Add auth and access control
  // before building any production-facing AI endpoint.
  if (process.env.NODE_ENV === "production") {
    return Response.json(
      { error: "Not found." },
      { status: 404 }
    );
  }

  if (
    !process.env.GROQ_API_KEY &&
    !process.env.GEMINI_API_KEY
  ) {
    return Response.json(
      {
        error: "No AI provider is configured.",
        message:
          "Configure GROQ_API_KEY or GEMINI_API_KEY in .env.local.",
      },
      { status: 503 }
    );
  }

  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return Response.json(
      { error: "Request body must be valid JSON." },
      { status: 400 }
    );
  }

  const parsed = RequestSchema.safeParse(body);

  if (!parsed.success) {
    return Response.json(
      {
        error: "Invalid request.",
        expected: {
          source: "sample",
          ruleId:
            "repeated_failed_logins_v1 or " +
            "failed_then_successful_login_v1",
        },
      },
      { status: 400 }
    );
  }

  // Normalize the known sample alerts.
  const alerts = sampleWazuhAlerts.map((alert) =>
    normalizeWazuhAlert(alert, "sample")
  );

  // The application chooses the incident, not the AI.
  const candidates =
    parsed.data.ruleId === "repeated_failed_logins_v1"
      ? correlateRepeatedFailedLogins(alerts)
      : correlateFailedThenSuccessfulLogin(alerts);

  const incident = candidates[0];

  if (!incident) {
    return Response.json(
      { error: "No matching sample incident was found." },
      { status: 404 }
    );
  }

  const matchedIds = new Set(incident.matchedAlertIds);

  const evidenceAlerts = alerts
    .filter((alert) => matchedIds.has(alert.sourceAlertId))
    .map((alert) => ({
      id: alert.sourceAlertId,
      timestamp: alert.timestamp,
      agentName: alert.agentName,
      ruleId: alert.ruleId,
      ruleLevel: alert.ruleLevel,
      ruleDescription: alert.ruleDescription,
      eventType: alert.eventType,
      sourceIp: alert.sourceIp,
      username: alert.username,
    }));

  const evidence: IncidentEvidence = {
    ruleId: incident.ruleId,
    title: incident.title,
    severity: incident.severity,
    matchReason: incident.matchReason,
    matchedAlertCount: incident.matchedAlertCount,
    firstSeenAt: incident.firstSeenAt,
    lastSeenAt: incident.lastSeenAt,
    alerts: evidenceAlerts,
  };

  try {
    const result = await analyzeIncident(evidence);

    return Response.json({
      success: true,
      source: "sample",
      notice:
        "This is an AI analysis of synthetic development data, not live Wazuh alerts.",

      providerUsed: result.provider,
      fallbackUsed: result.fallbackUsed,

      incident: {
        ruleId: incident.ruleId,
        title: incident.title,
        severity: incident.severity,
        matchedAlertCount: incident.matchedAlertCount,
        matchReason: incident.matchReason,
      },

      analysis: result.analysis,
    });
  } catch (error) {
    console.error(
      "[IncidentLens AI] All eligible providers failed or configuration needs attention."
    );

    // Keep detailed provider errors in the server environment.
    // Do not return raw SDK errors or credentials to the caller.
    const message =
      error instanceof Error ? error.message : "";

    console.error(message);

    return Response.json(
      {
        error:
          "AI analysis could not be completed. Check the server terminal.",
      },
      { status: 502 }
    );
  }
}