import { z } from "zod";

import { createAdminClient } from "@/lib/supabase/admin";
import {
  analyzeIncident,
  type IncidentEvidence,
} from "@/lib/ai/analyze-incident";

const RequestSchema = z
  .object({
    incidentId: z.string().uuid(),
  })
  .strict();

const SeveritySchema = z.enum([
  "low",
  "medium",
  "high",
  "critical",
])

export async function POST(request: Request) {
  // Keep this endpoint unavailable in production until
  // authentication and authorization are implemented.
  if (process.env.NODE_ENV === "production") {
    return Response.json(
      { error: "Not found." },
      { status: 404 }
    );
  }

  if (
    !process.env.GROQ_API_KEY?.trim() &&
    !process.env.GEMINI_API_KEY?.trim()
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
          incidentId: "A saved incident UUID",
        },
      },
      { status: 400 }
    );
  }

  try {
    const supabase = createAdminClient();

    // 1. Load the exact incident selected by the user.
    const { data: incident, error: incidentError } =
      await supabase
        .from("incidents")
        .select(
          "id, title, summary, severity, correlation_rule_id, first_seen_at, last_seen_at"
        )
        .eq("id", parsed.data.incidentId)
        .maybeSingle();

    if (incidentError) {
      console.error(
        "[IncidentLens AI] Incident lookup failed:",
        incidentError.message
      );

      return Response.json(
        { error: "Could not retrieve the incident." },
        { status: 500 }
      );
    }

    if (!incident) {
      return Response.json(
        { error: "The requested incident was not found." },
        { status: 404 }
      );
    }

    // 2. Find the alerts linked to this incident.
    const { data: links, error: linksError } = await supabase
      .from("incident_alerts")
      .select("alert_id, match_rule_id, match_reason")
      .eq("incident_id", incident.id);

    if (linksError) {
      console.error(
        "[IncidentLens AI] Incident-alert lookup failed:",
        linksError.message
      );

      return Response.json(
        { error: "Could not retrieve the incident evidence." },
        { status: 500 }
      );
    }

    if (!links || links.length === 0) {
      return Response.json(
        {
          error:
            "This incident has no linked alerts to analyse.",
        },
        { status: 422 }
      );
    }

    const alertIds = [...new Set(
      links.map((link) => link.alert_id)
    )];

    // 3. Retrieve the actual alert records from Supabase.
    const { data: savedAlerts, error: alertsError } =
      await supabase
        .from("security_alerts")
        .select(
          "id, source, source_alert_id, alert_timestamp, agent_name, rule_id, rule_level, rule_description, event_type, source_ip, username"
        )
        .in("id", alertIds);

    if (alertsError) {
      console.error(
        "[IncidentLens AI] Alert lookup failed:",
        alertsError.message
      );

      return Response.json(
        { error: "Could not retrieve the incident alerts." },
        { status: 500 }
      );
    }

    if (!savedAlerts || savedAlerts.length === 0) {
      return Response.json(
        { error: "No linked alert records were found." },
        { status: 422 }
      );
    }

    const severity = SeveritySchema.safeParse(
      incident.severity
    );

    if (!severity.success) {
      console.error(
        "[IncidentLens AI] Incident has an invalid severity."
      );

      return Response.json(
        { error: "The saved incident has invalid severity data." },
        { status: 500 }
      );
    }

    const evidenceAlerts = savedAlerts
      .map((alert) => ({
        id: alert.source_alert_id,
        timestamp: alert.alert_timestamp,
        agentName: alert.agent_name,
        ruleId: alert.rule_id,
        ruleLevel: alert.rule_level,
        ruleDescription:
          alert.rule_description ?? "No rule description supplied",
        eventType: alert.event_type,
        sourceIp: alert.source_ip,
        username: alert.username,
      }))
      .sort(
        (a, b) =>
          Date.parse(a.timestamp) - Date.parse(b.timestamp)
      );

    const firstAlert = evidenceAlerts[0];
    const lastAlert = evidenceAlerts[evidenceAlerts.length - 1];

    if (!firstAlert || !lastAlert) {
      return Response.json(
        { error: "The incident has no usable alert evidence." },
        { status: 422 }
      );
    }

    const matchReason =
      links.find((link) => link.match_reason)?.match_reason ??
      incident.summary ??
      "The incident was identified by a deterministic correlation rule.";

    // 4. Give the AI only the evidence attached to this incident.
    const evidence: IncidentEvidence = {
      ruleId: incident.correlation_rule_id,
      title: incident.title,
      severity: severity.data,
      matchReason,
      matchedAlertCount: evidenceAlerts.length,
      firstSeenAt: incident.first_seen_at ?? firstAlert.timestamp,
      lastSeenAt: incident.last_seen_at ?? lastAlert.timestamp,
      alerts: evidenceAlerts,
    };

    try {
      const result = await analyzeIncident(evidence);

      const sampleOnly = savedAlerts.every(
        (alert) => alert.source === "sample"
      );

      return Response.json({
        success: true,
        incidentId: incident.id,
        source: sampleOnly ? "sample" : "stored",
        notice: sampleOnly
          ? "This analysis uses synthetic sample alerts, not live Wazuh monitoring."
          : "This analysis uses stored security-alert evidence. Recommendations are advisory and do not perform response actions.",

        providerUsed: result.provider,
        fallbackUsed: result.fallbackUsed,

        incident: {
          id: incident.id,
          title: incident.title,
          severity: incident.severity,
          correlationRuleId: incident.correlation_rule_id,
          matchedAlertCount: evidenceAlerts.length,
          matchReason,
        },

        analysis: result.analysis,
      });
    } catch (error) {
      console.error(
        "[IncidentLens AI] Analysis failed:",
        error instanceof Error ? error.message : "Unknown error"
      );

      return Response.json(
        {
          error:
            "AI analysis could not be completed. Check the server terminal.",
        },
        { status: 502 }
      );
    }
  } catch (error) {
    console.error(
      "[IncidentLens AI] Request failed:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return Response.json(
      { error: "Could not process the incident analysis request." },
      { status: 500 }
    );
  }
}
