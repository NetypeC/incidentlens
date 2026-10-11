import { z } from "zod";

import { correlateRepeatedFailedLogins } from "@/lib/alerts/correlation";
import { normalizeWazuhAlert } from "@/lib/alerts/normalizer";
import { sampleWazuhAlerts } from "@/lib/alerts/sample-wazuh-alerts";
import {
  SampleImportRequestSchema,
  WazuhAlertSchema,
} from "@/lib/alerts/schema";
import { createAdminClient } from "@/lib/supabase/admin";

export async function POST(request: Request) {
  if (process.env.NODE_ENV === "production") {
    return Response.json({ error: "Not found." }, { status: 404 });
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

  const requestResult = SampleImportRequestSchema.safeParse(body);

  if (!requestResult.success) {
    return Response.json(
      { error: 'Request must contain { "source": "sample" }.' },
      { status: 400 }
    );
  }

  type Alert = z.infer<typeof WazuhAlertSchema>;

  const acceptedAlerts: Alert[] = [];

  const rejectedAlerts: Array<{
    alertId: string;
    issues: Array<{ path: string; message: string }>;
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

  if (rejectedAlerts.length > 0) {
    return Response.json(
      {
        success: false,
        message: "Some sample alerts failed validation.",
        counts: {
          received: sampleWazuhAlerts.length,
          accepted: acceptedAlerts.length,
          rejected: rejectedAlerts.length,
        },
        rejectedAlerts,
      },
      { status: 422 }
    );
  }

  const normalizedAlerts = acceptedAlerts.map((alert) =>
    normalizeWazuhAlert(alert, "sample")
  );

  const correlationPreview =
    correlateRepeatedFailedLogins(normalizedAlerts);

  const rows = normalizedAlerts.map((alert) => ({
    source: alert.source,
    source_alert_id: alert.sourceAlertId,
    alert_timestamp: alert.timestamp,

    agent_id: alert.agentId,
    agent_name: alert.agentName,
    agent_ip: alert.rawAlert.agent?.ip ?? null,

    rule_id: alert.ruleId,
    rule_level: alert.ruleLevel,
    rule_description: alert.ruleDescription,

    event_type: alert.eventType,
    source_ip: alert.sourceIp,
    username: alert.username,

    raw_alert: alert.rawAlert,
  }));

  try {
    const supabase = createAdminClient();

    const { data, error } = await supabase
      .from("security_alerts")
      .upsert(rows, {
        onConflict: "source,source_alert_id",
        ignoreDuplicates: true,
      })
      .select("id, source_alert_id");

    if (error) {
      console.error("Sample alert import failed:", error.message);

      return Response.json(
        {
          error:
            "Could not save alerts to Supabase. Check the server terminal.",
        },
        { status: 500 }
      );
    }

    const inserted = data?.length ?? 0;

    return Response.json({
      success: true,
      source: "sample",
      mode: "development-test",
      stored: true,
      message:
        "Sample alerts were processed. They are not live Wazuh data.",
      counts: {
        received: sampleWazuhAlerts.length,
        accepted: acceptedAlerts.length,
        rejected: 0,
        inserted,
        skippedAsDuplicates: acceptedAlerts.length - inserted,
      },
      normalizationPreview: normalizedAlerts.slice(0, 3).map((alert) => ({
        sourceAlertId: alert.sourceAlertId,
        eventType: alert.eventType,
        sourceIp: alert.sourceIp,
        username: alert.username,
        agentName: alert.agentName,
        ruleId: alert.ruleId,
      })),
      correlationPreview,
    });
  } catch (error) {
    console.error(
      "Sample alert import failed:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return Response.json(
      {
        error:
          "Could not save alerts to Supabase. Check the server terminal.",
      },
      { status: 500 }
    );
  }
}