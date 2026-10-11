import { z } from "zod";

import { sampleWazuhAlerts } from "@/lib/alerts/sample-wazuh-alerts";
import {
  SampleImportRequestSchema,
  WazuhAlertSchema,
} from "@/lib/alerts/schema";
import { createAdminClient } from "@/lib/supabase/admin";

function getString(
  record: Record<string, unknown> | undefined,
  key: string
): string | null {
  const value = record?.[key];

  return typeof value === "string" && value.trim().length > 0
    ? value
    : null;
}

export async function POST(request: Request) {
  // This sample-data endpoint must not run in production.
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

  // Validate every alert before attempting a database write.
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

  // Fail the batch instead of storing a partial set of test alerts.
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

  // Convert the validated records into database rows.
  const rows = acceptedAlerts.map((alert) => {
    const groups = alert.rule.groups ?? [];

    let eventType: string | null = null;

    if (groups.includes("authentication_failed")) {
      eventType = "authentication_failed";
    } else if (groups.includes("authentication_success")) {
      eventType = "authentication_success";
    } else if (groups.includes("syscheck")) {
      eventType = "file_integrity_change";
    } else if (groups.length > 0) {
      eventType = groups[0];
    }

    return {
      source: "sample" as const,
      source_alert_id: alert.id,
      alert_timestamp: alert.timestamp,

      agent_id: alert.agent.id ?? null,
      agent_name: alert.agent.name ?? null,
      agent_ip: alert.agent.ip ?? null,

      rule_id: alert.rule.id,
      rule_level: alert.rule.level,
      rule_description: alert.rule.description,

      event_type: eventType,
      source_ip: getString(alert.data, "srcip"),
      username:
        getString(alert.data, "dstuser") ??
        getString(alert.data, "username") ??
        getString(alert.data, "user"),

      raw_alert: alert,
    };
  });

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