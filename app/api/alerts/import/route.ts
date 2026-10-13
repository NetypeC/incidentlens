import { z } from "zod";

import {
  correlateRepeatedFailedLogins,
  correlateFailedThenSuccessfulLogin,
} from "@/lib/alerts/correlation";
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

  const successfulLoginPreview =
    correlateFailedThenSuccessfulLogin(normalizedAlerts);

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

    const incidentPreviews = [
      ...correlationPreview,
      ...successfulLoginPreview,
    ];

    const createDedupeKey = (
      preview: (typeof incidentPreviews)[number]
    ) =>
      `${preview.ruleId}:${[...preview.matchedAlertIds]
        .sort()
        .join("|")}`;

    const incidentRows = incidentPreviews.map((preview) => ({
      dedupe_key: createDedupeKey(preview),
      title: preview.title,
      summary: preview.matchReason,
      severity: preview.severity,
      confidence: "medium" as const,
      status: "open" as const,
      correlation_rule_id: preview.ruleId,
      first_seen_at: preview.firstSeenAt,
      last_seen_at: preview.lastSeenAt,
    }));

    const { data: savedAlerts, error: savedAlertsError } =
      await supabase
        .from("security_alerts")
        .select("id, source_alert_id")
        .eq("source", "sample")
        .in(
          "source_alert_id",
          normalizedAlerts.map((alert) => alert.sourceAlertId)
        );

    if (savedAlertsError) {
      console.error(
        "Could not retrieve imported alerts:",
        savedAlertsError.message
      );

      return Response.json(
        { error: "Could not retrieve saved alerts." },
        { status: 500 }
      );
    }

    const alertDatabaseIdBySourceId = new Map(
      (savedAlerts ?? []).map((alert) => [
        alert.source_alert_id,
        alert.id,
      ])
    );

    let savedIncidents: Array<{
      id: string;
      dedupe_key: string;
    }> = [];

    if (incidentRows.length > 0) {
      const { error: incidentUpsertError } = await supabase
        .from("incidents")
        .upsert(incidentRows, {
          onConflict: "dedupe_key",
          ignoreDuplicates: true,
        });

      if (incidentUpsertError) {
        console.error(
          "Could not save incidents:",
          incidentUpsertError.message
        );

        return Response.json(
          { error: "Could not save correlated incidents." },
          { status: 500 }
        );
      }

      const { data: incidentRecords, error: incidentReadError } =
        await supabase
          .from("incidents")
          .select("id, dedupe_key")
          .in(
            "dedupe_key",
            incidentRows.map((row) => row.dedupe_key)
          );

      if (incidentReadError) {
        console.error(
          "Could not retrieve saved incidents:",
          incidentReadError.message
        );

        return Response.json(
          { error: "Could not retrieve saved incidents." },
          { status: 500 }
        );
      }

      savedIncidents = incidentRecords ?? [];
    }

    const incidentIdByDedupeKey = new Map(
      savedIncidents.map((incident) => [
        incident.dedupe_key,
        incident.id,
      ])
    );

    const incidentLinks = incidentPreviews.flatMap((preview) => {
      const incidentId = incidentIdByDedupeKey.get(
        createDedupeKey(preview)
      );

      if (!incidentId) {
        return [];
      }

      return preview.matchedAlertIds.flatMap((sourceAlertId) => {
        const alertId =
          alertDatabaseIdBySourceId.get(sourceAlertId);

        if (!alertId) {
          return [];
        }

        return [
          {
            incident_id: incidentId,
            alert_id: alertId,
            match_rule_id: preview.ruleId,
            match_reason: preview.matchReason,
          },
        ];
      });
    });

    if (incidentLinks.length > 0) {
      const { error: linkError } = await supabase
        .from("incident_alerts")
        .upsert(incidentLinks, {
          onConflict: "incident_id,alert_id",
          ignoreDuplicates: true,
        });

      if (linkError) {
        console.error(
          "Could not link incident alerts:",
          linkError.message
        );

        return Response.json(
          { error: "Could not link incidents to alerts." },
          { status: 500 }
        );
      }
    }


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
      successfulLoginPreview,
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