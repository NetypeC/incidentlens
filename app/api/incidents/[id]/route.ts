import { createAdminClient } from "@/lib/supabase/admin";

type RouteContext = {
  params: Promise<{ id: string }>;
};

export async function GET(
  _request: Request,
  context: RouteContext
) {
  // Development-only until authentication and authorization
  // are implemented for incident access.
  if (process.env.NODE_ENV === "production") {
    return Response.json(
      { error: "Not found." },
      { status: 404 }
    );
  }

  const { id } = await context.params;

  // Validate that the supplied incident ID is a UUID.
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      id
    )
  ) {
    return Response.json(
      { error: "Invalid incident ID." },
      { status: 400 }
    );
  }

  try {
    const supabase = createAdminClient();

    // 1. Retrieve the selected incident.
    const { data: incident, error: incidentError } =
      await supabase
        .from("incidents")
        .select(
          "id, title, summary, severity, confidence, status, correlation_rule_id, first_seen_at, last_seen_at, created_at"
        )
        .eq("id", id)
        .maybeSingle();

    if (incidentError) {
      console.error(
        "[Incident detail] Incident lookup failed:",
        incidentError.message
      );

      return Response.json(
        { error: "Could not load this incident." },
        { status: 500 }
      );
    }

    if (!incident) {
      return Response.json(
        { error: "Incident not found." },
        { status: 404 }
      );
    }

    // 2. Find the alerts linked to this incident.
    const { data: links, error: linksError } = await supabase
      .from("incident_alerts")
      .select("alert_id, match_rule_id, match_reason")
      .eq("incident_id", id);

    if (linksError) {
      console.error(
        "[Incident detail] Alert-link lookup failed:",
        linksError.message
      );

      return Response.json(
        { error: "Could not load the incident evidence." },
        { status: 500 }
      );
    }

    const alertIds = [
      ...new Set((links ?? []).map((link) => link.alert_id)),
    ];

    // 3. Retrieve the actual security-alert records.
    let alerts: Array<{
      id: string;
      source: string;
      source_alert_id: string;
      alert_timestamp: string;
      agent_name: string | null;
      rule_id: string;
      rule_level: number;
      rule_description: string | null;
      event_type: string | null;
      source_ip: string | null;
      username: string | null;
      match_rule_id: string | null;
      match_reason: string | null;
    }> = [];

    if (alertIds.length > 0) {
      const { data: savedAlerts, error: alertsError } =
        await supabase
          .from("security_alerts")
          .select(
            "id, source, source_alert_id, alert_timestamp, agent_name, rule_id, rule_level, rule_description, event_type, source_ip, username"
          )
          .in("id", alertIds)
          .order("alert_timestamp", { ascending: true });

      if (alertsError) {
        console.error(
          "[Incident detail] Alert lookup failed:",
          alertsError.message
        );

        return Response.json(
          { error: "Could not load the linked alerts." },
          { status: 500 }
        );
      }

      const linkByAlertId = new Map(
        (links ?? []).map((link) => [link.alert_id, link])
      );

      alerts = (savedAlerts ?? []).map((alert) => {
        const link = linkByAlertId.get(alert.id);

        return {
          ...alert,
          match_rule_id: link?.match_rule_id ?? null,
          match_reason: link?.match_reason ?? null,
        };
      });
    }

    return Response.json(
      {
        success: true,
        incident,
        alerts,
        alertCount: alerts.length,
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  } catch (error) {
    console.error(
      "[Incident detail] Request failed:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return Response.json(
      { error: "Could not retrieve the incident." },
      { status: 500 }
    );
  }
}