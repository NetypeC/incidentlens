import { createAdminClient } from "@/lib/supabase/admin";
import { connection } from "next/server";

export async function GET() {
    await connection();

  if (process.env.NODE_ENV === "production") {
    return Response.json(
      { error: "Not found." },
      { status: 404 }
    );
  }

  try {
    const supabase = createAdminClient();

    const [
      alertCountResult,
      incidentCountResult,
      openIncidentCountResult,
      recentAlertsResult,
      recentIncidentsResult,
    ] = await Promise.all([
      supabase
        .from("security_alerts")
        .select("id", { count: "exact", head: true }),

      supabase
        .from("incidents")
        .select("id", { count: "exact", head: true }),

      supabase
        .from("incidents")
        .select("id", { count: "exact", head: true })
        .eq("status", "open"),

      supabase
        .from("security_alerts")
        .select(
          [
            "id",
            "source",
            "source_alert_id",
            "alert_timestamp",
            "agent_name",
            "rule_id",
            "rule_level",
            "rule_description",
            "event_type",
            "source_ip",
            "username",
          ].join(", ")
        )
        .order("alert_timestamp", { ascending: false })
        .limit(10),

      supabase
        .from("incidents")
        .select(
          "id, title, severity, status, first_seen_at, last_seen_at"
        )
        .order("created_at", { ascending: false })
        .limit(5),
    ]);

    const queryError = [
      alertCountResult.error,
      incidentCountResult.error,
      openIncidentCountResult.error,
      recentAlertsResult.error,
      recentIncidentsResult.error,
    ].find(Boolean);

    if (queryError) {
      console.error(
        "[Dashboard] Database query failed:",
        queryError.message
      );

      return Response.json(
        { error: "Could not load dashboard data." },
        { status: 500 }
      );
    }

    return Response.json(
      {
        success: true,

        counts: {
          alerts: alertCountResult.count ?? 0,
          incidents: incidentCountResult.count ?? 0,
          openIncidents: openIncidentCountResult.count ?? 0,
        },

        recentAlerts: recentAlertsResult.data ?? [],
        recentIncidents: recentIncidentsResult.data ?? [],
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  } catch (error) {
    console.error(
      "[Dashboard] Failed to load data:",
      error instanceof Error ? error.message : "Unknown error"
    );

    return Response.json(
      { error: "Could not load dashboard data." },
      { status: 500 }
    );
  }
}