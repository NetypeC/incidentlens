"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";

type DashboardAlert = {
  id: string;
  source: string;
  source_alert_id: string;
  alert_timestamp: string;
  agent_name: string | null;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  event_type: string | null;
  source_ip: string | null;
  username: string | null;
};

type DashboardIncident = {
  id: string;
  title: string;
  severity: string;
  status: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
};

type DashboardData = {
  success: boolean;
  counts: { alerts: number; incidents: number; openIncidents: number };
  recentAlerts: DashboardAlert[];
  recentIncidents: DashboardIncident[];
};

type ImportResult = {
  success?: boolean;
  counts?: {
    received: number;
    inserted: number;
    skippedAsDuplicates: number;
    rejected: number;
  };
  error?: string;
  message?: string;
};

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

async function fetchDashboardData(): Promise<DashboardData> {
  const response = await fetch("/api/dashboard", { cache: "no-store" });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Could not load dashboard data.");
  return result as DashboardData;
}

function Stat({
  label,
  value,
  attention,
}: {
  label: string;
  value: number | undefined;
  attention?: boolean;
}) {
  return (
    <div className={`stat${attention ? " stat--attention" : ""}`}>
      <p className="stat__label">{label}</p>
      <p className="stat__value" aria-live="polite">
        {value === undefined ? (
          <span className="loading-dash">—</span>
        ) : (
          value.toLocaleString("en-GB")
        )}
      </p>
    </div>
  );
}

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [alertSearch, setAlertSearch] = useState("");

  useEffect(() => {
    let active = true;

    fetchDashboardData()
      .then((result) => {
        if (active) setData(result);
      })
      .catch((err: unknown) => {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Could not connect to the dashboard API."
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  async function importSampleAlerts() {
    setImporting(true);
    setError(null);
    setNotice(null);

    try {
      const response = await fetch("/api/alerts/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: "sample" }),
      });

      const result = (await response.json()) as ImportResult;

      if (!response.ok || !result.success) {
        throw new Error(result.error || "Could not import sample alerts.");
      }

      const counts = result.counts;

      setNotice(
        counts
          ? `Processed ${counts.received} sample alerts: ${counts.inserted} inserted, ${counts.skippedAsDuplicates} duplicates skipped, ${counts.rejected} rejected.`
          : result.message || "Sample alert import completed."
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "The sample alert import failed."
      );
      setImporting(false);
      return;
    }

    // Refresh separately so a refresh failure isn't reported as an import failure.
    try {
      setData(await fetchDashboardData());
    } catch {
      setError("Alerts were imported, but the dashboard could not refresh.");
    } finally {
      setImporting(false);
    }
  }

  const counts = data?.counts;
  const recentAlerts = data?.recentAlerts ?? [];
  const normalizedAlertSearch = alertSearch.trim().toLowerCase();

  const filteredAlerts = recentAlerts.filter((alert) =>
    [
      alert.alert_timestamp,
      alert.source_alert_id,
      alert.agent_name,
      alert.rule_id,
      alert.rule_description,
      alert.event_type,
      alert.source_ip,
      alert.username,
      alert.source,
    ]
      .filter((value): value is string => Boolean(value))
      .some((value) => value.toLowerCase().includes(normalizedAlertSearch))
  );

  return (
    <main className="dashboard">
      <header className="masthead">
        <div className="page-shell masthead__inner">
          <Link className="brand" href="/" aria-label="IncidentLens dashboard">
            <span className="brand__name">IncidentLens</span>
          </Link>
        </div>
      </header>

      <div className="page-shell dashboard-content">
        <section className="dashboard-intro" aria-labelledby="page-title">
          <h1 className="dashboard-title" id="page-title">
            Security activity
          </h1>

          <Button
            type="button"
            onClick={importSampleAlerts}
            disabled={importing || loading}
            className="button import-button"
          >
            {importing ? "Loading sample alerts..." : "Load sample alerts"}
          </Button>
        </section>

        {error && (
          <div className="message message--error" role="alert">
            {error}
          </div>
        )}

        {notice && (
          <div className="message message--success" role="status">
            {notice}
          </div>
        )}

        <section className="stats-strip" aria-label="Security statistics">
          <Stat label="Alerts" value={counts?.alerts} />
          <Stat label="Incidents" value={counts?.incidents} />
          <Stat label="Open incidents" value={counts?.openIncidents} attention />
        </section>

        {/* Incidents first: they are what needs action */}
        <section className="panel" aria-labelledby="incidents-title">
          <div className="panel__heading">
            <h2 className="panel__title" id="incidents-title">
              Recent incidents
            </h2>
            <span className="panel__count">
              {data ? `${data.recentIncidents.length} records` : ""}
            </span>
          </div>

          {data?.recentIncidents.length ? (
            <div
              className="table-wrap"
              role="region"
              aria-label="Recent incidents, horizontally scrollable table"
              tabIndex={0}
            >
              <table className="data-table incidents-table">
                <thead>
                  <tr>
                    <th scope="col">Incident</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last seen</th>
                    <th scope="col">
                      <span className="sr-only">Open incident</span>
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {data.recentIncidents.map((incident) => (
                    <tr key={incident.id}>
                      <td>
                        <Link
                          className="incident-link"
                          href={`/incidents/${incident.id}`}
                        >
                          {incident.title}
                        </Link>
                      </td>

                      <td>
                        <span className="inc-chip">
                          <span
                            className="inc-dot"
                            data-level={incident.severity.toLowerCase()}
                            aria-hidden="true"
                          />
                          {incident.severity}
                        </span>
                      </td>

                      <td className="inc-cap">{incident.status}</td>

                      <td className="table-time">
                        {formatDate(incident.last_seen_at)}
                      </td>

                      <td>
                        <Link
                          className="row-action"
                          href={`/incidents/${incident.id}`}
                          aria-label={`Investigate ${incident.title}`}
                        >
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : error && !data ? (
            <div className="table-state">
              Incident records are unavailable until the connection is restored.
            </div>
          ) : !data ? (
            <div className="table-state" role="status">
              Loading incident data...
            </div>
          ) : (
            <div className="incident-empty">
              <p className="incident-empty__label">No saved incidents</p>
              <p>
                Correlation rules can create previews, but no incident records
                are saved yet.
              </p>
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="alerts-title">
          <div className="panel__heading">
            <h2 className="panel__title" id="alerts-title">
              Recent alerts
            </h2>

            <div className="panel__tools">
              <label className="sr-only" htmlFor="alert-search">
                Search the latest saved alerts
              </label>

              <input
                id="alert-search"
                className="table-search"
                type="search"
                value={alertSearch}
                onChange={(event) => setAlertSearch(event.target.value)}
                placeholder="Search alerts"
                disabled={!data || recentAlerts.length === 0}
              />

              <span className="panel__count" aria-live="polite">
                {data
                  ? `${filteredAlerts.length} of ${recentAlerts.length}`
                  : loading
                    ? "Loading"
                    : ""}
              </span>
            </div>
          </div>

          {loading && !data ? (
            <div className="table-state" role="status">
              Loading alert data...
            </div>
          ) : recentAlerts.length > 0 && filteredAlerts.length > 0 ? (
            <div
              className="table-wrap"
              role="region"
              aria-label="Recent alert records, horizontally scrollable table"
              tabIndex={0}
            >
              <table className="data-table alerts-table">
                <thead>
                  <tr>
                    <th scope="col">Time</th>
                    <th scope="col">Alert</th>
                    <th scope="col">User / agent</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Source</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredAlerts.map((alert) => (
                    <tr key={alert.id}>
                      <td className="table-time">
                        {formatDate(alert.alert_timestamp)}
                      </td>

                      <td className="event-cell">
                        <span className="event-cell__title">
                          {alert.rule_description}
                        </span>
                        <span className="event-cell__meta">
                          {alert.event_type || "Unclassified event"}
                        </span>
                      </td>

                      <td className="identity-cell">
                        <span>{alert.username || "Unknown user"}</span>
                        <span className="identity-cell__meta">
                          {alert.agent_name || "Agent unavailable"}
                        </span>
                      </td>

                      <td className="identity-cell">
                        <span>{alert.rule_id}</span>
                        <span className="identity-cell__meta">
                          Level {alert.rule_level}
                        </span>
                      </td>

                      <td>{alert.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : recentAlerts.length > 0 ? (
            <div className="table-state" role="status">
              <h3>No matching alerts</h3>
              <p>
                Try another search term or{" "}
                <button
                  className="text-action"
                  type="button"
                  onClick={() => setAlertSearch("")}
                >
                  clear the search
                </button>
                .
              </p>
            </div>
          ) : error && !data ? (
            <div className="table-state">
              Alert records are unavailable until the connection is restored.
            </div>
          ) : (
            <div className="table-state">
              <h3>No saved alerts yet</h3>
              <p>Load the sample alerts to see how they appear here.</p>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}