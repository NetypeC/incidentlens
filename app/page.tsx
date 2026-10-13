"use client";

import { useCallback, useEffect, useState } from "react";

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

  counts: {
    alerts: number;
    incidents: number;
    openIncidents: number;
  };

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
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function StatusBadge({ value }: { value: string }) {
  const styles: Record<string, string> = {
    sample: "bg-amber-100 text-amber-800",
    wazuh: "bg-blue-100 text-blue-800",
    open: "bg-rose-100 text-rose-800",
    investigating: "bg-blue-100 text-blue-800",
    resolved: "bg-emerald-100 text-emerald-800",
  };

  const style =
    styles[value.toLowerCase()] ?? "bg-slate-100 text-slate-700";

  return (
    <span
      className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${style}`}
    >
      {value}
    </span>
  );
}

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {

    try {
      const response = await fetch("/api/dashboard", {
        cache: "no-store",
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(
          result.error || "Could not load dashboard data."
        );
      }

      setData(result as DashboardData);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not connect to the dashboard API."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;

    fetch("/api/dashboard", {
      cache: "no-store",
    })
      .then(async (response) => {
        const result = await response.json();

        if (!response.ok) {
          throw new Error(
            result.error || "Could not load dashboard data."
          );
        }

        return result as DashboardData;
      })
      .then((result) => {
        if (active) {
          setData(result);
        }
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
        if (active) {
          setLoading(false);
        }
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
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          source: "sample",
        }),
      });

      const result = (await response.json()) as ImportResult;

      if (!response.ok || !result.success) {
        throw new Error(
          result.error || "Could not import sample alerts."
        );
      }

      const counts = result.counts;

      if (counts) {
        setNotice(
          `Processed ${counts.received} sample alerts: ` +
            `${counts.inserted} inserted, ` +
            `${counts.skippedAsDuplicates} duplicates skipped, ` +
            `${counts.rejected} rejected.`
        );
      } else {
        setNotice(
          result.message || "Sample-alert import completed."
        );
      }

      await loadDashboard();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "The sample-alert import failed."
      );
    } finally {
      setImporting(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-slate-900 text-lg font-bold text-white">
              IL
            </div>

            <div>
              <h1 className="text-xl font-bold tracking-tight">
                IncidentLens
              </h1>
              <p className="text-sm text-slate-500">
                Security alert investigation
              </p>
            </div>
          </div>

          <span className="w-fit rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-800">
            Development mode · Sample data
          </span>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <section className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-500">
              Overview
            </p>

            <h2 className="text-3xl font-bold tracking-tight">
              Security dashboard
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              Review stored security alerts and monitor your
              development progress. Sample records are not live
              security monitoring.
            </p>
          </div>

          <button
            type="button"
            onClick={importSampleAlerts}
            disabled={importing || loading}
            className="rounded-lg bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {importing
              ? "Importing sample alerts..."
              : "Import sample alerts"}
          </button>
        </section>

        {error && (
          <div
            role="alert"
            className="mb-6 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800"
          >
            {error}
          </div>
        )}

        {notice && (
          <div
            role="status"
            className="mb-6 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800"
          >
            {notice}
          </div>
        )}

        <section
          aria-label="Security statistics"
          className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3"
        >
          <StatCard
            title="Total alerts"
            value={data?.counts.alerts}
            description="Alerts stored in Supabase"
            loading={loading}
          />

          <StatCard
            title="Saved incidents"
            value={data?.counts.incidents}
            description="Incident records in the database"
            loading={loading}
          />

          <StatCard
            title="Open incidents"
            value={data?.counts.openIncidents}
            description="Incidents awaiting investigation"
            loading={loading}
          />
        </section>

        <section className="mb-8 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
            <h3 className="font-semibold">Recent security alerts</h3>
            <p className="mt-1 text-sm text-slate-500">
              The newest alert records saved in your database.
            </p>
          </div>

          {loading && !data ? (
            <div className="px-6 py-10 text-sm text-slate-500">
              Loading alert data...
            </div>
          ) : data?.recentAlerts.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-5 py-3 font-medium">Time</th>
                    <th className="px-5 py-3 font-medium">Event</th>
                    <th className="px-5 py-3 font-medium">User</th>
                    <th className="px-5 py-3 font-medium">Agent</th>
                    <th className="px-5 py-3 font-medium">Rule</th>
                    <th className="px-5 py-3 font-medium">Level</th>
                    <th className="px-5 py-3 font-medium">Source</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-100">
                  {data.recentAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className="transition hover:bg-slate-50"
                    >
                      <td className="whitespace-nowrap px-5 py-4 text-slate-500">
                        {formatDate(alert.alert_timestamp)}
                      </td>

                      <td className="max-w-sm px-5 py-4">
                        <p className="font-medium text-slate-900">
                          {alert.rule_description}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">
                          {alert.event_type || "Unclassified event"}
                        </p>
                      </td>

                      <td className="px-5 py-4">
                        {alert.username || "—"}
                      </td>

                      <td className="px-5 py-4">
                        {alert.agent_name || "—"}
                      </td>

                      <td className="px-5 py-4 font-mono text-xs">
                        {alert.rule_id}
                      </td>

                      <td className="px-5 py-4">
                        {alert.rule_level}
                      </td>

                      <td className="px-5 py-4">
                        <StatusBadge value={alert.source} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="px-6 py-10 text-sm text-slate-500">
              No alerts have been saved yet. Click{" "}
              <span className="font-medium text-slate-700">
                Import sample alerts
              </span>{" "}
              to load the development test records.
            </div>
          )}

          <div className="border-t border-slate-200 px-5 py-3 text-xs text-slate-500 sm:px-6">
            Alert records are read from Supabase. Sample events are
            labelled and must not be treated as live security data.
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
            <h3 className="font-semibold">Recent incidents</h3>
            <p className="mt-1 text-sm text-slate-500">
              Incidents saved by the correlation workflow.
            </p>
          </div>

          {data?.recentIncidents.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[650px] text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-5 py-3 font-medium">Incident</th>
                    <th className="px-5 py-3 font-medium">Severity</th>
                    <th className="px-5 py-3 font-medium">Status</th>
                    <th className="px-5 py-3 font-medium">Last seen</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-100">
                  {data.recentIncidents.map((incident) => (
                    <tr key={incident.id}>
                      <td className="px-5 py-4 font-medium">
                        <a
                          href={`/incidents/${incident.id}`}
                          className="text-blue-700 hover:underline"
                        >
                          {incident.title}
                        </a>
                      </td>

                      <td className="px-5 py-4 capitalize">
                        {incident.severity}
                      </td>

                      <td className="px-5 py-4">
                        <StatusBadge value={incident.status} />
                      </td>

                      <td className="whitespace-nowrap px-5 py-4 text-slate-500">
                        {formatDate(incident.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="px-6 py-8">
              <p className="text-sm font-medium text-slate-700">
                No incident records have been saved yet.
              </p>

              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                Your correlation rules can currently produce incident
                previews, but the results have not yet been saved to
                the incidents table. This section will show saved
                incidents after that workflow is implemented.
              </p>
            </div>
          )}
        </section>

        <footer className="py-8 text-center text-xs text-slate-500">
          IncidentLens · Local development prototype
        </footer>
      </div>
    </main>
  );
}

function StatCard({
  title,
  value,
  description,
  loading,
}: {
  title: string;
  value: number | undefined;
  description: string;
  loading: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">
        {title}
      </p>

      <p className="mt-3 text-3xl font-bold tracking-tight text-slate-900">
        {loading && value === undefined ? "—" : value ?? 0}
      </p>

      <p className="mt-2 text-xs text-slate-500">
        {description}
      </p>
    </div>
  );
}