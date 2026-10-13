"use client";

import { Suspense, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";

type Incident = {
  id: string;
  title: string;
  summary: string | null;
  severity: string;
  confidence: string;
  status: string;
  correlation_rule_id: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  created_at: string;
};

type IncidentAlert = {
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
};

type IncidentDetailResponse = {
  success: boolean;
  incident: Incident;
  alerts: IncidentAlert[];
  alertCount: number;
  error?: string;
};

type Recommendation = {
  priority: "low" | "medium" | "high";
  action: string;
  reason: string;
};

type IncidentAnalysis = {
  summary: string;
  facts: string[];
  interpretation: string;
  confidence: "low" | "medium" | "high";
  uncertainties: string[];
  recommendations: Recommendation[];
  conclusion: string;
};

type AnalysisResponse = {
  success?: boolean;
  error?: string;
  notice?: string;
  providerUsed?: string;
  fallbackUsed?: boolean;
  analysis?: IncidentAnalysis;
};

function formatDate(value: string | null): string {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function Badge({ value }: { value: string }) {
  const styles: Record<string, string> = {
    low: "bg-slate-100 text-slate-700",
    medium: "bg-amber-100 text-amber-800",
    high: "bg-orange-100 text-orange-800",
    critical: "bg-red-100 text-red-800",
    open: "bg-rose-100 text-rose-800",
    investigating: "bg-blue-100 text-blue-800",
    resolved: "bg-emerald-100 text-emerald-800",
    sample: "bg-amber-100 text-amber-800",
    wazuh: "bg-blue-100 text-blue-800",
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

function EvidenceList({ items }: { items: string[] }) {
  if (items.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        No items were returned.
      </p>
    );
  }

  return (
    <ul className="list-disc space-y-2 pl-5 text-sm leading-6 text-slate-700">
      {items.map((item, index) => (
        <li key={`${index}-${item}`}>{item}</li>
      ))}
    </ul>
  );
}

function IncidentInvestigationContent() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const [detail, setDetail] =
    useState<IncidentDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] =
    useState<string | null>(null);
  const [analysisResult, setAnalysisResult] =
    useState<AnalysisResponse | null>(null);

  useEffect(() => {
    let active = true;

    fetch(`/api/incidents/${encodeURIComponent(id)}`, {
      cache: "no-store",
    })
      .then(async (response) => {
        const result =
          (await response.json()) as IncidentDetailResponse;

        if (!response.ok || !result.success) {
          throw new Error(
            result.error || "Could not load this incident."
          );
        }

        return result;
      })
      .then((result) => {
        if (active) setDetail(result);
      })
      .catch((err: unknown) => {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Could not load this incident."
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [id]);

  async function runAnalysis() {
    setAnalyzing(true);
    setAnalysisError(null);
    setAnalysisResult(null);

    try {
      const response = await fetch("/api/alerts/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ incidentId: id }),
      });

      const result =
        (await response.json()) as AnalysisResponse;

      if (
        !response.ok ||
        !result.success ||
        !result.analysis
      ) {
        throw new Error(
          result.error || "AI analysis could not be completed."
        );
      }

      setAnalysisResult(result);
    } catch (err) {
      setAnalysisError(
        err instanceof Error
          ? err.message
          : "AI analysis could not be completed."
      );
    } finally {
      setAnalyzing(false);
    }
  }

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-50 p-8 text-slate-600">
        Loading incident and evidence...
      </main>
    );
  }

  if (error || !detail) {
    return (
      <main className="min-h-screen bg-slate-50 p-8">
        <Link
          href="/"
          className="text-sm font-medium text-blue-700 hover:underline"
        >
          ← Back to dashboard
        </Link>

        <div
          role="alert"
          className="mt-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800"
        >
          {error || "Incident not found."}
        </div>
      </main>
    );
  }

  const incident = detail.incident;

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-5 sm:px-8">
          <div>
            <p className="text-xl font-bold">IncidentLens</p>
            <p className="text-sm text-slate-500">
              Incident investigation
            </p>
          </div>

          <Badge value="Development · Sample data" />
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
        <Link
          href="/"
          className="text-sm font-medium text-blue-700 hover:underline"
        >
          ← Back to dashboard
        </Link>

        <section className="mb-8 mt-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
            <div className="min-w-0">
              <p className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                Incident investigation
              </p>

              <h1 className="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">
                {incident.title}
              </h1>

              <div className="mt-4 flex flex-wrap gap-2">
                <Badge value={incident.severity} />
                <Badge value={incident.status} />
              </div>

              <p className="mt-4 break-all font-mono text-xs text-slate-500">
                Incident ID: {incident.id}
              </p>
            </div>

            <button
              type="button"
              onClick={runAnalysis}
              disabled={analyzing || detail.alerts.length === 0}
              className="shrink-0 rounded-lg bg-slate-900 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {analyzing
                ? "Analysing evidence..."
                : "Analyse with AI"}
            </button>
          </div>

          <div className="mt-6 grid gap-4 border-t border-slate-100 pt-5 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <p className="text-xs text-slate-500">
                Linked alerts
              </p>
              <p className="mt-1 text-2xl font-bold">
                {detail.alertCount}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">
                Correlation rule
              </p>
              <p className="mt-1 break-words font-mono text-sm">
                {incident.correlation_rule_id}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">
                First seen
              </p>
              <p className="mt-1 text-sm">
                {formatDate(incident.first_seen_at)}
              </p>
            </div>

            <div>
              <p className="text-xs text-slate-500">
                Last seen
              </p>
              <p className="mt-1 text-sm">
                {formatDate(incident.last_seen_at)}
              </p>
            </div>
          </div>

          {incident.summary && (
            <div className="mt-6 rounded-lg bg-slate-50 p-4">
              <h2 className="text-sm font-semibold">
                Why this incident matched
              </h2>
              <p className="mt-2 text-sm leading-6 text-slate-700">
                {incident.summary}
              </p>
            </div>
          )}

          <p className="mt-4 text-xs leading-5 text-amber-800">
            This is a development investigation using synthetic
            sample alerts, not live Wazuh monitoring. AI findings
            are advisory and do not prove that an account was
            compromised.
          </p>
        </section>

        {analysisError && (
          <div
            role="alert"
            className="mb-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800"
          >
            {analysisError}
          </div>
        )}

        {analysisResult?.analysis && (
          <section className="mb-8 rounded-xl border border-blue-200 bg-white p-6 shadow-sm">
            <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-start">
              <div>
                <h2 className="text-xl font-bold">
                  AI investigation report
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  Provider: {analysisResult.providerUsed || "Unknown"}
                  {analysisResult.fallbackUsed
                    ? " · Fallback provider used"
                    : ""}
                </p>
              </div>

              <Badge
                value={`${analysisResult.analysis.confidence} confidence`}
              />
            </div>

            {analysisResult.notice && (
              <p className="mt-4 text-xs leading-5 text-amber-800">
                {analysisResult.notice}
              </p>
            )}

            <div className="mt-5 space-y-6">
              <div>
                <h3 className="font-semibold">Summary</h3>
                <p className="mt-2 text-sm leading-6 text-slate-700">
                  {analysisResult.analysis.summary}
                </p>
              </div>

              <div>
                <h3 className="font-semibold">Observed facts</h3>
                <div className="mt-2">
                  <EvidenceList
                    items={analysisResult.analysis.facts}
                  />
                </div>
              </div>

              <div>
                <h3 className="font-semibold">Interpretation</h3>
                <p className="mt-2 text-sm leading-6 text-slate-700">
                  {analysisResult.analysis.interpretation}
                </p>
              </div>

              <div>
                <h3 className="font-semibold">
                  Recommended investigation steps
                </h3>

                <div className="mt-3 space-y-3">
                  {analysisResult.analysis.recommendations.map(
                    (recommendation, index) => (
                      <div
                        key={`${index}-${recommendation.action}`}
                        className="rounded-lg border border-slate-200 p-4"
                      >
                        <Badge value={recommendation.priority} />
                        <h4 className="mt-2 font-medium">
                          {recommendation.action}
                        </h4>
                        <p className="mt-1 text-sm leading-6 text-slate-600">
                          {recommendation.reason}
                        </p>
                      </div>
                    )
                  )}
                </div>
              </div>

              <div>
                <h3 className="font-semibold">Uncertainties</h3>
                <div className="mt-2">
                  <EvidenceList
                    items={analysisResult.analysis.uncertainties}
                  />
                </div>
              </div>

              <div>
                <h3 className="font-semibold">Conclusion</h3>
                <p className="mt-2 text-sm leading-6 text-slate-700">
                  {analysisResult.analysis.conclusion}
                </p>
              </div>
            </div>
          </section>
        )}

        <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
            <h2 className="font-semibold">Linked security evidence</h2>
            <p className="mt-1 text-sm text-slate-500">
              Actual alert records associated with this saved incident.
            </p>
          </div>

          {detail.alerts.length === 0 ? (
            <p className="p-6 text-sm text-slate-500">
              No alert records are linked to this incident yet.
            </p>
          ) : (
            <div className="divide-y divide-slate-100">
              {detail.alerts.map((alert) => (
                <article key={alert.id} className="p-5 sm:px-6">
                  <div className="flex flex-col justify-between gap-3 sm:flex-row">
                    <div className="min-w-0">
                      <p className="font-medium">
                        {alert.rule_description || "Security alert"}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {alert.event_type || "Unclassified event"}
                      </p>
                    </div>

                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      <Badge value={alert.source} />
                      <span className="rounded bg-slate-100 px-2 py-1 text-xs text-slate-700">
                        Rule level {alert.rule_level}
                      </span>
                    </div>
                  </div>

                  <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <dt className="text-xs text-slate-500">Time</dt>
                      <dd className="mt-1">
                        {formatDate(alert.alert_timestamp)}
                      </dd>
                    </div>

                    <div>
                      <dt className="text-xs text-slate-500">Username</dt>
                      <dd className="mt-1">{alert.username || "Unavailable"}</dd>
                    </div>

                    <div>
                      <dt className="text-xs text-slate-500">Source IP</dt>
                      <dd className="mt-1">
                        {alert.source_ip || "Unavailable"}
                      </dd>
                    </div>

                    <div>
                      <dt className="text-xs text-slate-500">Agent</dt>
                      <dd className="mt-1">
                        {alert.agent_name || "Unavailable"}
                      </dd>
                    </div>
                  </dl>

                  {alert.match_reason && (
                    <div className="mt-4 rounded-lg bg-slate-50 p-3">
                      <p className="text-xs font-semibold text-slate-600">
                        Match reason
                      </p>
                      <p className="mt-1 text-sm leading-5 text-slate-600">
                        {alert.match_reason}
                      </p>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>

        <footer className="py-8 text-center text-xs text-slate-500">
          IncidentLens · Local development prototype
        </footer>
      </div>
    </main>
  );
}export default function IncidentInvestigationPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen bg-slate-50 p-8 text-slate-600">
          Loading incident investigation...
        </main>
      }
    >
      <IncidentInvestigationContent />
    </Suspense>
  );
}

