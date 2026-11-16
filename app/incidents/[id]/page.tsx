"use client";

import { Suspense, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";

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
};

type IncidentAlert = {
  id: string;
  source: string;
  alert_timestamp: string;
  agent_name: string | null;
  rule_level: number;
  rule_description: string | null;
  event_type: string | null;
  source_ip: string | null;
  username: string | null;
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

function Dot({ level }: { level: string }) {
  return (
    <span
      className="inc-dot"
      data-level={level.toLowerCase()}
      aria-hidden="true"
    />
  );
}

function PlainList({ items }: { items: string[] }) {
  if (!items.length) return <p className="inc-muted">Nothing returned.</p>;

  return (
    <ul className="inc-list">
      {items.map((item, index) => (
        <li key={`${index}-${item}`}>{item}</li>
      ))}
    </ul>
  );
}

function IncidentInvestigation() {
  const { id } = useParams<{ id: string }>();

  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(
    null
  );

  useEffect(() => {
    let active = true;

    // Reset so a previous incident never flashes while the next one loads.
    setLoading(true);
    setError(null);
    setDetail(null);
    setAnalysisResult(null);
    setAnalysisError(null);

    async function loadIncident() {
      try {
        const response = await fetch(
          `/api/incidents/${encodeURIComponent(id)}`,
          { cache: "no-store" }
        );
        const result = (await response.json()) as IncidentDetailResponse;

        if (!response.ok || !result.success) {
          throw new Error(result.error || "Could not load this incident.");
        }

        if (active) setDetail(result);
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error ? err.message : "Could not load this incident."
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    loadIncident();

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
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId: id }),
      });
      const result = (await response.json()) as AnalysisResponse;

      if (!response.ok || !result.success || !result.analysis) {
        throw new Error(result.error || "AI analysis could not be completed.");
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
      <main className="incident-page">
        <div className="page-shell page-state" role="status">
          Loading incident...
        </div>
      </main>
    );
  }

  if (error || !detail) {
    return (
      <main className="incident-page">
        <div className="page-shell page-state">
          <Link href="/">Back to dashboard</Link>
          <p role="alert">{error || "Incident not found."}</p>
        </div>
      </main>
    );
  }

  const { incident, alerts, alertCount } = detail;
  const analysis = analysisResult?.analysis;
  const facts = analysis?.facts ?? [];
  const uncertainties = analysis?.uncertainties ?? [];
  const recommendations = analysis?.recommendations ?? [];

  return (
    <main className="incident-page">
      <header className="masthead">
        <div className="page-shell masthead__inner">
          <Link className="brand" href="/">
            <span className="brand__name">IncidentLens</span>
          </Link>
        </div>
      </header>

      <div className="page-shell inc">
        <Link className="back-link" href="/">
          Back to dashboard
        </Link>

        <header className="inc-header">
          <div>
            <h1>{incident.title}</h1>
            <p className="inc-status">
              <span className="inc-chip">
                <Dot level={incident.severity} />
                {incident.severity} severity
              </span>
              <span className="inc-chip">{incident.status}</span>
            </p>
          </div>

          <Button
            type="button"
            onClick={runAnalysis}
            disabled={analyzing || alerts.length === 0}
            className="button"
          >
            {analyzing
              ? "Analyzing..."
              : analysis
                ? "Regenerate analysis"
                : "Generate analysis"}
          </Button>
        </header>

        {incident.summary && <p className="inc-lede">{incident.summary}</p>}

        <dl className="inc-facts">
          <div>
            <dt>Linked alerts</dt>
            <dd>{alertCount}</dd>
          </div>
          <div>
            <dt>Grouping confidence</dt>
            <dd className="inc-cap">{incident.confidence}</dd>
          </div>
          <div>
            <dt>First seen</dt>
            <dd>{formatDate(incident.first_seen_at)}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{formatDate(incident.last_seen_at)}</dd>
          </div>
        </dl>

        <details className="inc-details">
          <summary>Technical details</summary>
          <dl className="inc-tech">
            <div>
              <dt>Correlation rule</dt>
              <dd>{incident.correlation_rule_id}</dd>
            </div>
            <div>
              <dt>Incident ID</dt>
              <dd>{incident.id}</dd>
            </div>
          </dl>
        </details>

        {analysisError && (
          <div className="message message--error" role="alert">
            {analysisError}
          </div>
        )}

        {analysis && (
          <section className="inc-section" aria-labelledby="analysis-title">
            <div className="inc-section__head">
              <h2 id="analysis-title">Analysis</h2>
              <p className="inc-muted">
                <span className="inc-cap">{analysis.confidence}</span> analysis
                confidence, from {analysisResult?.providerUsed || "unknown"}
                {analysisResult?.fallbackUsed ? " (fallback)" : ""}
              </p>
            </div>

            <p className="inc-note">
              AI findings are advisory and do not prove an account was
              compromised.
            </p>

            {analysisResult?.notice && (
              <p className="inc-note">{analysisResult.notice}</p>
            )}

            <div className="inc-block">
              <h3>Summary</h3>
              <p>{analysis.summary}</p>
            </div>

            <div className="inc-block">
              <h3>Conclusion</h3>
              <p>{analysis.conclusion}</p>
            </div>

            <div className="inc-block">
              <h3>Next steps</h3>
              <ol className="inc-steps">
                {recommendations.map((item, index) => (
                  <li key={`${index}-${item.action}`}>
                    <p className="inc-steps__action">
                      <Dot level={item.priority} />
                      {item.action}
                    </p>
                    <p className="inc-muted">{item.reason}</p>
                  </li>
                ))}
              </ol>
            </div>

            <details className="inc-details">
              <summary>Full reasoning</summary>

              <div className="inc-block">
                <h3>What was observed</h3>
                <PlainList items={facts} />
              </div>

              <div className="inc-block">
                <h3>Interpretation</h3>
                <p>{analysis.interpretation}</p>
              </div>

              <div className="inc-block">
                <h3>What is still uncertain</h3>
                <PlainList items={uncertainties} />
              </div>
            </details>
          </section>
        )}

        <section className="inc-section" aria-labelledby="alerts-title">
          <div className="inc-section__head">
            <h2 id="alerts-title">Alerts</h2>
            <p className="inc-muted">{alertCount} linked</p>
          </div>

          {alerts.length === 0 ? (
            <p className="inc-muted">
              No alert records are linked to this incident.
            </p>
          ) : (
            <ol className="inc-alerts">
              {alerts.map((alert) => (
                <li className="inc-alert" key={alert.id}>
                  <time
                    className="inc-alert__time"
                    dateTime={alert.alert_timestamp}
                  >
                    {formatDate(alert.alert_timestamp)}
                  </time>

                  <div>
                    <h3>{alert.rule_description || "Security alert"}</h3>
                    <p className="inc-muted">
                      {alert.event_type || "Unclassified event"}, {alert.source},
                      rule level {alert.rule_level}
                    </p>
                    <p className="inc-muted">
                      {alert.username || "Unknown user"} on{" "}
                      {alert.agent_name || "unknown agent"}, from{" "}
                      {alert.source_ip || "unknown IP"}
                    </p>

                    {alert.match_reason && (
                      <details className="inc-details inc-details--small">
                        <summary>Why it matched</summary>
                        <p className="inc-reason">{alert.match_reason}</p>
                      </details>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <footer className="dashboard__footer">
          IncidentLens / Local development
        </footer>
      </div>
    </main>
  );
}

export default function IncidentInvestigationPage() {
  return (
    <Suspense
      fallback={
        <main className="incident-page">
          <div className="page-shell page-state" role="status">
            Loading incident...
          </div>
        </main>
      }
    >
      <IncidentInvestigation />
    </Suspense>
  );
}