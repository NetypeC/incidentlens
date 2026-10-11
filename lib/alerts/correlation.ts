import type { NormalizedSecurityAlert } from "./types";

const RULE_ID = "repeated_failed_logins_v1";

const DEFAULT_THRESHOLD = 5;
const DEFAULT_WINDOW_MINUTES = 10;

export type CorrelatedIncidentPreview = {
  ruleId: string;
  title: string;
  severity: "medium";
  matchedAlertIds: string[];
  matchedAlertCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  matchReason: string;
};

type WindowRange = {
  startIndex: number;
  endIndex: number;
};

export function correlateRepeatedFailedLogins(
  alerts: NormalizedSecurityAlert[],
  options: {
    threshold?: number;
    windowMinutes?: number;
  } = {}
): CorrelatedIncidentPreview[] {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const windowMinutes =
    options.windowMinutes ?? DEFAULT_WINDOW_MINUTES;

  if (!Number.isInteger(threshold) || threshold < 2) {
    throw new Error("Threshold must be an integer of at least 2.");
  }

  if (!Number.isFinite(windowMinutes) || windowMinutes <= 0) {
    throw new Error("Window duration must be greater than zero.");
  }

  const windowMs = windowMinutes * 60 * 1000;

  // Keep only failed-login alerts with enough information
  // to make a reliable account-and-IP match.
  const groups = new Map<string, NormalizedSecurityAlert[]>();

  for (const alert of alerts) {
    if (
      alert.eventType !== "authentication_failed" ||
      !alert.username ||
      !alert.sourceIp
    ) {
      continue;
    }

    const key = JSON.stringify([
      alert.username,
      alert.sourceIp,
    ]);

    const group = groups.get(key) ?? [];
    group.push(alert);
    groups.set(key, group);
  }

  const incidents: CorrelatedIncidentPreview[] = [];

  for (const group of groups.values()) {
    // Sort each account/IP group from oldest to newest.
    group.sort(
      (a, b) =>
        Date.parse(a.timestamp) - Date.parse(b.timestamp)
    );

    const matchingWindows: WindowRange[] = [];

    // Examine a ten-minute window starting at each alert.
    for (let startIndex = 0; startIndex < group.length; startIndex++) {
      const startTime = Date.parse(group[startIndex].timestamp);

      if (!Number.isFinite(startTime)) {
        continue;
      }

      let endIndex = startIndex;

      while (endIndex < group.length) {
        const eventTime = Date.parse(group[endIndex].timestamp);

        if (
          !Number.isFinite(eventTime) ||
          eventTime > startTime + windowMs
        ) {
          break;
        }

        endIndex++;
      }

      // The window qualifies when it contains enough failures.
      if (endIndex - startIndex < threshold) {
        continue;
      }

      const candidate: WindowRange = {
        startIndex,
        endIndex: endIndex - 1,
      };

      // Merge overlapping qualifying windows into one incident.
      const previous =
        matchingWindows[matchingWindows.length - 1];

      if (previous && candidate.startIndex <= previous.endIndex) {
        previous.endIndex = Math.max(
          previous.endIndex,
          candidate.endIndex
        );
      } else {
        matchingWindows.push(candidate);
      }
    }

    const username = group[0]?.username;
    const sourceIp = group[0]?.sourceIp;

    if (!username || !sourceIp) {
      continue;
    }

    for (const window of matchingWindows) {
      const matchedAlerts = group.slice(
        window.startIndex,
        window.endIndex + 1
      );

      const first = matchedAlerts[0];
      const last = matchedAlerts[matchedAlerts.length - 1];

      if (!first || !last) {
        continue;
      }

      incidents.push({
        ruleId: RULE_ID,
        title: `Repeated failed logins for ${username}`,
        severity: "medium",
        matchedAlertIds: matchedAlerts.map(
          (alert) => alert.sourceAlertId
        ),
        matchedAlertCount: matchedAlerts.length,
        firstSeenAt: first.timestamp,
        lastSeenAt: last.timestamp,
        matchReason:
          `At least ${threshold} failed-login alerts matched ` +
          `within a ${windowMinutes}-minute window for account ` +
          `"${username}" from source IP "${sourceIp}". ` +
          "This pattern requires investigation but does not " +
          "prove that the account was compromised.",
      });
    }
  }

  return incidents.sort(
    (a, b) =>
      Date.parse(a.firstSeenAt) - Date.parse(b.firstSeenAt)
  );
}