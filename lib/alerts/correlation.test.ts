import { describe, expect, it } from "vitest";

import { sampleWazuhAlerts } from "./sample-wazuh-alerts";
import { normalizeWazuhAlert } from "./normalizer";
import { correlateRepeatedFailedLogins } from "./correlation";

const normalizedSamples = sampleWazuhAlerts.map((alert) =>
  normalizeWazuhAlert(alert, "sample")
);

describe("Repeated failed login correlation rule", () => {
  it("creates one incident for five matching failures", () => {
    const results = correlateRepeatedFailedLogins(
      normalizedSamples
    );

    expect(results).toHaveLength(1);
    expect(results[0].ruleId).toBe(
      "repeated_failed_logins_v1"
    );
    expect(results[0].matchedAlertCount).toBe(5);

    expect(results[0].matchedAlertIds).toEqual(
      sampleWazuhAlerts.slice(0, 5).map((alert) => alert.id)
    );

    expect(results[0].title).toContain("alice");
    expect(results[0].matchReason).toContain(
      "does not prove"
    );
  });

  it("does not create an incident for only four failures", () => {
    const firstFour = normalizedSamples.slice(0, 4);

    const results =
      correlateRepeatedFailedLogins(firstFour);

    expect(results).toHaveLength(0);
  });

  it("does not count a successful login as a failed login", () => {
    const alerts = [
      ...normalizedSamples.slice(0, 4),
      normalizedSamples[5],
    ];

    const results =
      correlateRepeatedFailedLogins(alerts);

    expect(results).toHaveLength(0);
  });

  it("does not combine different accounts or IPs", () => {
    const unrelatedAlerts = normalizedSamples.slice(6, 8);

    const results =
      correlateRepeatedFailedLogins(unrelatedAlerts);

    expect(results).toHaveLength(0);
  });

  it("does not match five failures spread beyond ten minutes", () => {
    const startTime = Date.parse(
      "2026-10-11T10:00:00.000Z"
    );

    const spreadOutAlerts = sampleWazuhAlerts
      .slice(0, 5)
      .map((alert, index) => ({
        ...alert,
        timestamp: new Date(
          startTime + index * 3 * 60 * 1000
        ).toISOString(),
      }))
      .map((alert) =>
        normalizeWazuhAlert(alert, "sample")
      );

    const results =
      correlateRepeatedFailedLogins(spreadOutAlerts);

    expect(results).toHaveLength(0);
  });
});