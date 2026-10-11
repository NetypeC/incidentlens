import { describe, expect, it } from "vitest";

import { sampleWazuhAlerts } from "./sample-wazuh-alerts";
import { normalizeWazuhAlert } from "./normalizer";
import {
    correlateRepeatedFailedLogins,
    correlateFailedThenSuccessfulLogin,
} from "./correlation"

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

describe("Failed login followed by successful login", () => {
  it("groups matching failed logins and a later success", () => {
    const results = correlateFailedThenSuccessfulLogin(
      normalizedSamples
    );

    expect(results).toHaveLength(1);
    expect(results[0].ruleId).toBe(
      "failed_then_successful_login_v1"
    );
    expect(results[0].matchedAlertCount).toBe(6);

    expect(results[0].matchedAlertIds).toEqual(
      sampleWazuhAlerts
        .slice(0, 6)
        .map((alert) => alert.id)
    );

    expect(results[0].matchReason).toContain(
      "does not prove"
    );
  });

  it("does not match when the successful login is too late", () => {
    const lateSuccess = normalizeWazuhAlert(
      {
        ...sampleWazuhAlerts[5],
        timestamp: "2026-10-11T10:20:00.000Z",
      },
      "sample"
    );

    const alerts = [
      ...normalizedSamples.slice(0, 5),
      lateSuccess,
    ];

    expect(
      correlateFailedThenSuccessfulLogin(alerts)
    ).toHaveLength(0);
  });

  it("does not match when known IP addresses differ", () => {
    const differentIpSuccess = normalizeWazuhAlert(
      {
        ...sampleWazuhAlerts[5],
        data: {
          ...sampleWazuhAlerts[5].data,
          srcip: "198.51.100.100",
        },
      },
      "sample"
    );

    const alerts = [
      ...normalizedSamples.slice(0, 5),
      differentIpSuccess,
    ];

    expect(
      correlateFailedThenSuccessfulLogin(alerts)
    ).toHaveLength(0);
  });

  it("does not match when success happens before the failure", () => {
    const earlierSuccess = normalizeWazuhAlert(
      {
        ...sampleWazuhAlerts[5],
        timestamp: "2026-10-11T09:59:00.000Z",
      },
      "sample"
    );

    const alerts = [
      earlierSuccess,
      ...normalizedSamples.slice(0, 5),
    ];

    expect(
      correlateFailedThenSuccessfulLogin(alerts)
    ).toHaveLength(0);
  });

  it("does not match if the account names differ", () => {
    const differentAccountSuccess = normalizeWazuhAlert(
      {
        ...sampleWazuhAlerts[5],
        data: {
          ...sampleWazuhAlerts[5].data,
          dstuser: "bob",
        },
      },
      "sample"
    );

    const alerts = [
      ...normalizedSamples.slice(0, 5),
      differentAccountSuccess,
    ];

    expect(
      correlateFailedThenSuccessfulLogin(alerts)
    ).toHaveLength(0);
  });
});