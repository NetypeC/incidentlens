import type {
  AlertSource,
  NormalizedSecurityAlert,
  WazuhAlert,
} from "./types";

function getString(
  record: Record<string, unknown> | undefined,
  keys: string[]
): string | null {
  for (const key of keys) {
    const value = record?.[key];

    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }

  return null;
}

export function normalizeWazuhAlert(
  alert: WazuhAlert,
  source: AlertSource
): NormalizedSecurityAlert {
  const groups = alert.rule.groups ?? [];

  let eventType: string | null = null;

  if (groups.includes("authentication_failed")) {
    eventType = "authentication_failed";
  } else if (groups.includes("authentication_success")) {
    eventType = "authentication_success";
  } else if (groups.includes("syscheck")) {
    eventType = "file_integrity_change";
  } else if (groups.length > 0) {
    eventType = groups[0];
  }

  return {
    source,
    sourceAlertId: alert.id,
    timestamp: alert.timestamp,

    agentId: alert.agent.id || null,
    agentName: alert.agent.name || null,

    ruleId: alert.rule.id,
    ruleLevel: alert.rule.level,
    ruleDescription: alert.rule.description,

    eventType,

    sourceIp: getString(alert.data, [
      "srcip",
      "src_ip",
      "source_ip",
    ]),

    username: getString(alert.data, [
      "dstuser",
      "username",
      "user",
      "srcuser",
    ]),

    rawAlert: alert,
  };
}