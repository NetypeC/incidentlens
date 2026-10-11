export type WazuhAlert = {
  id: string;
  timestamp: string;

  rule: {
    id: string;
    level: number;
    description: string;
    groups?: string[];
  };

  agent: {
    id: string;
    name: string;
    ip?: string;
  };

  manager?: {
    name: string;
  };

  location?: string;
  full_log?: string;

  data?: Record<string, unknown>;
  syscheck?: Record<string, unknown>;
};


export type AlertSource = "sample" | "wazuh";

export type NormalizedSecurityAlert = {
  source: AlertSource;
  sourceAlertId: string;
  timestamp: string;

  agentId: string | null;
  agentName: string | null;

  ruleId: string;
  ruleLevel: number;
  ruleDescription: string;

  eventType: string | null;
  sourceIp: string | null;
  username: string | null;

  rawAlert: WazuhAlert;
};