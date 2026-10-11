import type { WazuhAlert } from "./types";

export const sampleWazuhAlerts: WazuhAlert[] = [
  {
    id: "sample-alert-001",
    timestamp: "2026-10-11T10:00:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 203.0.113.25 port 50100 ssh2",
  },
  {
    id: "sample-alert-002",
    timestamp: "2026-10-11T10:01:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 203.0.113.25 port 50101 ssh2",
  },
  {
    id: "sample-alert-003",
    timestamp: "2026-10-11T10:02:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 203.0.113.25 port 50102 ssh2",
  },
  {
    id: "sample-alert-004",
    timestamp: "2026-10-11T10:03:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 203.0.113.25 port 50103 ssh2",
  },
  {
    id: "sample-alert-005",
    timestamp: "2026-10-11T10:04:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 203.0.113.25 port 50104 ssh2",
  },
  {
    id: "sample-alert-006",
    timestamp: "2026-10-11T10:05:00.000+00:00",
    rule: {
      id: "100102",
      level: 3,
      description: "Synthetic test: successful SSH login",
      groups: ["authentication_success", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "203.0.113.25",
      dstuser: "alice",
      status: "success",
    },
    full_log:
      "Accepted password for alice from 203.0.113.25 port 50105 ssh2",
  },
  {
    id: "sample-alert-007",
    timestamp: "2026-10-11T11:00:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "198.51.100.77",
      dstuser: "bob",
      status: "failure",
    },
    full_log:
      "Failed password for bob from 198.51.100.77 port 50200 ssh2",
  },
  {
    id: "sample-alert-008",
    timestamp: "2026-10-11T11:20:00.000+00:00",
    rule: {
      id: "100101",
      level: 5,
      description: "Synthetic test: failed SSH login attempt",
      groups: ["authentication_failed", "sshd"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "/var/log/auth.log",
    data: {
      srcip: "198.51.100.77",
      dstuser: "alice",
      status: "failure",
    },
    full_log:
      "Failed password for alice from 198.51.100.77 port 50201 ssh2",
  },
  {
    id: "sample-alert-009",
    timestamp: "2026-10-11T11:30:00.000+00:00",
    rule: {
      id: "100550",
      level: 7,
      description: "Synthetic test: file integrity changed",
      groups: ["syscheck", "syscheck_entry_modified"],
    },
    agent: {
      id: "001",
      name: "lab-linux-01",
      ip: "192.0.2.10",
    },
    manager: {
      name: "lab-manager",
    },
    location: "syscheck",
    syscheck: {
      path: "/etc/ssh/sshd_config",
      event: "modified",
    },
    full_log:
      "Synthetic test: monitored file /etc/ssh/sshd_config changed",
  },
];