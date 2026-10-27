export const healthMock = {
    
  status: "ok",

  sensor_ready: true,

  ml_ready: true,

  ml_has_autoencoder: false,

  ml_alerting: false,

  ml_mode: "Isolation Forest",

  counts: {
    events: 1248,
    processes: 152,
    alerts: 32,
    incidents: 5,
    anomalies: 7,
  },
};
export const eventsMock = {
  events: [
    {
      ts: 1754201700,
      pid: 29812,
      ppid: 1,
      uid: 0,
      comm: "bash",
      type: "Process Created",
      detail: "bash executed",
    },
    {
      ts: 1754201760,
      pid: 2145,
      ppid: 1,
      uid: 0,
      comm: "vim",
      type: "File Modified",
      detail: "/etc/passwd",
    },
    {
      ts: 1754201820,
      pid: 4021,
      ppid: 29812,
      uid: 1000,
      comm: "python3",
      type: "Network Connect",
      detail: "192.168.1.25:443",
    },
  ],
};
export const alertsMock = {
  alerts: [
    {
      ts: 1754201700,
      rule: "connect_after_exec",
      technique: "T1071",
      severity: "medium",
      confidence: 0.75,
      pid: 29812,
      comm: "bash",
      summary: "Outbound connection shortly after exec",
      detail: {
        event: "CONNECT",
        tactic: "Command and Control",
        technique: "Application Layer Protocol",
      },
      incident_id: 1,
    },
    {
      ts: 1754201760,
      rule: "file_modified",
      technique: "T1565",
      severity: "high",
      confidence: 0.92,
      pid: 2145,
      comm: "vim",
      summary: "Sensitive file modified",
      detail: {
        event: "OPEN",
        tactic: "Impact",
        technique: "Data Manipulation",
      },
      incident_id: 2,
    },
    {
      ts: 1754201820,
      rule: "reverse_shell",
      technique: "T1059",
      severity: "critical",
      confidence: 0.98,
      pid: 4021,
      comm: "python3",
      summary: "Reverse shell detected",
      detail: {
        event: "CONNECT",
        tactic: "Execution",
        technique: "Command and Scripting Interpreter",
      },
      incident_id: 3,
    },
  ],
};
export const anomalyMock = {
  score: 0.72,

  threshold: 0.85,

  status: "normal",

  model: "Isolation Forest",

  ml_ready: true,

  ml_alerting: false,
};
export const processesMock = {
  processes: [
    {
      pid: 29812,
      name: "bash",
      user: "root",
      cpu: 2.1,
      memory: 18.5,
    },
    {
      pid: 2145,
      name: "vim",
      user: "root",
      cpu: 0.4,
      memory: 6.2,
    },
    {
      pid: 4021,
      name: "python3",
      user: "ubuntu",
      cpu: 8.7,
      memory: 45.3,
    },
  ],
};
export const incidentsMock = {
  incidents: [
    {
      id: 1,
      title: "Suspicious activity in bash tree",
      root_pid: 29812,
      root_comm: "bash",
      severity: "medium",
      status: "open",
      first_seen: 1754201700,
      last_seen: 1754201700,
      alert_count: 1,
      alerts: [
        alertsMock.alerts[0],
      ],
    },

    {
      id: 2,
      title: "Suspicious activity in vim tree",
      root_pid: 2145,
      root_comm: "vim",
      severity: "high",
      status: "open",
      first_seen: 1754201760,
      last_seen: 1754201760,
      alert_count: 1,
      alerts: [
        alertsMock.alerts[1],
      ],
    },

    {
      id: 3,
      title: "Suspicious activity in python3 tree",
      root_pid: 4021,
      root_comm: "python3",
      severity: "critical",
      status: "open",
      first_seen: 1754201820,
      last_seen: 1754201820,
      alert_count: 1,
      alerts: [
        alertsMock.alerts[2],
      ],
    },
  ],
};

export const threatIntelMock = {
  iocs: [
    {
      id: 1,
      indicator: "192.168.1.25",
      type: "IP",
      category: "Command and Control",
      source: "SOC Analyst",
      severity: "high",
    },
    {
      id: 2,
      indicator: "evil.example",
      type: "DOMAIN",
      category: "Command and Control",
      source: "Threat Feed",
      severity: "critical",
    },
    {
      id: 3,
      indicator: "/tmp/dropper",
      type: "FILE",
      category: "Malware",
      source: "Local Analysis",
      severity: "medium",
    },
  ],
};