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