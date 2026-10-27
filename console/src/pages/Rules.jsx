import { useMemo, useState } from "react";
import { usePoll } from "../api";

// Same-origin path. Vite proxies /api to the backend in dev, so no host or
// port is hardcoded and the page also works when served from another machine.
const API_BASE = "/api";

// A copy of L2's rule files (server/rules/*.yml on main at 1f3506c), generated
// by reading the YAML, not typed by hand. It does two jobs: it supplies the
// "on" and "where" lines on each card, because the /api/rules contract has no
// condition field, and it is the fallback list when /api/rules does not answer.
// If L2 changes a rule file, regenerate this copy, or the card shows an old
// condition.
const RULES_SOURCE = "server/rules/*.yml @ main 1f3506c";

const RULE_SNAPSHOT = [
  {
    "id": "connect_after_exec",
    "technique": "T1071",
    "severity": "medium",
    "description": "Outbound connection within 3 s of the program starting (possible C2 callback)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "CONNECT"
      },
      {
        "field": "evt.detail",
        "op": "not_matches",
        "value": ":53$"
      },
      {
        "field": "since.exec",
        "op": "lte",
        "value": 3.0
      },
      {
        "field": "proc.exe",
        "op": "not_matches",
        "value": "^(/usr)?/s?bin/(curl|wget|ping|ping6|git|ssh|scp|sftp|rsync|apt|apt-get|snap|dig|host|nslookup)$|^/usr/lib/(apt/methods|git-core)/|^/snap/|^/usr/lib/snapd/|^/usr/lib/(thunderbird|firefox)/"
      }
    ]
  },
  {
    "id": "network_parent_shell",
    "technique": "T1059",
    "severity": "high",
    "description": "A process that made a network connection started a shell (possible reverse shell)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "EXEC"
      },
      {
        "field": "proc.exe_name",
        "op": "in_set",
        "value": [
          "sh",
          "bash",
          "dash",
          "zsh",
          "ksh",
          "fish",
          "busybox"
        ]
      },
      {
        "field": "parent.net_connect_count",
        "op": "gte",
        "value": 1
      }
    ]
  },
  {
    "id": "ptrace_then_exec",
    "technique": "T1055",
    "severity": "critical",
    "description": "ptrace attach followed by an exec within 3 s (possible process injection)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "EXEC"
      },
      {
        "field": "proc.ptrace_count",
        "op": "gte",
        "value": 1
      },
      {
        "field": "since.ptrace",
        "op": "lte",
        "value": 3.0
      }
    ]
  },
  {
    "id": "suid_shell",
    "technique": "T1548",
    "severity": "high",
    "description": "Process went from a normal uid to root and started a shell within 3 s (possible privilege escalation)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "EXEC"
      },
      {
        "field": "proc.root_gain_count",
        "op": "gte",
        "value": 1
      },
      {
        "field": "since.setuid",
        "op": "lte",
        "value": 3.0
      },
      {
        "field": "proc.exe_name",
        "op": "in_set",
        "value": [
          "sh",
          "bash",
          "dash",
          "zsh",
          "ksh",
          "fish",
          "busybox"
        ]
      }
    ]
  },
  {
    "id": "ransomware_burst",
    "technique": "T1486",
    "severity": "critical",
    "description": "25 or more deletes/renames inside 5 s outside package and app cache folders (possible ransomware)",
    "where": [
      {
        "field": "evt.type",
        "op": "in_set",
        "value": [
          "UNLINK",
          "RENAME"
        ]
      },
      {
        "field": "proc.destruction_burst",
        "op": "gte",
        "value": 25
      }
    ]
  },
  {
    "id": "log_tampering",
    "technique": "T1070",
    "severity": "high",
    "description": "Write or delete under /var/log by something that is not a log daemon or package tool",
    "where": [
      {
        "field": "evt.type",
        "op": "in_set",
        "value": [
          "OPEN",
          "UNLINK"
        ]
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": "^/var/log/"
      },
      {
        "field": "proc.exe_name",
        "op": "not_in_set",
        "value": [
          "rsyslogd",
          "rs:main Q:Reg",
          "in:imuxsock",
          "in:imklog",
          "in:imjournal",
          "systemd-journald",
          "systemd-journal",
          "logrotate",
          "apt",
          "apt-get",
          "dpkg",
          "unattended-upgrade",
          "unattended-upgr",
          "update-alternatives",
          "update-alternat",
          "Xorg",
          "cupsd"
        ]
      }
    ]
  },
  {
    "id": "persistence_autostart",
    "technique": "T1547",
    "severity": "high",
    "description": "Write to a cron, systemd unit, rc.local, init.d or XDG autostart location",
    "where": [
      {
        "field": "evt.type",
        "op": "in_set",
        "value": [
          "OPEN",
          "RENAME"
        ]
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": "(^|-> )(/etc/(cron\\.(d|daily|hourly|weekly|monthly)/|crontab$|anacrontab$|rc\\.local$|init\\.d/|systemd/(system|user)/|xdg/autostart/)|/var/spool/cron/|/(usr/)?lib/systemd/(system|user)/|/(root|home/[^/]+)/\\.config/(systemd/user|autostart)/)"
      },
      {
        "field": "proc.exe_name",
        "op": "not_in_set",
        "value": [
          "dpkg",
          "apt",
          "apt-get",
          "unattended-upgrade",
          "unattended-upgr",
          "systemd"
        ]
      }
    ]
  },
  {
    "id": "credential_access",
    "technique": "T1003",
    "severity": "high",
    "description": "Write-intent open of /etc/shadow, /etc/gshadow or an SSH private key (reads are not visible to the sensor)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "OPEN"
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": "^(/etc/(shadow|gshadow)|/(root|home/[^/]+)/\\.ssh/id_[^/.]+)$"
      },
      {
        "field": "proc.exe_name",
        "op": "not_in_set",
        "value": [
          "passwd",
          "chpasswd",
          "usermod",
          "useradd",
          "userdel",
          "chage",
          "vipw",
          "ssh-keygen"
        ]
      }
    ]
  },
  {
    "id": "suid_backdoor",
    "technique": "T1548",
    "severity": "high",
    "description": "chmod set the setuid or setgid bit",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "CHMOD"
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": " mode=[2-7][0-7]{3}$"
      },
      {
        "field": "proc.exe_name",
        "op": "not_in_set",
        "value": [
          "dpkg",
          "apt",
          "apt-get",
          "unattended-upgrade",
          "unattended-upgr"
        ]
      }
    ]
  },
  {
    "id": "world_writable_sensitive",
    "technique": "T1222",
    "severity": "medium",
    "description": "chmod made a file under /etc writable by everyone",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "CHMOD"
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": "^/etc/\\S+ mode=[0-7]{3}[2367]$"
      }
    ]
  },
  {
    "id": "code_injection_rwx",
    "technique": "T1055",
    "severity": "high",
    "description": "mprotect asked for memory that is writable and executable at once (possible shellcode)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "MPROTECT"
      },
      {
        "field": "evt.detail",
        "op": "matches",
        "value": "prot=[r-]wx"
      }
    ]
  },
  {
    "id": "kernel_module_load",
    "technique": "T1547",
    "severity": "critical",
    "description": "A kernel module was loaded (code now runs with more power than root)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "MODULE"
      }
    ]
  },
  {
    "id": "backdoor_listener",
    "technique": "T1071",
    "severity": "high",
    "description": "A shell, netcat, socat or script interpreter opened a listening socket (possible bind shell)",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "BIND"
      },
      {
        "field": "proc.exe_name",
        "op": "matches",
        "value": "^(sh|bash|dash|zsh|ksh|busybox|nc|ncat|netcat|nc\\.openbsd|nc\\.traditional|socat|python[0-9.]*|perl|ruby|php[0-9.]*)$"
      }
    ]
  },
  {
    "id": "download_and_execute",
    "technique": "T1059",
    "severity": "high",
    "description": "Executed a file that a network-connected process wrote in the last 5 minutes",
    "where": [
      {
        "field": "evt.type",
        "op": "eq",
        "value": "EXEC"
      },
      {
        "field": "file.fetched_age",
        "op": "lte",
        "value": 300
      }
    ]
  }
];

const SNAPSHOT_BY_ID = Object.fromEntries(RULE_SNAPSHOT.map((rule) => [rule.id, rule]));

// The primary ATT&CK tactic of each technique the rules use. A technique name
// such as "Process Injection" is not a tactic, so it is not used as a heading.
const tacticMap = {
  T1059: "EXECUTION",
  T1055: "DEFENSE EVASION",
  T1548: "PRIVILEGE ESCALATION",
  T1071: "COMMAND AND CONTROL",
  T1486: "IMPACT",
  T1070: "DEFENSE EVASION",
  T1547: "PERSISTENCE",
  T1003: "CREDENTIAL ACCESS",
  T1222: "DEFENSE EVASION",
};

const severityClass = {
  critical: "rule-severity-critical",
  high: "rule-severity-high",
  medium: "rule-severity-medium",
  low: "rule-severity-low",
};

function getTactic(technique) {
  return tacticMap[technique] || "OTHER";
}

// Use a where list from the API if L4 ever sends one, else the YAML copy.
function getWhere(rule) {
  if (Array.isArray(rule.where)) return rule.where;
  return SNAPSHOT_BY_ID[rule.id]?.where ?? null;
}

function formatValue(value) {
  if (Array.isArray(value)) return `[${value.join(", ")}]`;
  return String(value);
}

// The event type comes from the rule's own evt.type clause.
function getEventType(rule) {
  const clause = getWhere(rule)?.find((c) => c.field === "evt.type");
  if (!clause) return "?";
  return Array.isArray(clause.value) ? clause.value.join(" | ") : String(clause.value);
}

// Every clause except evt.type, written as "field op value", as in the YAML.
function getRuleCondition(rule) {
  const where = getWhere(rule);
  if (!where) return null;

  const rest = where.filter((c) => c.field !== "evt.type");
  if (rest.length === 0) return ["fires on the event type alone"];

  return rest.map((c) => `${c.field} ${c.op} ${formatValue(c.value)}`);
}

function getRuleTitle(rule) {
  const titles = {
    connect_after_exec: "Outbound connect within 3 s of exec",
    network_parent_shell: "Shell started by a network-connected parent",
    ptrace_then_exec: "ptrace followed by exec",
    suid_shell: "Gained root, then started a shell",
    ransomware_burst: "Burst of deletes and renames",
    log_tampering: "Write or delete under /var/log",
    persistence_autostart: "Write to an autostart location",
    credential_access: "Write-intent open of a credential file",
    suid_backdoor: "setuid or setgid bit set by chmod",
    world_writable_sensitive: "File under /etc made world-writable",
    code_injection_rwx: "Writable and executable memory",
    kernel_module_load: "Kernel module loaded",
    backdoor_listener: "Shell or interpreter opened a listener",
    download_and_execute: "Ran a recently downloaded file",
  };

  return titles[rule.id] || String(rule.id || "").replaceAll("_", " ");
}

function getRuleDescription(rule) {
  return (
    rule.description ||
    SNAPSHOT_BY_ID[rule.id]?.description ||
    "No description returned by the backend."
  );
}

function RuleCard({ rule, onToggle, busy }) {
  const severity = String(rule.severity || "low").toLowerCase();
  const eventType = getEventType(rule);
  const conditions = getRuleCondition(rule);

  return (
    <article className={`rule-card ${severityClass[severity] || ""}`}>
      <div className="rule-card-top">
        <div className="rule-heading">
          <span className="rule-technique">
            {rule.technique || "UNKNOWN"}
          </span>

          <span className={`rule-severity ${severity}`}>
            {severity}
          </span>
        </div>

        <button
          type="button"
          className={`rule-toggle ${rule.enabled ? "enabled" : ""}`}
          onClick={() => onToggle(rule)}
          disabled={busy || rule.enabled === null}
          aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.id}`}
        >
          <span className="rule-toggle-knob" />
        </button>
      </div>

      <h2>{getRuleTitle(rule)}</h2>

      <p className="rule-description">
        {getRuleDescription(rule)}
      </p>

      <div className="rule-divider" />

      <div className="rule-definition">
        <div className="rule-line">
          <span>id</span>
          <code>{rule.id}</code>
        </div>

        <div className="rule-line">
          <span>on</span>
          <code>{eventType}</code>
        </div>

        <div className="rule-line rule-condition">
          <span>where</span>

          <div className="rule-condition-list">
            {conditions ? (
              conditions.map((condition, index) => (
                <code key={`${rule.id}-${index}`}>
                  {condition}
                </code>
              ))
            ) : (
              <code>not in this console&apos;s copy of the rule files</code>
            )}
          </div>
        </div>
      </div>

      <div className="rule-card-footer">
        <span>
          {rule.enabled === null ? "STATE UNKNOWN" : rule.enabled ? "ACTIVE" : "DISABLED"}
        </span>

        <span>
          HITS <strong>{rule.hits ?? "-"}</strong>
        </span>
      </div>
    </article>
  );
}

async function fetchRules() {
  const response = await fetch(`${API_BASE}/rules`);
  if (!response.ok) {
    throw new Error(`Rules request failed: ${response.status}`);
  }
  return response.json();
}

export default function Rules() {
  const rulesPoll = usePoll(fetchRules, 5000);
  const [busyId, setBusyId] = useState(null);
  const [actionError, setActionError] = useState("");

  const loading = !rulesPoll.data && !rulesPoll.error;
  // When /api/rules fails, show the YAML copy and say so on the page, so
  // nobody reads it as the live rule set.
  const demo = Boolean(rulesPoll.error);

  const rules = useMemo(() => {
    if (demo) return RULE_SNAPSHOT.map((rule) => ({ ...rule, enabled: null, hits: null }));
    return Array.isArray(rulesPoll.data?.rules) ? rulesPoll.data.rules : [];
  }, [demo, rulesPoll.data]);

  const errors = !demo && Array.isArray(rulesPoll.data?.errors) ? rulesPoll.data.errors : [];

  async function handleToggle(rule) {
    setBusyId(rule.id);
    setActionError("");

    try {
      const response = await fetch(`${API_BASE}/rules/${encodeURIComponent(rule.id)}/toggle`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error(`Toggle failed: ${response.status}`);
      }

      await rulesPoll.refresh();
    } catch (error) {
      // Do not swap the list for sample data here. Report the failure instead.
      setActionError(`Could not toggle ${rule.id}: ${error.message}`);
    } finally {
      setBusyId(null);
    }
  }

  const groupedRules = useMemo(() => {
    const groups = {};

    rules.forEach((rule) => {
      const tactic = getTactic(rule.technique);

      if (!groups[tactic]) {
        groups[tactic] = [];
      }

      groups[tactic].push(rule);
    });

    return groups;
  }, [rules]);

  // Roughly the order of the ATT&CK matrix, left to right.
  const groupOrder = [
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE ESCALATION",
    "DEFENSE EVASION",
    "CREDENTIAL ACCESS",
    "COMMAND AND CONTROL",
    "IMPACT",
    "OTHER",
  ];

  const orderedGroups = Object.entries(groupedRules).sort(
    ([nameA], [nameB]) => {
      const indexA = groupOrder.indexOf(nameA);
      const indexB = groupOrder.indexOf(nameB);

      const safeA = indexA === -1 ? 999 : indexA;
      const safeB = indexB === -1 ? 999 : indexB;

      return safeA - safeB;
    }
  );

  return (
    <main className="rules-page">
      <style>{`
        .rule-demo {
          margin-bottom: 14px;
          padding: 8px 12px;
          border: 1px solid rgba(232, 195, 74, 0.35);
          border-radius: 6px;
          background: rgba(232, 195, 74, 0.06);
          color: #e8c34a;
          font-family: "JetBrains Mono", monospace;
          font-size: 11px;
        }

        .rules-source {
          margin: -8px 0 14px;
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 10px;
        }

        .rules-page {
          padding: 4px 0 40px;
          color: var(--text, #e6edf6);
          font-family: Inter, sans-serif;
        }

        .rules-header {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 20px;
          margin-bottom: 16px;
        }

        .rules-eyebrow {
          margin-bottom: 4px;
          color: var(--signal, #4fd1c5);
          font-family: "JetBrains Mono", monospace;
          font-size: 11px;
          letter-spacing: 0.2em;
          text-transform: uppercase;
        }

        .rules-header h1 {
          margin: 0;
          font-family: "Space Grotesk", sans-serif;
          font-size: 22px;
          font-weight: 600;
        }

        .rules-summary {
          display: flex;
          gap: 18px;
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 11px;
        }

        .rules-summary strong {
          color: var(--text, #e6edf6);
        }

        .rule-error {
          margin-bottom: 22px;
          padding: 12px 14px;
          border: 1px solid rgba(255, 93, 93, 0.4);
          border-radius: 8px;
          background: rgba(255, 93, 93, 0.08);
          color: #ff8c8c;
          font-family: "JetBrains Mono", monospace;
          font-size: 12px;
        }

        .rule-group {
          margin-bottom: 20px;
        }

        .rule-group-title {
          margin: 0 0 10px;
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 10px;
          font-weight: 500;
          letter-spacing: 0.2em;
        }

        .rule-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 12px;
        }

        .rule-card {
          position: relative;
          min-height: 0;
          overflow: hidden;
          padding: 15px 14px 12px;
          border: 1px solid var(--line, #243149);
          border-radius: 8px;
          background:
            linear-gradient(
              145deg,
              rgba(22, 34, 58, 0.9),
              rgba(13, 20, 34, 0.92)
            );
          box-shadow:
            0 16px 35px rgba(0, 0, 0, 0.14),
            inset 0 1px 0 rgba(255, 255, 255, 0.025);
          transition:
            transform 160ms ease,
            border-color 160ms ease,
            box-shadow 160ms ease;
        }

        .rule-card:hover {
          transform: translateY(-2px);
          border-color: rgba(79, 209, 197, 0.28);
          box-shadow:
            0 20px 42px rgba(0, 0, 0, 0.2),
            0 0 22px rgba(79, 209, 197, 0.035);
        }

        .rule-card::before {
          content: "";
          position: absolute;
          top: 0;
          left: 0;
          width: 3px;
          height: 100%;
          background: currentColor;
          opacity: 0.8;
        }

        .rule-card-top {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 16px;
        }

        .rule-heading {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .rule-technique {
          color: #7c8cf8;
          font-family: "JetBrains Mono", monospace;
          font-size: 13px;
        }

        .rule-severity {
          padding: 2px 5px;
          border: 1px solid currentColor;
          border-radius: 3px;
          font-family: "JetBrains Mono", monospace;
          font-size: 9px;
          line-height: 1.3;
          text-transform: lowercase;
        }

        .rule-severity.critical {
          color: #ff5d5d;
        }

        .rule-severity.high {
          color: #f2a65a;
        }

        .rule-severity.medium {
          color: #e8c34a;
        }

        .rule-severity.low {
          color: #39c2b0;
        }

        .rule-card h2 {
          margin: 9px 42px 7px 0;
          color: var(--text, #e6edf6);
          font-family: "Space Grotesk", sans-serif;
          font-size: 15px;
          font-weight: 500;
          line-height: 1.35;
        }

        .rule-description {
          min-height: 0;
          margin: 0;
          color: var(--mute, #7e8aa0);
          font-size: 11px;
          line-height: 1.55;
        }

        .rule-divider {
          height: 1px;
          margin: 13px 0 10px;
          background: var(--line, #243149);
        }

        .rule-definition {
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 10px;
          line-height: 1.65;
        }

        .rule-line {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          margin-bottom: 4px;
        }

        .rule-line > span {
          width: 28px;
          flex: 0 0 28px;
        }

        .rule-line code {
          color: #9aa7ba;
          font-family: inherit;
          white-space: pre-wrap;
          word-break: break-word;
        }

        .rule-line code:first-child {
          padding: 2px 6px;
          border: 1px solid rgba(126, 138, 160, 0.22);
          border-radius: 3px;
          background: rgba(126, 138, 160, 0.045);
          color: #aeb9c8;
        }

        .rule-condition {
          align-items: flex-start;
        }

        .rule-condition-list {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }

        /* Every condition gets the same look. The first one is not special. */
        .rule-condition-list code,
        .rule-condition-list code:first-child {
          padding: 0;
          border: 0;
          background: none;
          color: #42c9bd;
        }

        .rule-card-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 12px;
          padding-top: 9px;
          border-top: 1px solid rgba(36, 49, 73, 0.65);
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 9px;
          letter-spacing: 0.08em;
        }

        .rule-card-footer strong {
          color: var(--text, #e6edf6);
          font-weight: 500;
        }

        .rule-toggle {
          position: relative;
          width: 38px;
          height: 21px;
          flex: 0 0 38px;
          padding: 0;
          border: 0;
          border-radius: 999px;
          background: #303b4e;
          cursor: pointer;
          transition: background 160ms ease;
        }

        .rule-toggle.enabled {
          background: #36aaa5;
        }

        .rule-toggle:disabled {
          cursor: wait;
          opacity: 0.6;
        }

        .rule-toggle-knob {
          position: absolute;
          top: 3px;
          left: 3px;
          width: 15px;
          height: 15px;
          border-radius: 50%;
          background: #edf5f7;
          box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25);
          transition: transform 160ms ease;
        }

        .rule-toggle.enabled .rule-toggle-knob {
          transform: translateX(17px);
        }

        .rule-severity-critical {
          color: #ff5d5d;
        }

        .rule-severity-high {
          color: #f2a65a;
        }

        .rule-severity-medium {
          color: #e8c34a;
        }

        .rule-severity-low {
          color: #39c2b0;
        }

        .rules-loading {
          min-height: 260px;
          display: grid;
          place-items: center;
          border: 1px solid var(--line, #243149);
          border-radius: 8px;
          color: var(--mute, #7e8aa0);
          font-family: "JetBrains Mono", monospace;
          font-size: 12px;
        }

        .rules-empty {
          padding: 50px 20px;
          border: 1px solid var(--line, #243149);
          border-radius: 8px;
          color: var(--mute, #7e8aa0);
          text-align: center;
          font-family: "JetBrains Mono", monospace;
          font-size: 12px;
        }

        @media (max-width: 1400px) {
          .rule-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 900px) {
          .rule-grid {
            grid-template-columns: 1fr;
          }

          .rules-header {
            align-items: flex-start;
            flex-direction: column;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .rule-card,
          .rule-toggle,
          .rule-toggle-knob {
            transition: none;
          }

          .rule-card:hover {
            transform: none;
          }
        }
      `}</style>

      <header className="rules-header">
        <div>
          <div className="rules-eyebrow">DETECTION ENGINE</div>
          <h1>Rules</h1>
        </div>

        <div className="rules-summary">
          <span>
            RULES <strong>{rules.length}</strong>
          </span>

          <span>
            ACTIVE{" "}
            <strong>
              {demo ? "-" : rules.filter((rule) => rule.enabled).length}
            </strong>
          </span>

          <span>
            HITS{" "}
            <strong>
              {demo
                ? "-"
                : rules.reduce(
                    (total, rule) => total + Number(rule.hits || 0),
                    0
                  )}
            </strong>
          </span>
        </div>
      </header>

      {demo && (
        <div className="rule-demo">
          /api/rules did not answer, so this list comes from the console&apos;s
          copy of the rule files ({RULES_SOURCE}). On/off state and hit counts
          are unknown, and toggles are disabled.
        </div>
      )}

      <p className="rules-source">
        The on and where lines come from {RULES_SOURCE}, because /api/rules does
        not send conditions.
      </p>

      {actionError && <div className="rule-error">{actionError}</div>}

      {errors.length > 0 && (
        <div className="rule-error">
          {errors.map((error, index) => (
            <div key={`${error}-${index}`}>{error}</div>
          ))}
        </div>
      )}

      {loading ? (
        <div className="rules-loading">
          Loading rule set...
        </div>
      ) : orderedGroups.length === 0 ? (
        <div className="rules-empty">
          No rules returned by /api/rules
        </div>
      ) : (
        orderedGroups.map(([tactic, groupRules]) => (
          <section className="rule-group" key={tactic}>
            <h3 className="rule-group-title">
              {tactic}
            </h3>

            <div className="rule-grid">
              {groupRules.map((rule) => (
                <RuleCard
                  key={rule.id}
                  rule={rule}
                  onToggle={handleToggle}
                  busy={busyId === rule.id}
                />
              ))}
            </div>
          </section>
        ))
      )}
    </main>
  );
}