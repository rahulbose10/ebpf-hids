import { useEffect, useMemo, useState } from "react";

// Same-origin path. Vite proxies /api to the backend in dev, so no host or
// port is hardcoded and the page also works when served from another machine.
const API_BASE = "/api";

const FALLBACK_RULES = [
  {
    id: "network_parent_shell",
    technique: "T1059",
    severity: "high",
    enabled: true,
    description: "A network-facing parent process launched a shell.",
    hits: 0,
  },
  {
    id: "ptrace_then_exec",
    technique: "T1055",
    severity: "critical",
    enabled: true,
    description: "A process used ptrace activity followed by execution.",
    hits: 0,
  },
  {
    id: "suid_shell",
    technique: "T1548",
    severity: "high",
    enabled: true,
    description: "A process requested uid 0 and then launched a shell.",
    hits: 0,
  },
  {
    id: "connect_after_exec",
    technique: "T1071",
    severity: "medium",
    enabled: true,
    description: "Beaconing — outbound connect shortly after exec.",
    hits: 0,
  },
  {
    id: "ransomware_burst",
    technique: "T1486",
    severity: "critical",
    enabled: true,
    description: "Rapid file destruction, possible ransomware activity.",
    hits: 0,
  },
  {
    id: "log_tampering",
    technique: "T1070",
    severity: "high",
    enabled: true,
    description: "Activity consistent with indicator removal or log tampering.",
    hits: 0,
  },
  {
    id: "persistence_autostart",
    technique: "T1547",
    severity: "high",
    enabled: true,
    description: "Write to an autostart or persistence location.",
    hits: 0,
  },
  {
    id: "credential_access",
    technique: "T1003",
    severity: "high",
    enabled: true,
    description: "Access to a credential store.",
    hits: 0,
  },
  {
    id: "suid_backdoor",
    technique: "T1548",
    severity: "high",
    enabled: true,
    description: "setuid bit set on a file, possible privilege backdoor.",
    hits: 0,
  },
  {
    id: "world_writable_sensitive",
    technique: "T1222",
    severity: "medium",
    enabled: true,
    description: "A sensitive file was made world-writable.",
    hits: 0,
  },
  {
    id: "code_injection_rwx",
    technique: "T1055",
    severity: "high",
    enabled: true,
    description: "Memory was remapped as executable, possible W^X violation.",
    hits: 0,
  },
  {
    id: "kernel_module_load",
    technique: "T1547",
    severity: "critical",
    enabled: true,
    description: "A kernel module was loaded.",
    hits: 0,
  },
  {
    id: "backdoor_listener",
    technique: "T1071",
    severity: "high",
    enabled: true,
    description: "A suspicious listener was detected.",
    hits: 0,
  },
  {
    id: "download_and_execute",
    technique: "T1059",
    severity: "high",
    enabled: true,
    description: "A downloaded payload was followed by execution.",
    hits: 0,
  },
];

const tacticMap = {
  T1059: "COMMAND AND CONTROL",
  T1055: "PROCESS INJECTION",
  T1548: "PRIVILEGE ESCALATION",
  T1071: "COMMAND AND CONTROL",
  T1486: "IMPACT",
  T1070: "IMPACT",
  T1547: "PERSISTENCE",
  T1003: "CREDENTIAL ACCESS",
  T1222: "FILE AND DIRECTORY PERMISSIONS",
};

const severityClass = {
  critical: "rule-severity-critical",
  high: "rule-severity-high",
  medium: "rule-severity-medium",
  low: "rule-severity-low",
};

function getTactic(technique) {
  return tacticMap[technique] || "DETECTION RULES";
}

function getEventType(rule) {
  const id = String(rule.id || "").toLowerCase();
  const description = String(rule.description || "").toLowerCase();

  if (
    id.includes("connect") ||
    id.includes("listener") ||
    description.includes("network") ||
    description.includes("connect")
  ) {
    return "CONNECT";
  }

  if (
    id.includes("ptrace") ||
    description.includes("ptrace") ||
    description.includes("process injection")
  ) {
    return "PTRACE";
  }

  if (
    id.includes("suid") ||
    id.includes("chmod") ||
    description.includes("permission")
  ) {
    return "CHMOD";
  }

  if (
    id.includes("module") ||
    description.includes("kernel module")
  ) {
    return "MODULE";
  }

  if (
    id.includes("exec") ||
    id.includes("shell") ||
    description.includes("shell")
  ) {
    return "EXEC";
  }

  if (
    id.includes("write") ||
    id.includes("ransomware") ||
    description.includes("file")
  ) {
    return "OPEN";
  }

  return "EVENT";
}

function getRuleTitle(rule) {
  const id = String(rule.id || "");

  const titles = {
    network_parent_shell: "Network parent shell",
    ptrace_then_exec: "ptrace followed by exec",
    suid_shell: "setuid(0) immediately followed by a shell",
    connect_after_exec: "Beaconing — outbound connect shortly after exec",
    ransomware_burst: "Rapid file destruction (possible ransomware)",
    log_tampering: "Log tampering activity",
    persistence_autostart: "Write to an autostart / persistence location",
    credential_access: "Access to a credential store",
    suid_backdoor: "setuid bit set on a file (privilege backdoor)",
    world_writable_sensitive: "File made world-writable",
    code_injection_rwx: "Memory remapped executable (W^X violation)",
    kernel_module_load: "Kernel module loaded",
    backdoor_listener: "Suspicious listener (possible bind shell / backdoor)",
    download_and_execute: "Download followed by execution",
  };

  return titles[id] || id.replaceAll("_", " ");
}

function getRuleDescription(rule) {
  if (rule.description) {
    return rule.description;
  }

  const descriptions = {
    suid_shell:
      "A process requested uid 0 and then launched a shell, indicating a possible privilege escalation path.",
    suid_backdoor:
      "A chmod operation created a setuid executable that may provide a privilege backdoor.",
    world_writable_sensitive:
      "A sensitive file was changed to mode 0777, making it writable by every local user.",
    code_injection_rwx:
      "Executable writable memory can indicate an injected payload being changed into runnable code.",
    connect_after_exec:
      "A shell or recently executed process connected to a network destination shortly after starting.",
    backdoor_listener:
      "A shell or freshly executed process opened a local listener that may represent a bind shell.",
    ransomware_burst:
      "A single process rapidly destroyed or renamed many files, matching a possible ransomware pattern.",
    persistence_autostart:
      "A file was opened for writing under a common startup or persistence location.",
    kernel_module_load:
      "A process loaded a kernel module. Outside normal boot activity this can be a high-signal event.",
    credential_access:
      "A process accessed a location commonly associated with stored credentials.",
  };

  return descriptions[rule.id] || "Detection rule configured by the HIDS rule engine.";
}

function getRuleCondition(rule) {
  const id = String(rule.id || "");
  const eventType = getEventType(rule);

  const conditions = {
    network_parent_shell: [
      "proc.is_shell eq true",
      "parent.connect_count ge 1",
    ],
    ptrace_then_exec: [
      "since.ptrace le 3",
      "proc.is_shell eq true",
    ],
    suid_shell: [
      "proc.setuid_to_root eq true",
      "since.setuid le 3",
      "proc.is_shell eq true",
    ],
    connect_after_exec: [
      "since.exec le 3",
      "proc.is_shell eq true",
      "parent.connect_count ge 1",
    ],
    ransomware_burst: [
      "proc.destruction_burst ge 15",
    ],
    persistence_autostart: [
      'event.detail matches "/etc/cron/*"',
      'event.detail matches "/etc/systemd/*"',
      'event.detail endswith ".bashrc"',
      'event.detail endswith ".profile"',
      'event.detail endswith "/authorized_keys"',
    ],
    kernel_module_load: [
      "fires on the event type alone",
    ],
    backdoor_listener: [
      "proc.is_shell eq true",
      "since.exec le 5",
    ],
    world_writable_sensitive: [
      'event.detail contains "mode=0777"',
    ],
    code_injection_rwx: [
      'event.detail contains "exec=1"',
    ],
    suid_backdoor: [
      "proc.setuid_bit_set eq true",
    ],
  };

  return conditions[id] || [`event.type eq ${eventType}`];
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
          disabled={busy}
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
            {conditions.map((condition, index) => (
              <code key={`${rule.id}-${index}`}>
                {condition}
              </code>
            ))}
          </div>
        </div>
      </div>

      <div className="rule-card-footer">
        <span>
          {rule.enabled ? "ACTIVE" : "DISABLED"}
        </span>

        <span>
          HITS <strong>{rule.hits ?? 0}</strong>
        </span>
      </div>
    </article>
  );
}

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [demo, setDemo] = useState(false);
  const [actionError, setActionError] = useState("");

  async function loadRules() {
    try {
      const response = await fetch(`${API_BASE}/rules`);

      if (!response.ok) {
        throw new Error(`Rules request failed: ${response.status}`);
      }

      const data = await response.json();

      setRules(Array.isArray(data.rules) ? data.rules : []);
      setErrors(Array.isArray(data.errors) ? data.errors : []);
      setDemo(false);
    } catch (error) {
      // The backend could not give us rules. Show the built-in sample list,
      // but say so on the page, so nobody reads it as the live rule set.
      setRules(FALLBACK_RULES);
      setErrors([]);
      setDemo(true);
    } finally {
      setLoading(false);
    }
  }

  async function handleToggle(rule) {
    setBusyId(rule.id);
    setActionError("");

    try {
      const response = await fetch(
        `${API_BASE}/rules/${encodeURIComponent(rule.id)}/toggle`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error(`Toggle failed: ${response.status}`);
      }

      await loadRules();
    } catch (error) {
      // Do not swap the list for sample data here. Report the failure instead.
      setActionError(`Could not toggle ${rule.id}: ${error.message}`);
    } finally {
      setBusyId(null);
    }
  }

  useEffect(() => {
    loadRules();

    const timer = setInterval(loadRules, 5000);

    return () => clearInterval(timer);
  }, []);

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

  const groupOrder = [
    "PRIVILEGE ESCALATION",
    "COMMAND AND CONTROL",
    "PROCESS INJECTION",
    "IMPACT",
    "PERSISTENCE",
    "CREDENTIAL ACCESS",
    "FILE AND DIRECTORY PERMISSIONS",
    "DETECTION RULES",
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

        .rule-condition-list code {
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
              {rules.filter((rule) => rule.enabled).length}
            </strong>
          </span>

          <span>
            HITS{" "}
            <strong>
              {rules.reduce(
                (total, rule) => total + Number(rule.hits || 0),
                0
              )}
            </strong>
          </span>
        </div>
      </header>

      {demo && (
        <div className="rule-demo">
          Demo data. The backend did not return a rule set from /api/rules, so
          this is the built-in sample list. Toggles will not work.
        </div>
      )}

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