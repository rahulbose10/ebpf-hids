import { useState } from "react";
import { api } from "../api";
import StatCard from "../components/StatCard";
import SeverityChip from "../components/SeverityChip";

// The id is what the browser sends to POST /api/sim/<id>. L4's server checks it
// against a hard whitelist and answers 400 for any other name. These ids must
// match that whitelist exactly. The techniques are what each scenario is
// expected to trigger. They are design intent, not a measured result.
const simulations = [
  {
    id: "reverse-shell",
    name: "Reverse shell shape",
    techniques: ["T1059", "T1071"],
    detail: "A loopback connection followed by a spawned shell. No remote host is contacted.",
    severity: "high",
  },
  {
    id: "privilege-escalation",
    name: "Privilege escalation",
    techniques: ["T1055", "T1548"],
    detail: "Simulates process tracing and a privilege transition, confined to the lab.",
    severity: "critical",
  },
  {
    id: "benign-exec-chain",
    name: "Benign exec chain",
    techniques: ["ML-ANOM"],
    detail: "Nested shell activity and a temporary-file write to exercise behavioural monitoring.",
    severity: "medium",
  },
  {
    id: "ransomware",
    name: "Ransomware burst",
    techniques: ["T1486"],
    detail: "A burst of simulated file operations using temporary lab files only.",
    severity: "critical",
  },
  {
    id: "rootkit",
    name: "Rootkit / module load",
    techniques: ["T1547"],
    detail: "Simulates a kernel-threat signal. No real kernel module is installed.",
    severity: "critical",
  },
  {
    id: "persistence",
    name: "Persistence foothold",
    techniques: ["T1547"],
    detail: "Simulates autostart-like activity within an approved temporary lab area.",
    severity: "high",
  },
  {
    id: "credaccess",
    name: "Credential access",
    techniques: ["T1003"],
    detail: "Exercises credential-access signals without collecting real credentials.",
    severity: "high",
  },
  {
    id: "backdoor",
    name: "Backdoor listener",
    techniques: ["T1071", "T1222"],
    detail: "Listener-shaped activity on loopback plus temporary-file operations.",
    severity: "high",
  },
];

export default function AttackRange() {
  const [running, setRunning] = useState("");
  const [results, setResults] = useState({});

  async function launchSimulation(simulation) {
    setRunning(simulation.id);

    try {
      const response = await api.launchSimulation(simulation.id);

      setResults((current) => ({
        ...current,
        [simulation.id]: {
          status: "STARTED",
          message: response?.note ?? response?.message ?? "The server accepted the request.",
        },
      }));
    } catch (err) {
      setResults((current) => ({
        ...current,
        [simulation.id]: {
          status: "FAILED",
          message: err?.error ?? err?.message ?? "The server did not accept this request.",
        },
      }));
    } finally {
      setRunning("");
    }
  }

  const resultList = Object.values(results);
  const startedCount = resultList.filter((item) => item.status === "STARTED").length;
  const failedCount = resultList.filter((item) => item.status === "FAILED").length;

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Validation / lab simulations</div>
        <h1>Attack Range</h1>
        <p>
          Fire benign, lab-local simulations that mimic attacker behaviour, then check Detection and
          Incidents to see whether the sensor saw them.
        </p>
      </div>

      <div className="mb-3 rounded border border-medium/40 bg-medium/10 px-3 py-2 text-[12px] leading-relaxed text-medium">
        <span className="font-semibold">Rules of engagement.</span> Run simulations only in an
        authorized lab. Keep activity benign, on loopback and under /tmp. Do not target external
        systems or real user data.
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Scenarios" value={simulations.length} />
        <StatCard label="Request in flight" value={running ? 1 : 0} tone="signal" />
        <StatCard label="Accepted" value={startedCount} sub="this page load" tone="low" />
        <StatCard label="Rejected" value={failedCount} sub="this page load" tone="critical" />
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {simulations.map((simulation) => {
          const result = results[simulation.id];
          const isRunning = running === simulation.id;

          return (
            <article key={simulation.id} className="panel flex min-w-0 flex-col">
              <div className="panel-body flex flex-1 flex-col">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="text-[13px] font-medium leading-5">{simulation.name}</h3>
                  <SeverityChip severity={simulation.severity} />
                </div>

                <div className="mt-1.5 flex flex-wrap gap-1">
                  {simulation.techniques.map((technique) => (
                    <span
                      key={technique}
                      className="rounded border border-ml/30 px-1.5 py-px font-mono text-[10px] text-ml"
                    >
                      {technique}
                    </span>
                  ))}
                </div>

                <p className="mt-2 flex-1 text-[11px] leading-snug text-mute">{simulation.detail}</p>

                {result?.message && (
                  <p
                    className={`mt-2 break-words text-[11px] leading-snug ${
                      result.status === "FAILED" ? "text-critical" : "text-low"
                    }`}
                  >
                    {result.message}
                  </p>
                )}

                <button
                  type="button"
                  onClick={() => launchSimulation(simulation)}
                  disabled={Boolean(running)}
                  className="mt-3 w-full rounded border border-signal/40 bg-signal/10 px-3 py-1.5 text-[12px] font-medium text-signal transition hover:bg-signal/20 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {isRunning ? "Sending..." : "Run simulation"}
                </button>
              </div>
            </article>
          );
        })}
      </div>

      <p className="mt-3 font-mono text-[10px] leading-relaxed text-mute">
        The browser sends only a scenario id to POST /api/sim/&lt;id&gt;. The server checks it against
        a whitelist, so the UI never names a script path. "Accepted" means the request was accepted,
        not that the threat was detected. Technique tags are the expected result, not a measurement.
      </p>
    </div>
  );
}
