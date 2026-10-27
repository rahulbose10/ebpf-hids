
import { useState } from "react";
import { api } from "../api";

const simulations = [
  {
    id: "reverse-shell",
    name: "Reverse shell shape",
    techniques: ["T1059", "T1071"],
    detail:
      "A loopback connection followed by a spawned shell. No remote host is contacted.",
    severity: "high",
  },
  {
    id: "privilege-escalation",
    name: "Privilege escalation",
    techniques: ["T1055", "T1548"],
    detail:
      "Simulates process tracing and a privilege transition. The attempt remains confined to the lab.",
    severity: "critical",
  },
  {
    id: "benign-exec-chain",
    name: "Benign exec chain",
    techniques: ["ML-ANOM"],
    detail:
      "Nested shell activity and a temporary-file write to exercise behavioural monitoring.",
    severity: "medium",
  },
  {
    id: "ransomware",
    name: "Ransomware burst",
    techniques: ["T1486"],
    detail:
      "A burst of simulated file operations using temporary lab files only.",
    severity: "critical",
  },
  {
    id: "rootkit",
    name: "Rootkit / module load",
    techniques: ["T1547"],
    detail:
      "Simulates a kernel-threat signal. No real kernel module is installed.",
    severity: "critical",
  },
  {
    id: "persistence",
    name: "Persistence foothold",
    techniques: ["T1547"],
    detail:
      "Simulates autostart-like activity within an approved temporary lab area.",
    severity: "high",
  },
  {
    id: "credaccess",
    name: "Credential access",
    techniques: ["T1003"],
    detail:
      "Exercises credential-access detection signals without collecting real credentials.",
    severity: "high",
  },
  {
    id: "backdoor",
    name: "Backdoor listener",
    techniques: ["T1071", "T1222"],
    detail:
      "Simulates a listener-shaped activity on loopback and temporary-file operations.",
    severity: "high",
  },
];

const severityStyles = {
  critical: "border-red-500/30 bg-red-500/10 text-red-400",
  high: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  medium: "border-blue-400/30 bg-blue-400/10 text-blue-300",
};

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
          message:
            response?.note ??
            response?.message ??
            "The server accepted the simulation request.",
        },
      }));
    } catch (err) {
      setResults((current) => ({
        ...current,
        [simulation.id]: {
          status: "FAILED",
          message:
            err?.error ??
            err?.message ??
            "The server did not accept this simulation request.",
        },
      }));
    } finally {
      setRunning("");
    }
  }

  const resultList = Object.values(results);
  const startedCount = resultList.filter(
    (item) => item.status === "STARTED"
  ).length;
  const failedCount = resultList.filter(
    (item) => item.status === "FAILED"
  ).length;

  return (
    <main className="min-h-full space-y-5 p-4 text-text sm:p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">VALIDATION / LAB SIMULATIONS</p>
          <h1 className="mt-2 font-display text-2xl font-semibold">
            Attack Range
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-mute">
            Fire benign, lab-local simulations that mimic attacker behaviour.
            Check Detection and Incidents to see whether the sensor observes
            their activity.
          </p>
        </div>

        <div className="panel flex items-center gap-3 px-4 py-3">
          <span
            className={`h-2 w-2 rounded-full ${
              running ? "animate-pulse bg-yellow-400" : "bg-signal"
            }`}
          />
          <div>
            <p className="eyebrow">SIMULATION CONTROL</p>
            <p className="mt-1 font-mono text-sm text-signal">
              {running ? "REQUEST IN PROGRESS" : "READY"}
            </p>
          </div>
        </div>
      </header>

      <section className="rounded-lg border border-yellow-400/40 bg-yellow-400/10 p-4">
        <h2 className="font-semibold text-yellow-300">
          Rules of Engagement
        </h2>
        <p className="mt-2 text-sm leading-6 text-mute">
          Run simulations only in an authorized lab. Keep activity benign and
          restricted to loopback networking and approved temporary paths
          under /tmp. Do not target external systems or real user data.
        </p>
      </section>

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="panel p-4">
          <p className="eyebrow">AVAILABLE SIMULATIONS</p>
          <p className="stat-num mt-3 text-3xl">{simulations.length}</p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">RUNNING REQUEST</p>
          <p className="stat-num mt-3 text-3xl text-signal">
            {running ? 1 : 0}
          </p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">STARTED</p>
          <p className="stat-num mt-3 text-3xl text-teal-300">
            {startedCount}
          </p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">FAILED REQUESTS</p>
          <p className="stat-num mt-3 text-3xl text-red-400">
            {failedCount}
          </p>
        </div>
      </section>

      <section>
        <div className="mb-3">
          <p className="eyebrow">SIMULATION LIBRARY</p>
          <h2 className="mt-1 text-base font-semibold">
            Approved Lab Scenarios
          </h2>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {simulations.map((simulation) => {
            const result = results[simulation.id];
            const isRunning = running === simulation.id;

            return (
              <article
                key={simulation.id}
                className="panel flex min-w-0 flex-col p-4"
              >
                <div className="flex flex-wrap gap-1.5">
                  {simulation.techniques.map((technique) => (
                    <span
                      key={technique}
                      className="rounded border border-indigo-400/30 bg-indigo-400/5 px-1.5 py-0.5 font-mono text-[10px] text-indigo-300"
                    >
                      {technique}
                    </span>
                  ))}
                </div>

                <div className="mt-3 flex-1">
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="text-sm font-medium leading-5">
                      {simulation.name}
                    </h3>
                    <span
                      className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                        severityStyles[simulation.severity]
                      }`}
                    >
                      {simulation.severity}
                    </span>
                  </div>

                  <p className="mt-3 text-xs leading-5 text-mute">
                    {simulation.detail}
                  </p>
                </div>

                {result?.message && (
                  <p
                    className={`mt-3 break-words text-xs leading-5 ${
                      result.status === "FAILED"
                        ? "text-red-400"
                        : "text-teal-300"
                    }`}
                  >
                    {result.message}
                  </p>
                )}

                <div className="mt-4">
                  <button
                    type="button"
                    onClick={() => launchSimulation(simulation)}
                    disabled={Boolean(running)}
                    className="w-full rounded-md border border-signal/40 bg-signal/10 px-3 py-2 text-xs font-medium text-signal transition hover:bg-signal/20 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {isRunning ? "Sending request..." : "Run simulation"}
                  </button>

                  <p
                    className={`mt-2 font-mono text-[10px] ${
                      result?.status === "FAILED"
                        ? "text-red-400"
                        : result?.status === "STARTED"
                          ? "text-teal-300"
                          : "text-mute"
                    }`}
                  >
                    STATUS: {isRunning ? "SENDING REQUEST" : result?.status ?? "NOT STARTED"}
                  </p>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="panel p-4">
        <p className="eyebrow">CONTROLLED SIMULATION LAUNCH</p>
        <h2 className="mt-2 text-sm font-semibold">
          Why the server uses a whitelist
        </h2>
        <p className="mt-2 text-sm leading-6 text-mute">
          The UI sends only a scenario identifier. The server must validate
          it against an approved whitelist. The UI never constructs a script
          path or selects an arbitrary file to execute.
        </p>
      </section>

      <p className="text-xs text-mute">
        DATA SOURCE: POST /api/sim/&lt;n&gt;. A successful response confirms
        request acceptance, not successful threat detection.
      </p>
    </main>
  );
}
