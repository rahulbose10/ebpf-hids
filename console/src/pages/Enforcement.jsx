
import { useState } from "react";

const actionLog = [];

function Toggle({ checked, onChange, label }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-10 shrink-0 rounded-full transition ${
        checked ? "bg-signal/40" : "bg-ink-600"
      }`}
    >
      <span
        className={`absolute top-0.5 h-4 w-4 rounded-full transition ${
          checked
            ? "left-[22px] bg-signal"
            : "left-0.5 bg-mute"
        }`}
      />
    </button>
  );
}

function PolicyRow({ title, description, children }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 py-3">
      <div>
        <p className="text-sm font-medium">{title}</p>
        <p className="mt-1 text-xs leading-5 text-mute">
          {description}
        </p>
      </div>
      {children}
    </div>
  );
}

export default function Enforcement() {
  const [activeResponse, setActiveResponse] = useState(false);
  const [dryRun, setDryRun] = useState(true);
  const [action, setAction] = useState("kill");
  const [minSeverity, setMinSeverity] = useState("critical");

  const loggedCount = actionLog.length;
  const executedCount = actionLog.filter(
    (item) => item.status === "executed"
  ).length;
  const dryRunCount = actionLog.filter(
    (item) => item.status === "dry-run"
  ).length;
  const blockedCount = actionLog.filter(
    (item) => item.status === "BLOCKED-by-guard"
  ).length;

  return (
    <main className="min-h-full space-y-4 p-4 text-text sm:p-6">
      <header>
        <h1 className="font-display text-2xl font-semibold">
          Enforcement
        </h1>
        <p className="mt-2 max-w-4xl text-sm leading-6 text-mute">
          Active response. The engine can terminate or quarantine a
          process when an alert meets the threshold. It is off and
          dry-run by default. Arming is an admin action.
        </p>
      </header>

      <section className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <div className="panel p-4">
          <p className="eyebrow">STATUS</p>
          <p className="mt-2 font-display text-2xl font-semibold">
            {activeResponse ? "ARMED" : "OFF"}
          </p>
          <p className="mt-1 text-xs text-mute">
            {activeResponse ? "UI selection only" : "no action taken"}
          </p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">ACTION</p>
          <p className="mt-2 font-display text-2xl font-semibold">
            {action}
          </p>
          <p className="mt-1 text-xs text-mute">
            kill or quarantine
          </p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">MIN SEVERITY</p>
          <p className="mt-2 font-display text-2xl font-semibold">
            {minSeverity}
          </p>
          <p className="mt-1 text-xs text-mute">
            threshold to act
          </p>
        </div>

        <div className="panel p-4">
          <p className="eyebrow">ACTIONS LOGGED</p>
          <p className="mt-2 font-display text-2xl font-semibold">
            {loggedCount}
          </p>
          <p className="mt-1 text-xs text-mute">
            {executedCount} executed · {dryRunCount} dry-run ·{" "}
            {blockedCount} guarded
          </p>
        </div>
      </section>

      <section className="panel px-4 py-4 sm:px-5">
        <p className="eyebrow">RESPONSE POLICY</p>

        <div className="mt-2 divide-y divide-line">
          <PolicyRow
            title="Active response"
            description="Master switch. When off, the engine only detects."
          >
            <Toggle
              label="Active response"
              checked={activeResponse}
              onChange={setActiveResponse}
            />
          </PolicyRow>

          <PolicyRow
            title="Dry-run (recommended)"
            description="Decide and log the action without executing it. Validate against benign traffic before disabling."
          >
            <Toggle
              label="Dry-run"
              checked={dryRun}
              onChange={setDryRun}
            />
          </PolicyRow>

          <PolicyRow
            title="Action"
            description="What to do to a flagged process."
          >
            <select
              value={action}
              onChange={(event) => setAction(event.target.value)}
              className="rounded-md border border-line bg-ink px-3 py-2 font-mono text-sm outline-none focus:border-signal"
            >
              <option value="kill">kill</option>
              <option value="quarantine">quarantine</option>
            </select>
          </PolicyRow>

          <PolicyRow
            title="Minimum severity"
            description="Only alerts at or above this trigger a response."
          >
            <select
              value={minSeverity}
              onChange={(event) => setMinSeverity(event.target.value)}
              className="rounded-md border border-line bg-ink px-3 py-2 font-mono text-sm outline-none focus:border-signal"
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </PolicyRow>
        </div>

        <p className="mt-3 border-t border-line pt-3 text-xs text-mute">
          These controls change only this page's local state. They do
          not change the backend enforcement configuration.
        </p>
      </section>

      <section className="panel p-4 sm:p-5">
        <p className="eyebrow">
          IN-KERNEL PREVENTION (SEPARATE LAYER)
        </p>
        <p className="mt-3 text-sm leading-6 text-mute">
          This page controls the userspace response. The stronger layer
          is an eBPF enforcement program that can deny an operation
          before it happens. Its actual status is not connected to
          this frontend.
        </p>
      </section>

      <section className="panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-4 py-3 sm:px-5">
          <p className="eyebrow">RESPONSE AUDIT LOG</p>
          <span className="font-mono text-xs text-mute">
            {loggedCount} recent
          </span>
        </div>

        {actionLog.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-mute">
            No audit records available. Backend audit is not connected.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[650px] text-left text-sm">
              <thead className="bg-ink-800/70 text-mute">
                <tr className="eyebrow">
                  <th className="px-4 py-3">TIME</th>
                  <th className="px-4 py-3">ACTION</th>
                  <th className="px-4 py-3">TARGET</th>
                  <th className="px-4 py-3">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {actionLog.map((item) => (
                  <tr key={item.id} className="border-t border-line">
                    <td className="px-4 py-3 font-mono text-mute">
                      {item.time}
                    </td>
                    <td className="px-4 py-3">{item.action}</td>
                    <td className="px-4 py-3 font-mono text-mute">
                      {item.target}
                    </td>
                    <td className="px-4 py-3">{item.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="border-t border-line px-4 py-3 text-xs text-mute">
          DATA SOURCE: MOCK · LIVE BACKEND AUDIT NOT CONNECTED
        </div>
      </section>
    </main>
  );
}
