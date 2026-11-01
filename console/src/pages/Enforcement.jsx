import { useState } from "react";
import StatCard from "../components/StatCard";

// Rows of a response audit log. Empty on purpose: there is no backend audit
// endpoint yet, so nothing may be invented here.
const actionLog = [];

const FIELD =
  "rounded border border-line bg-ink px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-signal";

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
          checked ? "left-[22px] bg-signal" : "left-0.5 bg-mute"
        }`}
      />
    </button>
  );
}

function PolicyRow({ title, description, children }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <p className="text-[13px] font-medium">{title}</p>
        <p className="text-[11px] leading-snug text-mute">{description}</p>
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

  const count = (status) => actionLog.filter((item) => item.status === status).length;

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Active response</div>
        <h1>Enforcement</h1>
        <p>
          The engine can terminate or quarantine a process when an alert meets the threshold. It is
          off and dry-run by default.
        </p>
      </div>

      <div className="mb-3 rounded border border-medium/40 bg-medium/10 px-3 py-2 font-mono text-[11px] text-medium">
        These controls change this browser tab only. They do not change the backend enforcement
        configuration, and the audit log is not connected.
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard
          label="Status"
          value={activeResponse ? "ARMED" : "OFF"}
          sub={activeResponse ? "UI selection only" : "no action taken"}
          tone={activeResponse ? "high" : undefined}
        />
        <StatCard label="Action" value={action} sub="kill or quarantine" />
        <StatCard label="Min severity" value={minSeverity} sub="threshold to act" />
        <StatCard
          label="Actions logged"
          value={actionLog.length}
          sub={`${count("executed")} executed, ${count("dry-run")} dry-run, ${count("BLOCKED-by-guard")} guarded`}
        />
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="panel">
          <div className="panel-label">Response policy</div>
          <div className="panel-body divide-y divide-line">
            <PolicyRow title="Active response" description="Master switch. When off, the engine only detects.">
              <Toggle label="Active response" checked={activeResponse} onChange={setActiveResponse} />
            </PolicyRow>

            <PolicyRow
              title="Dry-run (recommended)"
              description="Decide and log the action without executing it. Check against benign traffic before turning this off."
            >
              <Toggle label="Dry-run" checked={dryRun} onChange={setDryRun} />
            </PolicyRow>

            <PolicyRow title="Action" description="What to do to a flagged process.">
              <select value={action} onChange={(e) => setAction(e.target.value)} className={FIELD}>
                <option value="kill">kill</option>
                <option value="quarantine">quarantine</option>
              </select>
            </PolicyRow>

            <PolicyRow title="Minimum severity" description="Only alerts at or above this trigger a response.">
              <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)} className={FIELD}>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </PolicyRow>
          </div>
        </div>

        <div className="panel self-start">
          <div className="panel-label">In-kernel prevention</div>
          <div className="panel-body text-[12px] leading-relaxed text-mute">
            This page controls the userspace response. The stronger layer is an eBPF enforcement
            program that can deny an operation before it happens. Its status is not connected to this
            console yet.
          </div>
        </div>
      </div>

      <div className="panel mt-3">
        <div className="panel-label flex items-center justify-between">
          <span>Response audit log</span>
          <span>{actionLog.length} recent</span>
        </div>

        {actionLog.length === 0 ? (
          <div className="px-4 py-6 text-center font-mono text-[11px] text-mute">
            No audit records. The backend audit endpoint is not connected.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[650px] text-left text-[12px]">
              <thead className="text-mute">
                <tr className="eyebrow">
                  <th className="px-4 py-2">Time</th>
                  <th className="px-4 py-2">Action</th>
                  <th className="px-4 py-2">Target</th>
                  <th className="px-4 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {actionLog.map((item) => (
                  <tr key={item.id} className="border-t border-line">
                    <td className="px-4 py-2 font-mono text-mute">{item.time}</td>
                    <td className="px-4 py-2">{item.action}</td>
                    <td className="px-4 py-2 font-mono text-mute">{item.target}</td>
                    <td className="px-4 py-2">{item.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
