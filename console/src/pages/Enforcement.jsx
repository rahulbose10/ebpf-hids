import { useState } from "react";
import { api, roleAtLeast, usePoll, useSession } from "../api";
import StatCard from "../components/StatCard";

const FIELD =
  "rounded border border-line bg-ink px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-signal disabled:cursor-not-allowed disabled:opacity-50";

const DECISION_STYLE = {
  executed: "text-critical",
  dry_run: "text-medium",
  guard_blocked: "text-signal",
};

function Toggle({ checked, onChange, label, disabled }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-10 shrink-0 rounded-full transition disabled:cursor-not-allowed disabled:opacity-50 ${
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

function wallTime(ts) {
  if (typeof ts !== "number") return "-";
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

function statusOf(state) {
  if (!state) return { value: "-", sub: "waiting for /api/enforcement" };
  if (!state.enabled) return { value: "OFF", sub: "alerts are only recorded" };
  if (state.dry_run) return { value: "DRY RUN", sub: "decides and logs, kills nothing", tone: "medium" };
  return { value: "ARMED", sub: "SIGTERM, then SIGKILL", tone: "critical" };
}

export default function Enforcement() {
  const me = useSession();
  const isAdmin = roleAtLeast(me?.role, "admin");
  const isAnalyst = roleAtLeast(me?.role, "analyst");

  const poll = usePoll(api.enforcement, 3000);
  const state = poll.data;
  const actions = state?.actions ?? [];
  const counts = state?.counts ?? {};
  const status = statusOf(state);

  const [saving, setSaving] = useState(false);
  const [settingsError, setSettingsError] = useState("");

  const [pidText, setPidText] = useState("");
  const [commText, setCommText] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [manualResult, setManualResult] = useState(null);
  const [manualError, setManualError] = useState("");

  const [clearMessage, setClearMessage] = useState("");

  async function changeSetting(settings) {
    setSaving(true);
    setSettingsError("");
    try {
      await api.setEnforcement(settings);
      await poll.refresh();
    } catch (err) {
      setSettingsError(err?.error || "The server did not accept the change.");
    } finally {
      setSaving(false);
    }
  }

  async function requestAction(event) {
    event.preventDefault();
    setRequesting(true);
    setManualError("");
    setManualResult(null);
    const trimmed = pidText.trim();
    const pid = /^\d+$/.test(trimmed) ? Number(trimmed) : trimmed;
    const comm = commText.trim() || undefined;
    try {
      const result = await api.enforceProcess(pid, comm);
      setManualResult(result);
      await poll.refresh();
    } catch (err) {
      setManualError(err?.error || "The server did not accept the request.");
    } finally {
      setRequesting(false);
    }
  }

  async function clearLog() {
    setClearMessage("");
    try {
      const result = await api.clearEnforcement();
      setClearMessage(`Cleared ${result.cleared} entries.`);
      await poll.refresh();
    } catch (err) {
      setClearMessage(err?.error || "The server did not clear the log.");
    }
  }

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Active response</div>
        <h1>Enforcement</h1>
        <p>
          The server can stop a process when an alert reaches the minimum severity. It sends SIGTERM,
          then SIGKILL if the process is still running after the grace period. It starts off and in
          dry run.
        </p>
      </div>

      {poll.error && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load /api/enforcement: {poll.error.error || "no answer"}
        </div>
      )}

      {state?.note && (
        <div className="mb-3 rounded border border-line bg-ink-700 px-3 py-2 font-mono text-[11px] text-mute">
          Server note: {state.note}
        </div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Status" value={status.value} sub={status.sub} tone={status.tone} />
        <StatCard label="Min severity" value={state?.min_severity ?? "-"} sub="alerts at or above this" />
        <StatCard
          label="Grace period"
          value={state ? `${state.grace_seconds} s` : "-"}
          sub="between SIGTERM and SIGKILL"
        />
        <StatCard
          label="Actions logged"
          value={state ? actions.length : "-"}
          sub={`${counts.executed ?? 0} executed, ${counts.dry_run ?? 0} dry run, ${counts.guard_blocked ?? 0} guard blocked`}
        />
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="panel">
          <div className="panel-label">Response policy</div>
          <div className="panel-body divide-y divide-line">
            <PolicyRow title="Active response" description="Master switch. When off, alerts are only recorded.">
              <Toggle
                label="Active response"
                checked={Boolean(state?.enabled)}
                disabled={!state || !isAdmin || saving}
                onChange={(value) => changeSetting({ enabled: value })}
              />
            </PolicyRow>

            <PolicyRow
              title="Dry run"
              description="Decide and log the action without sending any signal. A real kill needs active response on and dry run off."
            >
              <Toggle
                label="Dry run"
                checked={Boolean(state?.dry_run)}
                disabled={!state || !isAdmin || saving}
                onChange={(value) => changeSetting({ dry_run: value })}
              />
            </PolicyRow>

            <PolicyRow title="Minimum severity" description="Only alerts at or above this trigger a response.">
              <select
                value={state?.min_severity ?? ""}
                disabled={!state || !isAdmin || saving}
                onChange={(e) => changeSetting({ min_severity: e.target.value })}
                className={FIELD}
              >
                {(state?.severities ?? []).map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </select>
            </PolicyRow>

            {!isAdmin && (
              <p className="pt-2.5 font-mono text-[11px] text-mute">
                Changing the policy needs the admin role. You are signed in as {me?.role ?? "unknown role"}.
              </p>
            )}
            {settingsError && <p className="pt-2.5 font-mono text-[11px] text-critical">{settingsError}</p>}
          </div>
        </div>

        <div className="grid content-start gap-3">
          <div className="panel">
            <div className="panel-label">Guards</div>
            <div className="panel-body grid gap-2 text-[12px] leading-relaxed text-mute">
              <p>
                Never acts on a pid below{" "}
                <span className="font-mono text-text">{state?.min_safe_pid ?? "-"}</span>, or on any
                process in the server&apos;s own process tree.
              </p>
              <p>Never acts on these names:</p>
              <p className="break-words font-mono text-[11px] text-text">
                {(state?.never_kill ?? []).join(", ") || "-"}
              </p>
            </div>
          </div>

          <div className="panel">
            <div className="panel-label">In-kernel prevention</div>
            <div className="panel-body text-[12px] leading-relaxed text-mute">
              The BPF-LSM program (loader/ips_enforce) denies an operation before it happens. It runs
              as its own process and the API does not report its status, so this page cannot show
              whether it is loaded.
            </div>
          </div>
        </div>
      </div>

      <div className="panel mt-3">
        <div className="panel-label">Act on one process</div>
        <form className="panel-body flex flex-wrap items-end gap-3" onSubmit={requestAction}>
          <label className="grid gap-1 text-[11px] text-mute">
            pid
            <input
              value={pidText}
              onChange={(e) => setPidText(e.target.value)}
              disabled={!isAnalyst || requesting}
              className={`${FIELD} w-28`}
              inputMode="numeric"
            />
          </label>
          <label className="grid gap-1 text-[11px] text-mute">
            comm (optional)
            <input
              value={commText}
              onChange={(e) => setCommText(e.target.value)}
              disabled={!isAnalyst || requesting}
              className={`${FIELD} w-44`}
            />
          </label>
          <button
            type="submit"
            disabled={!isAnalyst || requesting || pidText.trim() === ""}
            className="rounded border border-critical/40 bg-critical/10 px-3 py-1.5 text-[12px] font-medium text-critical transition hover:bg-critical/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {requesting ? "Sending..." : "Request action"}
          </button>
          <p className="basis-full text-[11px] leading-snug text-mute">
            Goes through the same guards and the same off and dry run switches as an alert. With the
            default settings it only logs what it would have done.
            {!isAnalyst && ` Needs the analyst role. You are signed in as ${me?.role ?? "unknown role"}.`}
          </p>
          {manualError && <p className="basis-full font-mono text-[11px] text-critical">{manualError}</p>}
          {manualResult && (
            <p className="basis-full font-mono text-[11px]">
              <span className={DECISION_STYLE[manualResult.decision] || "text-text"}>
                {manualResult.decision}
              </span>{" "}
              <span className="text-mute">
                pid {manualResult.pid} {manualResult.comm ?? ""}: {manualResult.reason}
              </span>
            </p>
          )}
        </form>
      </div>

      <div className="panel mt-3">
        <div className="panel-label flex items-center justify-between gap-3">
          <span>Response log</span>
          <span className="flex items-center gap-3">
            {clearMessage && <span className="normal-case tracking-normal">{clearMessage}</span>}
            <span>{actions.length} recent</span>
            {isAdmin && actions.length > 0 && (
              <button
                type="button"
                onClick={clearLog}
                className="rounded border border-line px-2 py-0.5 normal-case tracking-normal hover:border-signal hover:text-signal"
              >
                Clear
              </button>
            )}
          </span>
        </div>

        {actions.length === 0 ? (
          <div className="px-4 py-6 text-center font-mono text-[11px] text-mute">
            {state ? "No actions since the server started." : "Waiting for /api/enforcement."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[12px]">
              <thead className="text-mute">
                <tr className="eyebrow">
                  <th className="px-4 py-2">Time</th>
                  <th className="px-4 py-2">pid</th>
                  <th className="px-4 py-2">comm</th>
                  <th className="px-4 py-2">Rule</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Decision</th>
                  <th className="px-4 py-2">Reason</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((item, index) => (
                  <tr key={`${item.ts}-${item.pid}-${index}`} className="border-t border-line align-top">
                    <td className="px-4 py-2 font-mono text-mute">{wallTime(item.ts)}</td>
                    <td className="px-4 py-2 font-mono">{item.pid}</td>
                    <td className="px-4 py-2 font-mono">{item.comm ?? "-"}</td>
                    <td className="px-4 py-2">{item.rule}</td>
                    <td className="px-4 py-2">{item.severity}</td>
                    <td className={`px-4 py-2 font-mono ${DECISION_STYLE[item.decision] || ""}`}>
                      {item.decision}
                    </td>
                    <td className="px-4 py-2 text-[11px] text-mute">{item.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="px-4 pb-3 font-mono text-[10px] text-mute">
          Time here is the server&apos;s wall clock, not kernel time.
        </p>
      </div>
    </div>
  );
}
