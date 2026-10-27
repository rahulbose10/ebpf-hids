import { useMemo, useState } from "react";
import { api, usePoll } from "../api";

const COLUMNS = [
  { key: "pid", label: "PID", align: "right" },
  { key: "ppid", label: "PPID", align: "right" },
  { key: "comm", label: "Command", align: "left" },
  { key: "uid", label: "UID", align: "right" },
  { key: "exec_count", label: "Exec", align: "right" },
  { key: "connect_count", label: "Connect", align: "right" },
  { key: "file_write_count", label: "File write", align: "right" },
  { key: "ptrace_count", label: "Ptrace", align: "right", warn: true },
  { key: "setuid_count", label: "Setuid", align: "right", warn: true },
  { key: "depth", label: "Depth", align: "right" },
  { key: "lifetime_s", label: "Lifetime", align: "right" },
  { key: "root", label: "Root", align: "left" },
];

// The stub backend still uses name/user, the real process dict uses comm/uid.
// Accept both so the page works against either until L4 replaces the stub.
function commandOf(p) {
  return p.comm ?? p.name ?? "-";
}

function uidOf(p) {
  return p.uid ?? p.user ?? "-";
}

function rootOf(p) {
  if (typeof p.ran_as_root === "boolean") return p.ran_as_root ? "ROOT" : "USER";
  if (p.user === "root") return "ROOT";
  if (p.user) return "USER";
  return "-";
}

function cell(p, key) {
  if (key === "comm") return commandOf(p);
  if (key === "uid") return uidOf(p);
  if (key === "root") return rootOf(p);
  const value = p[key];
  if (value === undefined || value === null) return "-";
  if (key === "lifetime_s") return `${Number(value).toFixed(1)}s`;
  return value;
}

function cellClass(p, col) {
  const value = cell(p, col.key);

  if (col.key === "comm") return "font-semibold text-text";
  if (col.key === "root") {
    if (value === "ROOT") return "text-critical";
    if (value === "USER") return "text-mute";
    return "text-mute/60";
  }
  if (value === "-" || value === 0) return "text-mute/50";
  // ptrace and setuid are the two counters that usually mean something is wrong
  if (col.warn) return "font-semibold text-high";
  return "text-text/90";
}

function Processes() {
  const { data, error } = usePoll(api.processes, 5000);
  const [filter, setFilter] = useState("");

  const all = useMemo(() => data?.processes || [], [data]);

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return all;
    return all.filter(
      (p) =>
        String(p.pid).includes(q) || commandOf(p).toLowerCase().includes(q)
    );
  }, [all, filter]);

  return (
    <div className="flex flex-col gap-3">
      <div className="page-header">
        <h1>Processes</h1>
        <p>Live process activity collected by the HIDS sensor.</p>
      </div>

      <section className="panel flex flex-col overflow-hidden">
        <header className="flex h-11 items-center justify-between gap-4 border-b border-line px-4">
          <span className="eyebrow">Process monitor</span>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="filter by pid or command"
              aria-label="Filter processes by pid or command"
              className="h-7 w-56 rounded border border-line bg-ink px-2.5 font-mono text-[11px] text-text outline-none placeholder:text-mute/70 focus:border-signal/60"
            />
            <span className="whitespace-nowrap font-mono text-[11px] text-mute">
              <strong className="text-text">{shown.length}</strong>
              {filter ? ` of ${all.length}` : ""} processes
            </span>
          </div>
        </header>

        {error && !data ? (
          <div className="m-4 rounded border border-critical/30 bg-critical/5 px-4 py-3 font-mono text-xs text-critical">
            Could not load process data from /api/processes.
          </div>
        ) : !data ? (
          <div className="px-4 py-10 text-center font-mono text-xs text-mute">
            Loading process data...
          </div>
        ) : (
          <div className="h-[calc(100vh-250px)] min-h-[300px] overflow-auto">
            <table className="w-full min-w-[960px] border-separate border-spacing-0 font-mono text-[11.5px]">
              <thead>
                <tr>
                  {COLUMNS.map((col) => (
                    <th
                      key={col.key}
                      className={`sticky top-0 z-10 whitespace-nowrap border-b border-line bg-ink-800 px-3 py-2 text-[10px] font-medium uppercase tracking-[0.12em] text-mute ${
                        col.align === "right" ? "text-right" : "text-left"
                      }`}
                    >
                      {col.label}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {shown.length === 0 ? (
                  <tr>
                    <td
                      colSpan={COLUMNS.length}
                      className="px-4 py-10 text-center text-mute"
                    >
                      {all.length === 0
                        ? "No process data available."
                        : "No process matches the filter."}
                    </td>
                  </tr>
                ) : (
                  shown.map((p) => (
                    <tr key={p.pid} className="hover:bg-ink-700">
                      {COLUMNS.map((col) => (
                        <td
                          key={col.key}
                          className={`h-7 whitespace-nowrap border-b border-line/40 px-3 tabular-nums ${
                            col.align === "right" ? "text-right" : "text-left"
                          } ${cellClass(p, col)}`}
                        >
                          {cell(p, col.key)}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default Processes;
