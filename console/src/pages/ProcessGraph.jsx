import { useMemo, useState } from "react";
import { api, usePoll } from "../api";
import SeverityChip from "../components/SeverityChip";
import { formatKts } from "../format";

// Spacing of the drawn tree, in SVG pixels.
const NODE_GAP_X = 110;
const LEVEL_GAP_Y = 96;
const MARGIN_X = 60;
const MARGIN_TOP = 52;
const MARGIN_BOTTOM = 44;

const SEVERITY_COLOR = {
  critical: "#ff5d5d",
  high: "#f2a65a",
  medium: "#e8c34a",
  low: "#39c2b0",
};

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

// The stub backend sends name/user, the real process dict sends comm/uid.
// Accept both so the page works against either until L4 replaces the stub.
function normaliseProcess(p) {
  const hasParent = p.ppid !== undefined && p.ppid !== null && p.ppid !== "";
  return {
    ...p,
    pid: Number(p.pid),
    ppid: hasParent ? Number(p.ppid) : null,
    comm: p.comm ?? p.name ?? "unknown",
    uid: p.uid ?? p.user ?? "-",
    lifetime_s: Number(p.lifetime_s) || 0,
    ran_as_root:
      typeof p.ran_as_root === "boolean" ? p.ran_as_root : p.user === "root",
  };
}

// Worst severity among all alerts of one pid, or null if it has none.
// Built once for all pids so drawing N nodes does not filter the alert list N times.
function worstSeverityByPid(alerts) {
  const worst = new Map();
  alerts.forEach((alert) => {
    const pid = Number(alert.pid);
    const level = String(alert.severity || "low").toLowerCase();
    const current = worst.get(pid);
    if (!current || (SEVERITY_ORDER[level] || 0) > (SEVERITY_ORDER[current] || 0)) {
      worst.set(pid, level);
    }
  });
  return worst;
}

// Turn the flat process list into a forest. A process whose parent is not in
// the list becomes a root. Any process left unreached (a ppid cycle) is also
// promoted to a root, so it is never silently dropped from the picture.
function buildTree(processes) {
  const byPid = new Map();
  processes.forEach((p) => byPid.set(p.pid, { ...p, children: [] }));

  const roots = [];
  byPid.forEach((node) => {
    const parent = node.ppid !== null && node.ppid !== node.pid ? byPid.get(node.ppid) : null;
    if (parent) parent.children.push(node);
    else roots.push(node);
  });

  const seen = new Set();
  const mark = (node) => {
    if (seen.has(node.pid)) return;
    seen.add(node.pid);
    node.children.forEach(mark);
  };
  roots.forEach(mark);
  byPid.forEach((node) => {
    if (!seen.has(node.pid)) {
      roots.push(node);
      mark(node);
    }
  });

  return roots;
}

// Leaves take the next free column. A parent sits in the middle of its first
// and last child. Y comes from the real tree depth, not from process.depth,
// so the picture is right even when the backend depth field is off.
function layoutTree(roots) {
  const positions = new Map();
  let nextColumn = 0;
  let deepest = 0;

  function place(node, level) {
    deepest = Math.max(deepest, level);
    const y = MARGIN_TOP + level * LEVEL_GAP_Y;

    if (!node.children.length) {
      positions.set(node.pid, { x: MARGIN_X + nextColumn * NODE_GAP_X, y });
      nextColumn += 1;
      return;
    }

    node.children.forEach((child) => place(child, level + 1));
    const first = positions.get(node.children[0].pid);
    const last = positions.get(node.children[node.children.length - 1].pid);
    positions.set(node.pid, { x: (first.x + last.x) / 2, y });
  }

  roots.forEach((root) => {
    place(root, 0);
    nextColumn += 0.5; // a small gap between separate trees
  });

  const width = MARGIN_X * 2 + Math.max(1, nextColumn - 1) * NODE_GAP_X;
  const height = MARGIN_TOP + deepest * LEVEL_GAP_Y + MARGIN_BOTTOM;
  return { positions, width, height };
}

function flatten(roots) {
  const nodes = [];
  const edges = [];
  const walk = (node) => {
    nodes.push(node);
    node.children.forEach((child) => {
      edges.push({ parent: node, child });
      walk(child);
    });
  };
  roots.forEach(walk);
  return { nodes, edges };
}

function ProcessNode({ node, position, severity, selected, onSelect }) {
  const ring = severity ? SEVERITY_COLOR[severity] || SEVERITY_COLOR.low : "#243149";
  const label = node.comm.length > 14 ? `${node.comm.slice(0, 13)}…` : node.comm;

  return (
    <g
      transform={`translate(${position.x}, ${position.y})`}
      onClick={() => onSelect(node.pid)}
      style={{ cursor: "pointer" }}
    >
      <title>{`${node.comm} (pid ${node.pid})`}</title>

      {node.ran_as_root && (
        <circle r="24" fill="none" stroke="#ff5d5d" strokeWidth="1.2" strokeDasharray="3 3" />
      )}

      {severity && (
        <circle
          r="23"
          fill="none"
          stroke={ring}
          strokeWidth="5"
          opacity="0.16"
          style={{ filter: `drop-shadow(0 0 8px ${ring})` }}
        />
      )}

      <circle
        r="18"
        fill="#111a2b"
        stroke={selected ? "#e6edf6" : ring}
        strokeWidth={selected ? 2.2 : severity ? 1.8 : 1.1}
        style={severity ? { filter: `drop-shadow(0 0 6px ${ring})` } : undefined}
      />

      <text
        y="4"
        textAnchor="middle"
        fill="#e6edf6"
        fontSize="10"
        fontFamily="JetBrains Mono, monospace"
      >
        {node.pid}
      </text>

      <text
        y="-30"
        textAnchor="middle"
        fill="#7e8aa0"
        fontSize="10"
        fontFamily="JetBrains Mono, monospace"
        stroke="#0d1422"
        strokeWidth="4"
        paintOrder="stroke"
      >
        {label}
      </text>

      {severity && <circle cx="14" cy="-14" r="3.5" fill={ring} />}
    </g>
  );
}

function LegendRow({ swatch, label }) {
  return (
    <div className="flex items-center gap-2 text-[11px] text-mute">
      {swatch}
      <span className="font-mono">{label}</span>
    </div>
  );
}

function Detail({ label, value, tone }) {
  return (
    <div className="flex justify-between gap-3 py-[3px] font-mono text-[11px]">
      <span className="text-mute">{label}</span>
      <span className={tone || "text-text"}>{value}</span>
    </div>
  );
}

export default function ProcessGraph() {
  const processesPoll = usePoll(api.processes, 5000);
  const alertsPoll = usePoll(api.alerts, 5000);
  const [selectedPid, setSelectedPid] = useState(null);

  const processes = useMemo(
    () => (processesPoll.data?.processes || []).map(normaliseProcess),
    [processesPoll.data]
  );
  const alerts = useMemo(() => alertsPoll.data?.alerts || [], [alertsPoll.data]);

  const roots = useMemo(() => buildTree(processes), [processes]);
  const { nodes, edges } = useMemo(() => flatten(roots), [roots]);
  const layout = useMemo(() => layoutTree(roots), [roots]);
  const worst = useMemo(() => worstSeverityByPid(alerts), [alerts]);

  // Keep the selection by pid, so it survives a refresh and clears itself
  // when that process is no longer in the list.
  const selected = nodes.find((n) => n.pid === selectedPid) || null;
  const selectedAlerts = selected
    ? alerts.filter((a) => Number(a.pid) === selected.pid)
    : [];

  const loading = !processesPoll.data && !processesPoll.error;

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Process correlation</div>
        <h1>Process Graph</h1>
        <p>Parent and child processes from /api/processes. A ring colour shows the worst alert on that pid.</p>
      </div>

      {processesPoll.error && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load /api/processes: {String(processesPoll.error.message || processesPoll.error)}
        </div>
      )}

      <div className="grid gap-4" style={{ gridTemplateColumns: "minmax(0, 1fr) 280px" }}>
        <section className="min-h-[420px] overflow-auto rounded-lg border border-line bg-ink-800/60">
          {loading ? (
            <div className="p-6 font-mono text-[12px] text-mute">Loading process tree...</div>
          ) : nodes.length === 0 ? (
            <div className="p-6 font-mono text-[12px] text-mute">
              /api/processes returned no processes.
            </div>
          ) : (
            <svg
              width={layout.width}
              height={layout.height}
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              role="img"
              aria-label="Process correlation graph"
            >
              {edges.map(({ parent, child }) => {
                const a = layout.positions.get(parent.pid);
                const b = layout.positions.get(child.pid);
                if (!a || !b) return null;
                const mid = (a.y + b.y) / 2;
                return (
                  <path
                    key={`${parent.pid}-${child.pid}`}
                    d={`M ${a.x} ${a.y} C ${a.x} ${mid}, ${b.x} ${mid}, ${b.x} ${b.y}`}
                    fill="none"
                    stroke="#243149"
                    strokeWidth="1.3"
                  />
                );
              })}

              {nodes.map((node) => (
                <ProcessNode
                  key={node.pid}
                  node={node}
                  position={layout.positions.get(node.pid)}
                  severity={worst.get(node.pid) || null}
                  selected={selected?.pid === node.pid}
                  onSelect={setSelectedPid}
                />
              ))}
            </svg>
          )}
        </section>

        <aside className="grid content-start gap-3">
          <div className="panel">
            <div className="panel-label">Legend</div>
            <div className="panel-body grid gap-2">
              {Object.entries(SEVERITY_COLOR).map(([level, color]) => (
                <LegendRow
                  key={level}
                  label={`${level} alert`}
                  swatch={
                    <span
                      className="h-2.5 w-2.5 rounded-full border-2"
                      style={{ borderColor: color }}
                    />
                  }
                />
              ))}
              <LegendRow
                label="runs as root"
                swatch={<span className="h-2.5 w-2.5 rounded-full border border-dashed border-critical" />}
              />
              <LegendRow
                label="no alerts"
                swatch={<span className="h-2.5 w-2.5 rounded-full border border-line" />}
              />
            </div>
          </div>

          <div className="panel">
            <div className="panel-label">{selected ? "Process detail" : "Select a node"}</div>
            <div className="panel-body">
              {!selected ? (
                <div className="font-mono text-[11px] leading-relaxed text-mute">
                  Click a node to see its fields and the alerts raised on that pid.
                </div>
              ) : (
                <>
                  <Detail label="pid" value={selected.pid} />
                  <Detail label="ppid" value={selected.ppid ?? "-"} />
                  <Detail label="comm" value={selected.comm} />
                  <Detail label="uid" value={selected.uid} />
                  <Detail label="lifetime" value={`${selected.lifetime_s}s`} />
                  <Detail
                    label="root"
                    value={selected.ran_as_root ? "yes" : "no"}
                    tone={selected.ran_as_root ? "text-critical" : "text-low"}
                  />

                  <div className="eyebrow mb-1 mt-3 border-t border-line pt-3">Alerts</div>
                  {selectedAlerts.length === 0 ? (
                    <div className="font-mono text-[11px] text-mute">No alerts for this process.</div>
                  ) : (
                    selectedAlerts.map((alert, i) => (
                      <div
                        key={`${alert.rule}-${alert.ts}-${i}`}
                        className="border-b border-line/60 py-2 last:border-0"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <SeverityChip severity={alert.severity} />
                          <span className="truncate font-mono text-[10px] text-mute">{alert.rule}</span>
                        </div>
                        {alert.summary && (
                          <div className="mt-1 text-[12px] text-text">{alert.summary}</div>
                        )}
                        <div className="mt-0.5 flex gap-2 font-mono text-[10px] text-mute">
                          {alert.technique && <span className="text-ml">{alert.technique}</span>}
                          <span>ts {formatKts(alert.ts)}</span>
                        </div>
                      </div>
                    ))
                  )}
                </>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-body font-mono text-[11px] leading-relaxed text-mute">
              <div>{nodes.length} processes</div>
              <div>{roots.length} root nodes</div>
              <div>{alerts.length} alerts loaded</div>
              <div>refresh every 5s</div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
