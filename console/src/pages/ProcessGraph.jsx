import { useEffect, useMemo, useState } from "react";


const REFRESH_MS = 5000;


const SEVERITY = {
  critical: {
    color: "#ff5d5d",
    glow: "rgba(255, 93, 93, 0.55)",
  },
  high: {
    color: "#f2a65a",
    glow: "rgba(242, 166, 90, 0.50)",
  },
  medium: {
    color: "#e8c34a",
    glow: "rgba(232, 195, 74, 0.45)",
  },
  low: {
    color: "#39c2b0",
    glow: "rgba(57, 194, 176, 0.40)",
  },
};


function normaliseProcess(process) {
  return {
    ...process,

    pid: Number(process.pid),
    ppid:
      process.ppid === undefined ||
      process.ppid === null ||
      process.ppid === ""
        ? null
        : Number(process.ppid),

    comm:
      process.comm ??
      process.name ??
      "unknown",

    uid:
      process.uid ??
      process.user ??
      "—",

    depth:
      process.depth === undefined ||
      process.depth === null
        ? 0
        : Number(process.depth),

    lifetime_s:
      process.lifetime_s === undefined ||
      process.lifetime_s === null
        ? 0
        : Number(process.lifetime_s),

    ran_as_root:
      Boolean(
        process.ran_as_root ??
        process.user === "root"
      ),
  };
}


function severityForProcess(pid, alerts) {
  const processAlerts = alerts.filter(
    (alert) => Number(alert.pid) === Number(pid)
  );

  if (!processAlerts.length) {
    return null;
  }

  const order = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  return processAlerts.reduce((highest, alert) => {
    const current = String(
      alert.severity || "low"
    ).toLowerCase();

    if (!highest) {
      return current;
    }

    return order[current] > order[highest]
      ? current
      : highest;
  }, null);
}


function buildTree(processes) {
  const byPid = new Map();

  processes.forEach((process) => {
    byPid.set(process.pid, {
      ...process,
      children: [],
    });
  });

  const roots = [];

  processes.forEach((process) => {
    const node = byPid.get(process.pid);

    if (
      process.ppid !== null &&
      byPid.has(process.ppid) &&
      process.ppid !== process.pid
    ) {
      byPid
        .get(process.ppid)
        .children
        .push(node);
    } else {
      roots.push(node);
    }
  });

  return {
    roots,
    byPid,
  };
}


function calculateSubtreeWidth(node) {
  if (!node.children.length) {
    return 1;
  }

  return node.children.reduce(
    (total, child) =>
      total + calculateSubtreeWidth(child),
    0
  );
}


function layoutTree(roots) {
  const NODE_GAP_X = 150;
  const LEVEL_GAP_Y = 120;

  const positions = new Map();

  let cursorX = 100;

  function walk(node, depth) {
    const subtreeWidth =
      calculateSubtreeWidth(node);

    const subtreePixelWidth =
      subtreeWidth * NODE_GAP_X;

    const children = node.children;

    if (!children.length) {
      const x = cursorX;

      cursorX += NODE_GAP_X;

      positions.set(node.pid, {
        x,
        y: 80 + depth * LEVEL_GAP_Y,
      });

      return;
    }

    children.forEach((child) => {
      walk(child, depth + 1);
    });

    const firstChild =
      positions.get(children[0].pid);

    const lastChild =
      positions.get(
        children[children.length - 1].pid
      );

    const childCenter =
      (firstChild.x + lastChild.x) / 2;

    positions.set(node.pid, {
      x: childCenter,
      y: 80 + depth * LEVEL_GAP_Y,
    });

    cursorX = Math.max(
      cursorX,
      childCenter + subtreePixelWidth * 0.05
    );
  }

  roots.forEach((root) => {
    walk(root, 0);
    cursorX += 70;
  });

  return positions;
}


function collectNodes(roots) {
  const nodes = [];

  function walk(node) {
    nodes.push(node);

    node.children.forEach(
      (child) => walk(child)
    );
  }

  roots.forEach((root) => walk(root));

  return nodes;
}


function collectEdges(roots) {
  const edges = [];

  function walk(node) {
    node.children.forEach((child) => {
      edges.push({
        parent: node,
        child,
      });

      walk(child);
    });
  }

  roots.forEach((root) => walk(root));

  return edges;
}


function ProcessNode({
  node,
  position,
  severity,
  selected,
  onSelect,
}) {
  const severityData =
    severity
      ? SEVERITY[severity]
      : null;

  const ringColor =
    severityData?.color ||
    "#243149";

  const glow =
    severityData?.glow ||
    "rgba(0,0,0,0)";

  return (
    <g
      transform={`translate(${position.x}, ${position.y})`}
      onClick={() => onSelect(node)}
      style={{
        cursor: "pointer",
      }}
    >
      {node.ran_as_root && (
        <circle
          r="29"
          fill="none"
          stroke="#ff5d5d"
          strokeWidth="1.5"
          strokeDasharray="4 4"
          opacity="0.95"
        />
      )}

      {severity && (
        <circle
          r="25"
          fill="none"
          stroke={ringColor}
          strokeWidth="5"
          opacity="0.16"
          style={{
            filter: `drop-shadow(0 0 10px ${glow})`,
          }}
        />
      )}

      <circle
        r="20"
        fill="#111a2b"
        stroke={ringColor}
        strokeWidth={
          selected ? 2.5 : 1.2
        }
        style={{
          filter: severity
            ? `drop-shadow(0 0 8px ${glow})`
            : "none",
        }}
      />

      <text
        x="0"
        y="-36"
        textAnchor="middle"
        fill="#7e8aa0"
        fontSize="11"
        fontFamily="JetBrains Mono, monospace"
      >
        {node.comm}
      </text>

      <text
        x="0"
        y="4"
        textAnchor="middle"
        fill="#e6edf6"
        fontSize="11"
        fontFamily="JetBrains Mono, monospace"
      >
        {node.pid}
      </text>

      {node.ran_as_root && (
        <text
          x="0"
          y="43"
          textAnchor="middle"
          fill="#ff5d5d"
          fontSize="9"
          fontFamily="JetBrains Mono, monospace"
        >
          ROOT
        </text>
      )}

      {severity && (
        <circle
          cx="16"
          cy="-16"
          r="4"
          fill={ringColor}
          style={{
            filter: `drop-shadow(0 0 5px ${glow})`,
          }}
        />
      )}
    </g>
  );
}


export default function ProcessGraph() {
  const [processes, setProcesses] =
    useState([]);

  const [alerts, setAlerts] =
    useState([]);

  const [selected, setSelected] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  async function loadGraph() {
    try {
      setError("");

      const [
        processResponse,
        alertResponse,
      ] = await Promise.all([
        fetch("/api/processes"),
        fetch("/api/alerts"),
      ]);

      if (!processResponse.ok) {
        throw new Error(
          `Process request failed: ${processResponse.status}`
        );
      }

      const processData =
        await processResponse.json();

      let alertData = {
        alerts: [],
      };

      if (alertResponse.ok) {
        alertData =
          await alertResponse.json();
      }

      const processRows =
        Array.isArray(processData.processes)
          ? processData.processes
          : [];

      const alertRows =
        Array.isArray(alertData.alerts)
          ? alertData.alerts
          : [];

      setProcesses(
        processRows.map(normaliseProcess)
      );

      setAlerts(alertRows);

      setSelected((current) => {
        if (!current) {
          return null;
        }

        return processRows.some(
          (process) =>
            Number(process.pid) ===
            Number(current.pid)
        )
          ? current
          : null;
      });
    } catch (err) {
      setError(
        err.message ||
        "Process Graph request failed."
      );
    } finally {
      setLoading(false);
    }
  }


  useEffect(() => {
    loadGraph();

    const timer =
      window.setInterval(
        loadGraph,
        REFRESH_MS
      );

    return () => {
      window.clearInterval(timer);
    };
  }, []);


  const tree = useMemo(
    () => buildTree(processes),
    [processes]
  );


  const nodes = useMemo(
    () => collectNodes(tree.roots),
    [tree.roots]
  );


  const edges = useMemo(
    () => collectEdges(tree.roots),
    [tree.roots]
  );


  const positions = useMemo(
    () => layoutTree(tree.roots),
    [tree.roots]
  );


  const width = Math.max(
    900,
    positions.size
      ? Math.max(
          ...Array.from(
            positions.values()
          ).map(
            (position) => position.x
          )
        ) + 180
      : 900
  );


  const maxDepth =
    nodes.length
      ? Math.max(
          ...nodes.map(
            (node) =>
              Number(node.depth) || 0
          )
        )
      : 0;


  const height =
    Math.max(
      560,
      150 + (maxDepth + 1) * 120
    );


  return (
    <main
      style={{
        padding: "18px 22px 40px",
        color: "#e6edf6",
      }}
    >
      <div
        style={{
          marginBottom: "18px",
        }}
      >
        <div
          style={{
            color: "#4fd1c5",
            fontFamily:
              "JetBrains Mono, monospace",
            fontSize: "10px",
            letterSpacing: "2px",
            marginBottom: "8px",
          }}
        >
          PROCESS CORRELATION GRAPH
        </div>

        <h1
          style={{
            margin: 0,
            fontSize: "28px",
            fontWeight: 600,
          }}
        >
          Process Graph
        </h1>

        <p
          style={{
            marginTop: "7px",
            color: "#7e8aa0",
            fontSize: "13px",
          }}
        >
          Live process tree built from
          parent and child relationships.
          Nodes that fire detections glow
          by severity.
        </p>
      </div>


      {error && (
        <div
          style={{
            marginBottom: "14px",
            padding: "12px 14px",
            border:
              "1px solid rgba(255,93,93,0.45)",
            background:
              "rgba(255,93,93,0.08)",
            color: "#ff5d5d",
            borderRadius: "8px",
            fontFamily:
              "JetBrains Mono, monospace",
            fontSize: "12px",
          }}
        >
          {error}
        </div>
      )}


      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "minmax(0, 1fr) 260px",
          gap: "18px",
          alignItems: "start",
        }}
      >

        <section
          style={{
            minHeight: "570px",
            border:
              "1px solid #243149",
            borderRadius: "9px",
            background:
              "rgba(17,26,43,0.62)",
            overflow: "auto",
            boxShadow:
              "0 18px 50px rgba(0,0,0,0.22)",
          }}
        >
          {loading ? (
            <div
              style={{
                padding: "40px",
                color: "#7e8aa0",
                fontFamily:
                  "JetBrains Mono, monospace",
              }}
            >
              Loading process tree...
            </div>
          ) : nodes.length === 0 ? (
            <div
              style={{
                padding: "40px",
                color: "#7e8aa0",
                fontFamily:
                  "JetBrains Mono, monospace",
              }}
            >
              No process data returned by
              /api/processes
            </div>
          ) : (
            <svg
              width={width}
              height={height}
              viewBox={`0 0 ${width} ${height}`}
              role="img"
              aria-label="Process correlation graph"
            >

              {edges.map((edge) => {
                const parentPosition =
                  positions.get(
                    edge.parent.pid
                  );

                const childPosition =
                  positions.get(
                    edge.child.pid
                  );

                if (
                  !parentPosition ||
                  !childPosition
                ) {
                  return null;
                }

                return (
                  <path
                    key={`${edge.parent.pid}-${edge.child.pid}`}
                    d={`
                      M ${parentPosition.x}
                        ${parentPosition.y}
                      C ${parentPosition.x}
                        ${parentPosition.y + 45},
                        ${childPosition.x}
                        ${childPosition.y - 45},
                        ${childPosition.x}
                        ${childPosition.y}
                    `}
                    fill="none"
                    stroke="#243149"
                    strokeWidth="1.4"
                  />
                );
              })}


              {nodes.map((node) => {
                const position =
                  positions.get(
                    node.pid
                  );

                if (!position) {
                  return null;
                }

                const severity =
                  severityForProcess(
                    node.pid,
                    alerts
                  );

                return (
                  <ProcessNode
                    key={node.pid}
                    node={node}
                    position={position}
                    severity={severity}
                    selected={
                      selected?.pid ===
                      node.pid
                    }
                    onSelect={setSelected}
                  />
                );
              })}
            </svg>
          )}
        </section>


        <aside
          style={{
            display: "grid",
            gap: "14px",
          }}
        >

          <section
            style={{
              border:
                "1px solid #243149",
              borderRadius: "9px",
              padding: "16px",
              background:
                "rgba(17,26,43,0.62)",
            }}
          >
            <div
              style={{
                color: "#7e8aa0",
                fontFamily:
                  "JetBrains Mono, monospace",
                fontSize: "10px",
                letterSpacing: "2px",
                marginBottom: "14px",
              }}
            >
              LEGEND
            </div>

            {[
              ["critical", "critical alert"],
              ["high", "high alert"],
              ["medium", "medium alert"],
              ["low", "low alert"],
            ].map(
              ([severity, label]) => (
                <div
                  key={severity}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    marginBottom: "10px",
                    fontSize: "12px",
                  }}
                >
                  <span
                    style={{
                      width: "9px",
                      height: "9px",
                      borderRadius: "50%",
                      background:
                        SEVERITY[
                          severity
                        ].color,
                      boxShadow:
                        `0 0 8px ${SEVERITY[severity].glow}`,
                    }}
                  />

                  <span
                    style={{
                      color: "#7e8aa0",
                      fontFamily:
                        "JetBrains Mono, monospace",
                    }}
                  >
                    {label}
                  </span>
                </div>
              )
            )}

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginTop: "14px",
                marginBottom: "10px",
                fontSize: "12px",
              }}
            >
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  border:
                    "1px dashed #ff5d5d",
                }}
              />

              <span
                style={{
                  color: "#7e8aa0",
                  fontFamily:
                    "JetBrains Mono, monospace",
                }}
              >
                runs as root
              </span>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                fontSize: "12px",
              }}
            >
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  border:
                    "1px solid #243149",
                }}
              />

              <span
                style={{
                  color: "#7e8aa0",
                  fontFamily:
                    "JetBrains Mono, monospace",
                }}
              >
                clean process
              </span>
            </div>
          </section>


          <section
            style={{
              border:
                "1px solid #243149",
              borderRadius: "9px",
              padding: "16px",
              background:
                "rgba(17,26,43,0.62)",
            }}
          >
            {!selected ? (
              <div
                style={{
                  color: "#7e8aa0",
                  fontFamily:
                    "JetBrains Mono, monospace",
                  fontSize: "12px",
                  lineHeight: 1.7,
                }}
              >
                click a node to inspect
                its process and alerts
              </div>
            ) : (
              <>
                <div
                  style={{
                    color: "#4fd1c5",
                    fontFamily:
                      "JetBrains Mono, monospace",
                    fontSize: "10px",
                    letterSpacing: "1.5px",
                    marginBottom: "12px",
                  }}
                >
                  PROCESS DETAIL
                </div>

                <div
                  style={{
                    fontFamily:
                      "JetBrains Mono, monospace",
                    fontSize: "12px",
                    lineHeight: 1.9,
                  }}
                >
                  <div>
                    PID: {selected.pid}
                  </div>

                  <div>
                    PPID:{" "}
                    {selected.ppid ??
                      "—"}
                  </div>

                  <div>
                    COMM: {selected.comm}
                  </div>

                  <div>
                    UID: {selected.uid}
                  </div>

                  <div>
                    DEPTH:{" "}
                    {selected.depth}
                  </div>

                  <div>
                    LIFETIME:{" "}
                    {selected.lifetime_s}s
                  </div>

                  <div
                    style={{
                      color:
                        selected.ran_as_root
                          ? "#ff5d5d"
                          : "#39c2b0",
                    }}
                  >
                    ROOT:{" "}
                    {selected.ran_as_root
                      ? "yes"
                      : "no"}
                      <div
  style={{
    marginTop: "14px",
    paddingTop: "12px",
    borderTop: "1px solid #243149",
  }}
>
  <div
    style={{
      color: "#e6edf6",
      fontSize: "11px",
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      marginBottom: "8px",
    }}
  >
    Alerts
  </div>

  {alerts.filter(
    (alert) =>
      Number(alert.pid) === Number(selected.pid)
  ).length === 0 ? (
    <div
      style={{
        color: "#7e8aa0",
      }}
    >
      No alerts for this process.
    </div>
  ) : (
    alerts
      .filter(
        (alert) =>
          Number(alert.pid) ===
          Number(selected.pid)
      )
      .map((alert, index) => (
        <div
          key={`${alert.rule}-${alert.ts}-${index}`}
          style={{
            padding: "9px 0",
            borderBottom:
              "1px solid rgba(36,49,73,0.7)",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: "12px",
            }}
          >
            <span
              style={{
                color:
                  alert.severity === "critical"
                    ? "#ff5d5d"
                    : alert.severity === "high"
                    ? "#f2a65a"
                    : alert.severity === "medium"
                    ? "#e8c34a"
                    : "#39c2b0",
              }}
            >
              {alert.severity}
            </span>

            <span
              style={{
                color: "#7e8aa0",
              }}
            >
              {alert.rule}
            </span>
          </div>

          <div
            style={{
              color: "#e6edf6",
              marginTop: "3px",
            }}
          >
            {alert.summary}
          </div>

          {alert.technique && (
            <div
              style={{
                color: "#7c8cf8",
                marginTop: "3px",
              }}
            >
              {alert.technique}
            </div>
          )}
        </div>
      ))
  )}
</div>
                  </div>
                </div>
              </>
            )}
          </section>


          <section
            style={{
              border:
                "1px solid #243149",
              borderRadius: "9px",
              padding: "16px",
              background:
                "rgba(17,26,43,0.62)",
              fontFamily:
                "JetBrains Mono, monospace",
              fontSize: "11px",
              lineHeight: 1.8,
              color: "#7e8aa0",
            }}
          >
            <div>
              {nodes.length} processes
            </div>

            <div>
              {tree.roots.length} root nodes
            </div>

            <div>
              {alerts.length} alerts loaded
            </div>

            <div>
              live refresh: 5s
            </div>
          </section>

        </aside>
      </div>
    </main>
  );
}