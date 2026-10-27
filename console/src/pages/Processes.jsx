import { useEffect, useState } from "react";


function Processes() {
  const [processes, setProcesses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  async function loadProcesses() {
    try {
      setError("");

      const response = await fetch("/api/processes");

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      setProcesses(data.processes || []);
    } catch (err) {
      console.error("Failed to load processes:", err);
      setError("Could not load process data from /api/processes.");
    } finally {
      setLoading(false);
    }
  }


  useEffect(() => {
    loadProcesses();

    const timer = setInterval(() => {
      loadProcesses();
    }, 5000);

    return () => {
      clearInterval(timer);
    };
  }, []);


  function getCommand(process) {
    return process.comm ?? process.name ?? "—";
  }


  function getUid(process) {
    return process.uid ?? process.user ?? "—";
  }


  function getRootStatus(process) {
    if (typeof process.ran_as_root === "boolean") {
      return process.ran_as_root ? "ROOT" : "USER";
    }

    if (process.user === "root") {
      return "ROOT";
    }

    if (process.user) {
      return "USER";
    }

    return "—";
  }


  function getRootColor(process) {
    const status = getRootStatus(process);

    if (status === "ROOT") {
      return "#ff5d5d";
    }

    if (status === "USER") {
      return "#39c2b0";
    }

    return "#7e8aa0";
  }


  function formatNumber(value) {
    if (value === undefined || value === null) {
      return "—";
    }

    return value;
  }


  function formatLifetime(value) {
    if (value === undefined || value === null) {
      return "—";
    }

    return `${Number(value).toFixed(1)}s`;
  }


  const headerStyle = {
    padding: "13px 16px",
    textAlign: "left",
    color: "#7e8aa0",
    fontSize: "11px",
    fontWeight: 700,
    letterSpacing: "0.08em",
    whiteSpace: "nowrap",
    borderBottom: "1px solid #243149",
    background: "#111a2b",
  };


  const cellStyle = {
    padding: "14px 16px",
    color: "#e6edf6",
    borderBottom: "1px solid #1d2c49",
    whiteSpace: "nowrap",
    verticalAlign: "middle",
  };


  const monoCellStyle = {
    ...cellStyle,
    fontFamily: "JetBrains Mono, monospace",
  };


  return (
    <main className="page-shell">

      <div
        className="panel"
        style={{
          padding: "22px",
        }}
      >

        <div className="panel-eyebrow">
          PROCESS MONITOR
        </div>


        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            marginBottom: "22px",
            gap: "20px",
          }}
        >

          <div>
            <h1
              style={{
                marginBottom: "6px",
              }}
            >
              Processes
            </h1>

            <p
              style={{
                margin: 0,
                color: "#7e8aa0",
              }}
            >
              Live process activity collected by the HIDS sensor.
            </p>
          </div>


          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "7px 11px",
              border: "1px solid #243149",
              borderRadius: "6px",
              background: "#0d1422",
              color: "#7e8aa0",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "11px",
              whiteSpace: "nowrap",
            }}
          >

            <span
              style={{
                width: "7px",
                height: "7px",
                borderRadius: "50%",
                background: "#39c2b0",
                boxShadow: "0 0 8px rgba(57, 194, 176, 0.7)",
              }}
            />

            LIVE

            <span
              style={{
                color: "#e6edf6",
              }}
            >
              {processes.length}
            </span>

            PROCESSES

          </div>

        </div>


        {loading && (
          <div
            style={{
              padding: "40px",
              textAlign: "center",
              color: "#7e8aa0",
              fontFamily: "JetBrains Mono, monospace",
              border: "1px solid #243149",
              borderRadius: "8px",
            }}
          >
            Loading process data...
          </div>
        )}


        {!loading && error && (
          <div
            style={{
              padding: "24px",
              color: "#ff5d5d",
              background: "rgba(255, 93, 93, 0.06)",
              border: "1px solid rgba(255, 93, 93, 0.25)",
              borderRadius: "8px",
              fontFamily: "JetBrains Mono, monospace",
            }}
          >
            {error}
          </div>
        )}


        {!loading && !error && (
          <div
            style={{
              overflowX: "auto",
              border: "1px solid #243149",
              borderRadius: "8px",
              background: "#0d1422",
            }}
          >

            <table
              style={{
                width: "100%",
                minWidth: "1200px",
                borderCollapse: "separate",
                borderSpacing: 0,
                fontFamily: "Inter, sans-serif",
                fontSize: "12px",
              }}
            >

              <thead>
                <tr>
                  <th style={headerStyle}>PID</th>
                  <th style={headerStyle}>PPID</th>
                  <th style={headerStyle}>COMMAND</th>
                  <th style={headerStyle}>UID</th>
                  <th style={headerStyle}>EXEC</th>
                  <th style={headerStyle}>CONNECT</th>
                  <th style={headerStyle}>FILE WRITE</th>
                  <th style={headerStyle}>PTRACE</th>
                  <th style={headerStyle}>SETUID</th>
                  <th style={headerStyle}>DEPTH</th>
                  <th style={headerStyle}>LIFETIME</th>
                  <th style={headerStyle}>ROOT</th>
                </tr>
              </thead>


              <tbody>

                {processes.length === 0 ? (
                  <tr>
                    <td
                      colSpan="12"
                      style={{
                        padding: "40px",
                        textAlign: "center",
                        color: "#7e8aa0",
                      }}
                    >
                      No process data available.
                    </td>
                  </tr>
                ) : (
                  processes.map((process) => (
                    <tr key={process.pid}>

                      <td style={monoCellStyle}>
                        {formatNumber(process.pid)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.ppid)}
                      </td>

                      <td
                        style={{
                          ...monoCellStyle,
                          color: "#e6edf6",
                          fontWeight: 600,
                        }}
                      >
                        {getCommand(process)}
                      </td>

                      <td style={monoCellStyle}>
                        {getUid(process)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.exec_count)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.connect_count)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.file_write_count)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.ptrace_count)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.setuid_count)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatNumber(process.depth)}
                      </td>

                      <td style={monoCellStyle}>
                        {formatLifetime(process.lifetime_s)}
                      </td>

                      <td style={monoCellStyle}>
                        <span
                          style={{
                            color: getRootColor(process),
                            fontWeight: 700,
                          }}
                        >
                          {getRootStatus(process)}
                        </span>
                      </td>

                    </tr>
                  ))
                )}

              </tbody>

            </table>

          </div>
        )}

      </div>

    </main>
  );
}


export default Processes;