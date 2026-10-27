import { useMemo, useState } from "react";
import { incidentsMock } from "../mock";
import { api } from "../api";

const severityStyles = {
  critical: {
    text: "text-critical",
    border: "border-critical",
    bg: "bg-critical",
    soft: "bg-critical/10",
  },
  high: {
    text: "text-high",
    border: "border-high",
    bg: "bg-high",
    soft: "bg-high/10",
  },
  medium: {
    text: "text-medium",
    border: "border-medium",
    bg: "bg-medium",
    soft: "bg-medium/10",
  },
  low: {
    text: "text-low",
    border: "border-low",
    bg: "bg-low",
    soft: "bg-low/10",
  },
};

const statusStyles = {
  open: "text-signal border-signal/40 bg-signal/5",
  investigating:
    "text-high border-high/40 bg-high/5",
  resolved:
    "text-low border-low/40 bg-low/5",
  false_positive:
    "text-mute border-line bg-ink-700",
};

function formatAge(ts) {
  const seconds = Math.max(
    0,
    Math.floor(Date.now() / 1000) - ts
  );

  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m ago`;
  }

  return `${Math.floor(seconds / 3600)}h ago`;
}

function Incidents() {
  const incidents = incidentsMock.incidents;

  const [selectedId, setSelectedId] = useState(null);

  const [statusMessage, setStatusMessage] = useState("");
  const [statusError, setStatusError] = useState("");
  const [statusUpdating, setStatusUpdating] =
    useState(false);

  const selectedIncident = useMemo(
    () =>
      incidents.find(
        (incident) => incident.id === selectedId
      ),
    [incidents, selectedId]
  );

  const selectIncident = (id) => {
    if (selectedId === id) {
      setSelectedId(null);
    } else {
      setSelectedId(id);
    }

    setStatusMessage("");
    setStatusError("");
  };

  const changeStatus = async (status) => {
    if (!selectedIncident || statusUpdating) {
      return;
    }

    setStatusMessage("");
    setStatusError("");
    setStatusUpdating(true);

    try {
      await api.setStatus(
        selectedIncident.id,
        status,
        `Status changed to ${status}`
      );

      setStatusMessage(
        `Status updated to ${status}`
      );
    } catch (error) {
      if (error?.unauth) {
        setStatusError(
          "Authentication required"
        );
      } else {
        setStatusError(
          error?.error ||
            error?.message ||
            "Status update failed"
        );
      }
    } finally {
      setStatusUpdating(false);
    }
  };

  return (
    <main className="page-shell">
      <section className="page-header">
        <div className="eyebrow">
          INCIDENT RESPONSE
        </div>

        <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1>Incidents</h1>

            <p className="mt-1">
              Correlated alerts grouped into analyst
              cases.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-mute">
            <span className="h-2 w-2 rounded-full bg-signal" />

            {incidents.length} active cases
          </div>
        </div>
      </section>

      <section className="grid items-start grid-cols-1 gap-4 xl:grid-cols-[380px_minmax(0,1fr)]">
        <div className="panel min-w-0 overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <div>
              <div className="font-mono text-[11px] font-semibold tracking-[0.16em]">
                INCIDENT QUEUE
              </div>

              <div className="mt-1 text-xs text-mute">
                Select a case to investigate
              </div>
            </div>

            <div className="rounded border border-line bg-ink-700 px-2 py-1 font-mono text-[10px] text-signal">
              {incidents.length}
            </div>
          </div>

          <div>
            {incidents.map((incident) => {
              const severity =
                severityStyles[incident.severity] ||
                severityStyles.low;

              const selected =
                selectedId === incident.id;

              const statusClass =
                statusStyles[incident.status] ||
                statusStyles.open;

              return (
                <button
                  key={incident.id}
                  type="button"
                  onClick={() =>
                    selectIncident(incident.id)
                  }
                  className={`grid w-full grid-cols-[4px_minmax(0,1fr)] border-b border-line text-left transition-colors last:border-b-0 ${
                    selected
                      ? "bg-ink-700"
                      : "bg-ink-800/30 hover:bg-ink-700/70"
                  }`}
                >
                  <span
                    className={`min-h-[112px] ${severity.bg}`}
                  />

                  <span className="min-w-0 px-4 py-4">
                    <span className="flex items-start justify-between gap-3">
                      <span className="min-w-0">
                        <span
                          className={`block truncate text-sm font-semibold ${
                            selected
                              ? "text-text"
                              : "text-text/90"
                          }`}
                        >
                          {incident.title}
                        </span>

                        <span className="mt-1 block font-mono text-[10px] text-mute">
                          CASE #{incident.id}
                        </span>
                      </span>

                      <span
                        className={`shrink-0 rounded border px-2 py-1 font-mono text-[9px] font-semibold uppercase ${severity.text} ${severity.border} ${severity.soft}`}
                      >
                        {incident.severity}
                      </span>
                    </span>

                    <span className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-[10px] text-mute">
                      <span>
                        PID {incident.root_pid}
                      </span>

                      <span>
                        {incident.root_comm}
                      </span>

                      <span>
                        {incident.alert_count} alerts
                      </span>

                      <span>
                        {formatAge(incident.last_seen)}
                      </span>
                    </span>

                    <span className="mt-3">
                      <span
                        className={`inline-flex rounded border px-2 py-1 font-mono text-[9px] uppercase ${statusClass}`}
                      >
                        {incident.status}
                      </span>
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="panel min-w-0 overflow-hidden">
          {!selectedIncident ? (
            <div className="flex min-h-[420px] flex-col items-center justify-center px-6 text-center">
              <div className="grid h-12 w-12 place-items-center rounded-full border border-line bg-ink-800 font-mono text-lg text-mute">
                !
              </div>

              <div className="mt-4 font-mono text-[11px] font-semibold tracking-[0.18em] text-text">
                SELECT AN INCIDENT
              </div>

              <p className="mt-2 max-w-sm text-xs leading-5 text-mute">
                Choose a case from the incident queue
                to view its alerts and response details.
              </p>
            </div>
          ) : (
            <>
              <div className="border-b border-line px-5 py-4">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="eyebrow">
                      CASE #{selectedIncident.id}
                    </div>

                    <h2 className="mt-2 text-xl font-semibold leading-7">
                      {selectedIncident.title}
                    </h2>

                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-mute">
                      <span>
                        root:{" "}
                        {selectedIncident.root_comm}
                      </span>

                      <span>
                        pid:{" "}
                        {selectedIncident.root_pid}
                      </span>

                      <span>
                        alerts:{" "}
                        {selectedIncident.alert_count}
                      </span>

                      <span>
                        last seen:{" "}
                        {formatAge(
                          selectedIncident.last_seen
                        )}
                      </span>
                    </div>
                  </div>

                  <span
                    className={`shrink-0 rounded border px-2 py-1 font-mono text-[9px] font-semibold uppercase ${
                      (
                        severityStyles[
                          selectedIncident.severity
                        ] || severityStyles.low
                      ).text
                    } ${
                      (
                        severityStyles[
                          selectedIncident.severity
                        ] || severityStyles.low
                      ).border
                    }`}
                  >
                    {selectedIncident.severity}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-px border-b border-line bg-line md:grid-cols-4">
                <div className="bg-ink-800 px-4 py-3">
                  <span className="block font-mono text-[9px] uppercase tracking-wider text-mute">
                    ROOT PROCESS
                  </span>

                  <strong className="mt-1 block truncate font-mono text-xs">
                    {selectedIncident.root_comm}
                  </strong>
                </div>

                <div className="bg-ink-800 px-4 py-3">
                  <span className="block font-mono text-[9px] uppercase tracking-wider text-mute">
                    PID
                  </span>

                  <strong className="mt-1 block font-mono text-xs">
                    {selectedIncident.root_pid}
                  </strong>
                </div>

                <div className="bg-ink-800 px-4 py-3">
                  <span className="block font-mono text-[9px] uppercase tracking-wider text-mute">
                    STATUS
                  </span>

                  <strong className="mt-1 block font-mono text-xs uppercase">
                    {selectedIncident.status}
                  </strong>
                </div>

                <div className="bg-ink-800 px-4 py-3">
                  <span className="block font-mono text-[9px] uppercase tracking-wider text-mute">
                    ALERTS
                  </span>

                  <strong className="mt-1 block font-mono text-xs">
                    {selectedIncident.alert_count}
                  </strong>
                </div>
              </div>

              <div className="border-b border-line p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-[11px] font-semibold tracking-[0.16em]">
                      CASE STATUS
                    </div>

                    <div className="mt-1 text-xs text-mute">
                      Update the server-side incident state
                    </div>
                  </div>

                  <span
                    className={`rounded border px-2 py-1 font-mono text-[9px] uppercase ${
                      statusStyles[
                        selectedIncident.status
                      ] || statusStyles.open
                    }`}
                  >
                    {selectedIncident.status}
                  </span>
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  {[
                    "open",
                    "investigating",
                    "resolved",
                    "false_positive",
                  ].map((status) => {
                    const active =
                      selectedIncident.status ===
                      status;

                    return (
                      <button
                        key={status}
                        type="button"
                        disabled={statusUpdating}
                        onClick={() =>
                          changeStatus(status)
                        }
                        className={`rounded border px-3 py-2 font-mono text-[9px] uppercase transition-colors ${
                          active
                            ? "border-signal bg-signal/10 text-signal"
                            : "border-line bg-ink-700 text-mute hover:border-signal hover:text-signal"
                        } disabled:cursor-not-allowed disabled:opacity-50`}
                      >
                        {status}
                      </button>
                    );
                  })}
                </div>

                {statusMessage && (
                  <div className="mt-2 font-mono text-[10px] text-signal">
                    {statusMessage}
                  </div>
                )}

                {statusError && (
                  <div className="mt-2 font-mono text-[10px] text-critical">
                    {statusError}
                  </div>
                )}
              </div>

              <div className="p-4">
                <div className="mb-4 flex items-end justify-between gap-4">
                  <div>
                    <div className="font-mono text-[11px] font-semibold tracking-[0.16em]">
                      ALERT TIMELINE
                    </div>

                    <div className="mt-1 text-xs text-mute">
                      Alerts correlated into this case
                    </div>
                  </div>

                  <span className="font-mono text-[10px] text-mute">
                    {selectedIncident.alert_count} events
                  </span>
                </div>

                <div className="space-y-3">
                  {selectedIncident.alerts.map(
                    (alert, index) => {
                      const severity =
                        severityStyles[
                          alert.severity
                        ] || severityStyles.low;

                      return (
                        <div
                          key={`${alert.rule}-${index}`}
                          className="grid grid-cols-[10px_minmax(0,1fr)] gap-3"
                        >
                          <div className="relative flex justify-center">
                            <span
                              className={`mt-2 h-2.5 w-2.5 rounded-full border-2 ${severity.border} bg-ink`}
                            />

                            {index <
                              selectedIncident.alerts
                                .length -
                                1 && (
                              <span className="absolute top-5 bottom-[-12px] w-px bg-line" />
                            )}
                          </div>

                          <div className="rounded border border-line bg-ink-800/80">
                            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
                              <div>
                                <div className="font-mono text-[10px] text-signal">
                                  {alert.rule}
                                </div>

                                <h3 className="mt-1 text-sm font-semibold">
                                  {alert.summary}
                                </h3>
                              </div>

                              <span
                                className={`rounded border px-2 py-1 font-mono text-[9px] uppercase ${severity.text} ${severity.border}`}
                              >
                                {alert.severity}
                              </span>
                            </div>

                            <div className="grid grid-cols-2 gap-px bg-line md:grid-cols-4">
                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  PID
                                </span>

                                <strong className="mt-1 block font-mono text-[10px]">
                                  {alert.pid}
                                </strong>
                              </div>

                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  PROCESS
                                </span>

                                <strong className="mt-1 block font-mono text-[10px]">
                                  {alert.comm}
                                </strong>
                              </div>

                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  TECHNIQUE
                                </span>

                                <strong className="mt-1 block font-mono text-[10px]">
                                  {alert.technique}
                                </strong>
                              </div>

                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  CONFIDENCE
                                </span>

                                <strong className="mt-1 block font-mono text-[10px]">
                                  {Math.round(
                                    alert.confidence * 100
                                  )}
                                  %
                                </strong>
                              </div>
                            </div>

                            <div className="grid gap-px bg-line md:grid-cols-3">
                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  EVENT
                                </span>

                                <strong className="mt-1 block font-mono text-[10px]">
                                  {alert.detail.event}
                                </strong>
                              </div>

                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  TACTIC
                                </span>

                                <strong className="mt-1 block text-[10px]">
                                  {alert.detail.tactic}
                                </strong>
                              </div>

                              <div className="bg-ink-800 px-4 py-3">
                                <span className="block font-mono text-[9px] uppercase text-mute">
                                  TECHNIQUE
                                </span>

                                <strong className="mt-1 block text-[10px]">
                                  {alert.detail.technique}
                                </strong>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </section>
    </main>
  );
}

export default Incidents;