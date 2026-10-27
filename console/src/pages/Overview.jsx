import Panel from "../components/Panel";
import StatCard from "../components/StatCard";
import { api, usePoll } from "../api";

function Overview() {

  const { data: health } = usePoll(api.health, 4000);
  const { data: ev } = usePoll(() => api.events(60), 2500);
  const { data: al } = usePoll(api.alerts, 3000);
  const { data: an } = usePoll(api.anomaly, 4000);

  const counts = health?.counts || {};
  const events = ev?.events || [];
  const alerts = al?.alerts || [];
  const anomalies = an?.anomaly_count ?? 0 ;

  return (

    <div className="flex flex-col gap-2">

      <div className="page-header">

        <h1>
          Overview
        </h1>

        <p>
          Live host telemetry from the eBPF sensor,
          scored by rules and the ML anomaly model.
        </p>

      </div>

      <Panel title="">

        {/* ===== Statistics ===== */}

        <div className="grid grid-cols-5 gap-4">

          <StatCard
            label="EVENTS"
            value={counts.events ?? 0}
          />

          <StatCard
            label="PROCESSES"
            value={counts.processes ?? 0}
          />

          <StatCard
            label="ALERTS"
            value={counts.alerts ?? 0}
          />

          <StatCard
            label="INCIDENTS"
            value={counts.incidents ?? 0}
          />

          <StatCard
            label="ANOMALIES"
            value={anomalies}
          />

        </div>

        {/* ===== Live Events + Latest Alerts ===== */}

        <div className="mt-6 grid grid-cols-3 gap-6">

          {/* ---------- Live Events ---------- */}

          <div className="col-span-2">

            <div className="panel overflow-hidden">

              <div className="px-4 py-3 border-b border-line flex justify-between items-center">

                <span className="eyebrow">
                  LIVE EVENTS
                </span>

                <span className="text-xs text-mute">
                  {events.length} Events
                </span>

              </div>

              <div className="max-h-[380px] overflow-y-auto">

                {events.length === 0 ? (

                  <div className="p-6 text-center text-mute">
                    No Live Events
                  </div>

                ) : (

                  events.slice(0, 20).map((event, index) => (

                    <div
                      key={event.id ?? index}
                      className="px-4 py-4 border-b border-line/40"
                    >

                      <div className="flex justify-between items-start">

                        <div>

                          <div className="font-medium">
                            {event.type || "Unknown Event"}
                          </div>

                          <div className="text-xs text-mute mt-2">
                            PID : {event.pid ?? "-"}
                          </div>

                          <div className="text-xs text-mute mt-1">
                              {event.comm ?? "-"}
                          </div>

                          <div className="text-xs text-mute mt-1">
                            {event.detail || event.path || "-"}
                          </div>

                        </div>

                        <div className="text-xs text-mute">
                          {event.ts
                             ? new Date(event.ts * 1000).toLocaleTimeString([], {
                                  hour: "2-digit",
                                  minute: "2-digit",
                                  second: "2-digit",
                                })
                              : "--:--:--"}
                          </div>

                      </div>

                    </div>

                  ))

                )}

              </div>

            </div>

          </div>

          {/* ---------- Latest Alerts ---------- */}

          <div>

            <div className="panel overflow-hidden">

              <div className="px-4 py-3 border-b border-line">

                <span className="eyebrow">
                  LATEST ALERTS
                </span>

              </div>

              <div className="max-h-[380px] overflow-y-auto">

                {alerts.length === 0 ? (

                  <div className="p-6 text-center text-mute">
                    No Alerts
                  </div>

                ) : (

                  alerts.slice(0, 8).map((alert, index) => (

                    <div
                      key={alert.id ?? index}
                      className="px-4 py-3 border-b border-line/40"
                    >

                      <div className="flex items-center">

                        <div className="flex-1">

                          <span className="font-medium">
                            {alert.rule || alert.type || "Unknown Alert"}
                          </span>

                        </div>

                        <div className="severity-wrapper">

                          <span
                            className={`severity ${String(alert.severity || "info").toLowerCase()}`}
                          >
                            {alert.severity || "INFO"}
                          </span>

                        </div>

                      </div>

                      <div className="text-xs text-mute mt-2">
                        {alert.comm || "-"}
                      </div>

                      <div className="text-xs text-mute mt-1 opacity-80">
                        {alert.summary || "-"}
                      </div>

                    </div>

                  ))

                )}

              </div>

            </div>

          </div>

        </div>

      </Panel>

    </div>

  );

}

export default Overview;