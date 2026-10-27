import StatCard from "../components/StatCard";
import { api, usePoll } from "../api";

// Full class strings so Tailwind can find them when it scans this file.
const SEVERITY_CHIP = {
  critical: "border-critical/50 bg-critical/10 text-critical",
  high: "border-high/50 bg-high/10 text-high",
  medium: "border-medium/50 bg-medium/10 text-medium",
  low: "border-low/50 bg-low/10 text-low",
};

// ts from the sensor is kernel monotonic seconds since boot.
// The contract forbids turning it into a wall clock time, so show it as is.
function formatKts(ts) {
  return typeof ts === "number" ? ts.toFixed(3) : "-";
}

function Overview() {
  const { data: health } = usePoll(api.health, 4000);
  const { data: ev } = usePoll(() => api.events(60), 2500);
  const { data: al } = usePoll(api.alerts, 3000);
  const { data: an } = usePoll(api.anomaly, 4000);

  const counts = health?.counts || {};
  const events = ev?.events || [];
  const alerts = al?.alerts || [];
  const anomalies = an?.anomaly_count ?? 0;

  return (
    <div className="flex flex-col gap-3">
      <div className="page-header">
        <h1>Overview</h1>
        <p>
          Live host telemetry from the eBPF sensor, scored by rules and the ML
          anomaly model.
        </p>
      </div>

      <div className="grid grid-cols-5 gap-3">
        <StatCard label="Events" value={counts.events ?? 0} tone="signal" />
        <StatCard label="Processes" value={counts.processes ?? 0} />
        <StatCard label="Alerts" value={counts.alerts ?? 0} tone="high" />
        <StatCard label="Incidents" value={counts.incidents ?? 0} tone="critical" />
        <StatCard label="Anomalies" value={anomalies} tone="ml" />
      </div>

      <div className="grid grid-cols-5 gap-3">
        <section className="col-span-3 flex flex-col overflow-hidden rounded-lg border border-line bg-ink-800">
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <span className="eyebrow">Event tape · live kernel stream</span>
            <span className="font-mono text-[11px] text-mute">
              ts = seconds since boot
            </span>
          </header>

          <div className="h-[calc(100vh-318px)] min-h-[280px] overflow-y-auto py-1">
            {events.length === 0 ? (
              <div className="px-4 py-6 text-center font-mono text-xs text-mute">
                No events yet
              </div>
            ) : (
              events.map((event, index) => (
                <div
                  key={`${event.ts}-${event.pid}-${index}`}
                  className="flex h-[22px] items-center gap-3 px-4 font-mono text-[11.5px] hover:bg-ink-700"
                >
                  <span className="w-[104px] shrink-0 whitespace-nowrap text-right tabular-nums text-mute">
                    {formatKts(event.ts)}
                  </span>
                  <span className="w-[112px] shrink-0 truncate font-semibold text-text">
                    {event.type || "?"}
                  </span>
                  <span className="min-w-0 truncate text-mute">
                    pid {event.pid ?? "-"}
                    <span className="mx-1.5 opacity-50">·</span>
                    <span className="text-text/80">{event.comm || "-"}</span>
                    {event.detail ? (
                      <>
                        <span className="mx-1.5 opacity-50">·</span>
                        {event.detail}
                      </>
                    ) : null}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="col-span-2 flex flex-col overflow-hidden rounded-lg border border-line bg-ink-800">
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <span className="eyebrow">Latest alerts</span>
            <span className="font-mono text-[11px] text-mute">
              {alerts.length}
            </span>
          </header>

          <div className="h-[calc(100vh-318px)] min-h-[280px] overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="px-4 py-6 text-center font-mono text-xs text-mute">
                No alerts
              </div>
            ) : (
              alerts.slice(0, 30).map((alert, index) => {
                const severity = String(alert.severity || "low").toLowerCase();

                return (
                  <div
                    key={`${alert.ts}-${alert.rule}-${index}`}
                    className="flex gap-3 border-b border-line/50 px-4 py-2.5"
                  >
                    <span
                      className={`mt-px h-[18px] shrink-0 rounded border px-1.5 font-mono text-[10px] leading-4 ${
                        SEVERITY_CHIP[severity] || SEVERITY_CHIP.low
                      }`}
                    >
                      {severity}
                    </span>

                    <div className="min-w-0">
                      <div className="text-[12.5px] leading-snug text-text">
                        <span className="mr-2 font-mono text-signal">
                          {alert.rule}
                        </span>
                        {alert.summary}
                      </div>
                      <div className="mt-1 font-mono text-[10.5px] text-mute">
                        pid {alert.pid ?? "-"} · {alert.comm || "-"}
                        {alert.technique ? ` · ${alert.technique}` : ""}
                        {alert.confidence != null ? ` · conf ${alert.confidence}` : ""}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

export default Overview;
