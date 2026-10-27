
import { usePoll } from "../api";
import { api } from "../api";

function MetricCard({
  label,
  value,
  detail,
  valueClass = "text-text",
}) {
  return (
    <section className="panel min-w-0 p-4">
      <p className="eyebrow">{label}</p>

      <p className={`stat-num mt-2 break-words text-3xl ${valueClass}`}>
        {value}
      </p>

      {detail && (
        <p className="mt-1 text-xs text-mute">{detail}</p>
      )}
    </section>
  );
}

function BarRow({ label, width, color, count }) {
  return (
    <div className="grid grid-cols-[88px_minmax(0,1fr)_24px] items-center gap-3">
      <span className="truncate font-mono text-xs text-mute">
        {label}
      </span>

      <div className="h-2 overflow-hidden rounded-full bg-ink-600">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width }}
        />
      </div>

      <span className="text-right font-mono text-xs text-mute">
        {count ?? "—"}
      </span>
    </div>
  );
}

export default function Analytics() {
  const { data: health, error } = usePoll(api.health, 3000);

  const counts = health?.counts ?? {};
  const loading = !health && !error;

  function displayValue(value) {
    if (typeof value !== "number") {
      return loading ? "…" : "—";
    }

    return value.toLocaleString("en-US");
  }

  return (
    <main className="min-h-full space-y-5 p-4 text-text sm:p-6">
      <header>
        <h1 className="font-display text-2xl font-semibold">
          Analytics
        </h1>

        <p className="mt-2 max-w-4xl text-sm leading-6 text-mute">
          Detection metrics from the system health API. Detailed
          rule-level, ML-level and MITRE technique data may require
          additional API endpoints.
        </p>

        {error && (
          <p role="alert" className="mt-2 text-sm text-red-400">
            Analytics metrics could not be loaded. Check the health API.
          </p>
        )}
      </header>

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="EVENTS PROCESSED"
          value={displayValue(counts.events)}
        />

        <MetricCard
          label="ALERTS RAISED"
          value={displayValue(counts.alerts)}
          valueClass="text-orange-300"
        />

        <MetricCard
          label="INCIDENTS"
          value={displayValue(counts.incidents)}
          valueClass="text-red-400"
        />

        <MetricCard
          label="MITRE COVERAGE"
          value="—"
          detail="Coverage data unavailable"
          valueClass="text-indigo-400"
        />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="panel min-w-0 p-4 sm:p-5">
          <p className="eyebrow">
            RULE ENGINE VS ML ANOMALY
          </p>

          <div className="mt-5 space-y-4">
            <BarRow
              label="rule alerts"
              width="12%"
              color="bg-signal"
              count={null}
            />

            <BarRow
              label="ml alerts"
              width="100%"
              color="bg-indigo-400"
              count={null}
            />
          </div>

          <p className="mt-5 font-mono text-[10px] leading-5 text-mute">
            Separate rule and ML alert counts are not available from
            the health API.
          </p>
        </div>

        <div className="panel min-w-0 p-4 sm:p-5">
          <p className="eyebrow">ALERTS BY TECHNIQUE</p>

          <div className="mt-5 space-y-4">
            <BarRow
              label="ML-ANOM"
              width="100%"
              color="bg-orange-400"
              count={null}
            />

            <BarRow
              label="Technique"
              width="12%"
              color="bg-orange-400"
              count={null}
            />
          </div>

          <p className="mt-5 font-mono text-[10px] leading-5 text-mute">
            Technique-level alert counts are not available from the
            current health API.
          </p>
        </div>
      </section>

      <section className="space-y-4">
        <p className="eyebrow">
          MITRE ATT&CK COVERAGE · THIS RUN
        </p>

        <div className="panel px-4 py-6">
          <p className="text-sm text-mute">
            MITRE ATT&CK technique coverage data is not available
            from the current health API.
          </p>
        </div>
      </section>

      <p className="text-xs text-mute">
        DATA SOURCE: /api/health · Detailed analytics API not connected
      </p>
    </main>
  );
}
