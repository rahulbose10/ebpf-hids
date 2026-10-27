
import { useMemo } from "react";
import { api, usePoll } from "../api";

function StatCard({ label, value, detail, color = "text-text" }) {
  return (
    <section className="panel min-w-0 p-4">
      <p className="eyebrow">{label}</p>
      <p className={`stat-num mt-3 text-2xl ${color}`}>{value}</p>
      {detail && <p className="mt-1 text-xs text-mute">{detail}</p>}
    </section>
  );
}

function getTechniques(data) {
  if (Array.isArray(data?.techniques)) return data.techniques;
  if (Array.isArray(data?.coverage)) return data.coverage;
  if (Array.isArray(data?.matrix)) return data.matrix;

  if (data?.by_technique && typeof data.by_technique === "object") {
    return Object.entries(data.by_technique).map(([technique, count]) => ({
      technique,
      alert_count: count,
    }));
  }

  return [];
}

function getId(item) {
  return item.technique ?? item.technique_id ?? item.id ?? "Unknown";
}

function getCount(item) {
  const value = item.alert_count ?? item.alerts ?? item.count ?? 0;
  return typeof value === "number" ? value : 0;
}

function getTactic(item) {
  return item.tactic ?? item.tactic_name ?? "Other techniques";
}

export default function AttackMap() {
  const { data, error } = usePoll(api.mitre, 5000);

  const techniques = useMemo(() => getTechniques(data), [data]);

  const summary = useMemo(() => {
    const covered = techniques.filter((item) => getCount(item) > 0);
    const totalAlerts = techniques.reduce(
      (sum, item) => sum + getCount(item),
      0
    );
    const tactics = new Set(
      covered.map(getTactic).filter((name) => name !== "Other techniques")
    );

    const busiest = [...techniques].sort(
      (a, b) => getCount(b) - getCount(a)
    )[0];

    return {
      covered: covered.length,
      totalAlerts,
      tactics: tactics.size,
      busiest: busiest ? getId(busiest) : "—",
    };
  }, [techniques]);

  const groups = useMemo(() => {
    const result = {};

    techniques.forEach((item) => {
      const tactic = getTactic(item);
      if (!result[tactic]) result[tactic] = [];
      result[tactic].push(item);
    });

    return Object.entries(result);
  }, [techniques]);

  const maxAlerts = Math.max(1, ...techniques.map(getCount));
  const loading = !data && !error;

  function heatColor(count) {
    if (count === 0) return "border-line bg-ink-800";
    if (count / maxAlerts >= 0.75) return "border-red-400/40 bg-red-500/90";
    if (count / maxAlerts >= 0.4) return "border-orange-300/40 bg-orange-400/80";
    return "border-yellow-300/40 bg-yellow-400/70";
  }

  return (
    <main className="min-h-full space-y-5 p-4 text-text sm:p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">MITRE ATT&CK / COVERAGE MATRIX</p>
          <h1 className="mt-2 font-display text-2xl font-semibold">
            ATT&CK Navigator
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-mute">
            Live ATT&CK coverage from this session, shaded by alert volume.
            Uncovered techniques help identify possible detection gaps.
          </p>
        </div>

        <a
          href="/api/navigator/download"
          className="rounded-md border border-line px-3 py-2 text-sm transition hover:border-signal hover:text-signal"
        >
          ↓ Download layer JSON
        </a>
      </header>

      {error && (
        <section className="panel border-red-500/40 p-4">
          <p className="font-semibold text-red-400">
            MITRE coverage data is currently unavailable
          </p>
          <p className="mt-2 text-sm text-mute">
            The /api/mitre endpoint returned an error. Check its availability
            with the backend team; this page does not change backend code.
          </p>
        </section>
      )}

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="TECHNIQUES DETECTED"
          value={loading ? "…" : summary.covered}
          detail="Techniques with alerts"
          color="text-signal"
        />

        <StatCard
          label="ALERTS MAPPED"
          value={loading ? "…" : summary.totalAlerts}
        />

        <StatCard
          label="TACTICS TOUCHED"
          value={loading ? "…" : summary.tactics}
        />

        <StatCard
          label="BUSIEST TECHNIQUE"
          value={loading ? "…" : summary.busiest}
          detail="Highest alert count"
          color="text-indigo-400"
        />
      </section>

      <section className="panel overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
          <div>
            <p className="eyebrow">COVERAGE HEATMAP</p>
            <h2 className="mt-1 text-sm font-semibold">
              Technique alert distribution
            </h2>
          </div>

          <div className="flex items-center gap-2 text-[10px] text-mute">
            <span>fewer</span>
            <span className="h-2 w-3 rounded-sm bg-ink-800" />
            <span className="h-2 w-3 rounded-sm bg-yellow-400/70" />
            <span className="h-2 w-3 rounded-sm bg-orange-400/80" />
            <span className="h-2 w-3 rounded-sm bg-red-500/90" />
            <span>more alerts</span>
          </div>
        </div>

        {loading ? (
          <p className="p-6 text-sm text-mute">
            Loading ATT&CK techniques…
          </p>
        ) : techniques.length === 0 ? (
          <p className="p-6 text-sm text-mute">
            No technique coverage data was returned by the API.
          </p>
        ) : (
          <div className="space-y-5 p-4 sm:p-5">
            {groups.map(([tactic, items]) => (
              <div key={tactic}>
                <p className="mb-2 font-mono text-[10px] uppercase tracking-widest text-mute">
                  {tactic}
                </p>

                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {items.map((item, index) => {
                    const id = getId(item);
                    const count = getCount(item);
                    const covered = count > 0;

                    return (
                      <div
                        key={`${id}-${index}`}
                        className={`flex min-w-0 items-center justify-between gap-3 rounded border p-3 ${heatColor(count)}`}
                      >
                        <div className="min-w-0">
                          <p className="font-mono text-xs font-semibold text-white">
                            {id}
                          </p>
                          <p className="mt-1 break-words text-xs text-white/80">
                            {item.name ??
                              item.technique_name ??
                              "Technique name unavailable"}
                          </p>
                          <p className="mt-2 text-[10px] uppercase tracking-wider text-white/70">
                            {covered ? "Covered" : "Uncovered"}
                          </p>
                        </div>

                        <span className="font-mono text-sm font-semibold text-white">
                          {count}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="panel p-4 sm:p-5">
        <p className="eyebrow">HOW TO USE THE EXPORT</p>
        <p className="mt-2 text-sm leading-6 text-mute">
          Download the layer JSON, then open MITRE ATT&CK Navigator and use
          “Open Existing Layer” to upload the downloaded file. The matrix
          shows detected techniques and their alert counts.
        </p>
      </section>

      <p className="text-xs text-mute">
        DATA SOURCE: /api/mitre · Layer export: /api/navigator/download
      </p>
    </main>
  );
}
