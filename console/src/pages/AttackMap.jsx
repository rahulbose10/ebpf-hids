import { useMemo } from "react";
import { api, usePoll } from "../api";
import StatCard from "../components/StatCard";

// /api/mitre is not in the frozen contract yet, so its shape is not agreed
// with L4. Until it is, accept the shapes L4 is most likely to send. Once the
// shape is fixed, delete the branches that are not used.
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

// A tile is shaded by its share of the busiest technique. Dark text on a
// translucent tint stays readable, which white on yellow was not.
function tileClass(count, max) {
  if (count === 0) return "border-line bg-ink-800/60";
  const share = count / max;
  if (share >= 0.75) return "border-critical/60 bg-critical/25";
  if (share >= 0.4) return "border-high/60 bg-high/25";
  return "border-medium/60 bg-medium/20";
}

export default function AttackMap() {
  const { data, error } = usePoll(api.mitre, 5000);

  const techniques = useMemo(() => getTechniques(data), [data]);

  const summary = useMemo(() => {
    const alerted = techniques.filter((item) => getCount(item) > 0);
    const totalAlerts = techniques.reduce((sum, item) => sum + getCount(item), 0);
    const tactics = new Set(
      alerted.map(getTactic).filter((name) => name !== "Other techniques")
    );
    const busiest = [...techniques].sort((a, b) => getCount(b) - getCount(a))[0];

    return {
      alerted: alerted.length,
      totalAlerts,
      tactics: tactics.size,
      busiest: busiest && getCount(busiest) > 0 ? getId(busiest) : "-",
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

  return (
    <div>
      <div className="page-header flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="eyebrow">MITRE ATT&CK</div>
          <h1>ATT&CK Navigator</h1>
          <p>
            Techniques from this session, shaded by alert volume. A grey tile means no alert fired
            for that technique in this session. It does not prove there is no rule for it.
          </p>
        </div>

        <a
          href="/api/navigator/download"
          className="shrink-0 rounded border border-line px-3 py-1.5 text-[12px] transition hover:border-signal hover:text-signal"
        >
          Download layer JSON
        </a>
      </div>

      {error && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load /api/mitre. The endpoint may not exist yet on the backend.
        </div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard
          label="Techniques alerted"
          value={loading ? "..." : summary.alerted}
          sub="at least one alert"
          tone="signal"
        />
        <StatCard label="Alerts mapped" value={loading ? "..." : summary.totalAlerts} tone="high" />
        <StatCard label="Tactics touched" value={loading ? "..." : summary.tactics} />
        <StatCard label="Busiest technique" value={loading ? "..." : summary.busiest} tone="ml" />
      </div>

      <div className="panel">
        <div className="panel-label flex flex-wrap items-center justify-between gap-3">
          <span>Technique alert distribution</span>

          <span className="flex items-center gap-2 normal-case tracking-normal">
            <span>none</span>
            <span className="h-2 w-3 rounded-sm border border-line bg-ink-800" />
            <span className="h-2 w-3 rounded-sm border border-medium/60 bg-medium/20" />
            <span className="h-2 w-3 rounded-sm border border-high/60 bg-high/25" />
            <span className="h-2 w-3 rounded-sm border border-critical/60 bg-critical/25" />
            <span>most</span>
          </span>
        </div>

        {loading ? (
          <p className="p-4 font-mono text-[12px] text-mute">Loading techniques...</p>
        ) : techniques.length === 0 ? (
          <p className="p-4 font-mono text-[12px] text-mute">
            No technique data returned by /api/mitre.
          </p>
        ) : (
          <div className="grid content-start gap-4 p-3 md:grid-cols-2 xl:grid-cols-3">
            {groups.map(([tactic, items]) => (
              <div key={tactic}>
                <div className="eyebrow mb-1.5">{tactic}</div>

                <div className="grid gap-2">
                  {items.map((item, index) => {
                    const id = getId(item);
                    const count = getCount(item);

                    return (
                      <div
                        key={`${id}-${index}`}
                        className={`flex min-w-0 items-center justify-between gap-3 rounded border px-2.5 py-2 ${tileClass(count, maxAlerts)}`}
                      >
                        <div className="min-w-0">
                          <div className="font-mono text-[12px] font-semibold text-text">{id}</div>
                          <div className="truncate text-[11px] text-mute" title={item.name ?? item.technique_name ?? ""}>
                            {item.name ?? item.technique_name ?? "name not provided"}
                          </div>
                        </div>

                        <span className="font-mono text-[13px] text-text">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="mt-3 font-mono text-[10px] leading-relaxed text-mute">
        Export: download the layer JSON, open MITRE ATT&CK Navigator, choose Open Existing Layer and
        upload the file. Source: /api/mitre and /api/navigator/download.
      </p>
    </div>
  );
}
