import { useMemo } from "react";
import { api, usePoll } from "../api";
import StatCard from "../components/StatCard";

// The alert API returns at most this many rows (newest first), so every
// breakdown below describes the latest alerts, not all alerts ever raised.
const ALERT_CAP = 300;

const SEVERITIES = [
  { id: "critical", bar: "bg-critical" },
  { id: "high", bar: "bg-high" },
  { id: "medium", bar: "bg-medium" },
  { id: "low", bar: "bg-low" },
];

// The ML detector tags its alerts with this rule id. Evaluation.jsx uses the
// same convention, so the two pages agree.
const ML_RULE = "ML-ANOM";

function BarRow({ label, count, max, bar }) {
  const width = max > 0 ? `${Math.max((count / max) * 100, count > 0 ? 2 : 0)}%` : "0%";

  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)_36px] items-center gap-3">
      <span className="truncate font-mono text-[11px] text-mute" title={label}>
        {label}
      </span>
      <div className="h-2 overflow-hidden rounded-full bg-ink-600">
        <div className={`h-full rounded-full ${bar}`} style={{ width }} />
      </div>
      <span className="text-right font-mono text-[11px] text-text">{count}</span>
    </div>
  );
}

function Breakdown({ title, rows, note, bar }) {
  const max = Math.max(0, ...rows.map((row) => row.count));

  return (
    <div className="panel min-w-0">
      <div className="panel-label">{title}</div>
      <div className="panel-body grid gap-2.5">
        {rows.length === 0 ? (
          <p className="font-mono text-[11px] text-mute">No alerts yet.</p>
        ) : (
          rows.map((row) => (
            <BarRow
              key={row.label}
              label={row.label}
              count={row.count}
              max={max}
              bar={row.bar || bar}
            />
          ))
        )}
        {note && <p className="mt-1 font-mono text-[10px] leading-relaxed text-mute">{note}</p>}
      </div>
    </div>
  );
}

export default function Analytics() {
  const healthPoll = usePoll(api.health, 3000);
  const alertsPoll = usePoll(api.alerts, 5000);

  const counts = healthPoll.data?.counts ?? {};
  const alerts = useMemo(() => alertsPoll.data?.alerts ?? [], [alertsPoll.data]);
  const failed = healthPoll.error || alertsPoll.error;
  const loading = !healthPoll.data && !healthPoll.error;

  const stats = useMemo(() => {
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s.id, 0]));
    const byTechnique = new Map();
    let ml = 0;

    alerts.forEach((alert) => {
      const level = String(alert.severity || "low").toLowerCase();
      if (level in bySeverity) bySeverity[level] += 1;

      if (alert.rule === ML_RULE) {
        ml += 1;
      } else if (alert.technique) {
        byTechnique.set(alert.technique, (byTechnique.get(alert.technique) || 0) + 1);
      }
    });

    const techniques = [...byTechnique.entries()]
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

    return { bySeverity, techniques, ml, rule: alerts.length - ml };
  }, [alerts]);

  const show = (value) =>
    typeof value === "number" ? value.toLocaleString("en-US") : loading ? "..." : "-";

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Detection metrics</div>
        <h1>Analytics</h1>
        <p>
          Totals come from /api/health. The breakdowns are counted in the browser from the latest
          alerts returned by /api/alerts.
        </p>
      </div>

      {failed && (
        <div
          role="alert"
          className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical"
        >
          Some analytics data could not be loaded. Check /api/health and /api/alerts.
        </div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Events processed" value={show(counts.events)} tone="signal" />
        <StatCard label="Alerts raised" value={show(counts.alerts)} tone="high" />
        <StatCard label="Incidents" value={show(counts.incidents)} tone="critical" />
        <StatCard
          label="Techniques seen"
          value={alertsPoll.data ? stats.techniques.length : "-"}
          sub="distinct, rule alerts only"
          tone="ml"
        />
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <Breakdown
          title="Alerts by severity"
          rows={SEVERITIES.map((s) => ({ label: s.id, count: stats.bySeverity[s.id], bar: s.bar }))}
          bar="bg-signal"
          note={`Counted over ${alerts.length} latest alerts (API cap ${ALERT_CAP}).`}
        />

        <Breakdown
          title="Rule engine vs ML anomaly"
          rows={[
            { label: "rule alerts", count: stats.rule, bar: "bg-signal" },
            { label: "ml alerts", count: stats.ml, bar: "bg-ml" },
          ]}
          bar="bg-signal"
          note={`ML alerts are the ones with rule id ${ML_RULE}.`}
        />

        <Breakdown
          title="Rule alerts by technique"
          rows={stats.techniques}
          bar="bg-high"
          note="ATT&CK technique id from each rule. ML alerts are not counted here."
        />
      </div>
    </div>
  );
}
