import { useMemo } from "react";
import { api, usePoll } from "../api";
import StatCard from "../components/StatCard";
import { formatKts } from "../format";

// The ML detector tags its alerts with this rule id. Analytics.jsx uses the
// same convention, so the two pages agree.
const ML_RULE = "ML-ANOM";

function Bar({ label, count, max, bar }) {
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

// Share of the returned scores that the model flagged. Both numbers come from
// the same list, so the share can never pass 100%. anomaly_count from the API
// is a separate figure and is shown as text, not used for the ring.
function FlagRing({ flagged, total }) {
  const percent = total > 0 ? (flagged / total) * 100 : 0;

  return (
    <div
      className="relative flex h-[84px] w-[84px] shrink-0 items-center justify-center rounded-full"
      style={{
        background: `conic-gradient(#7c8cf8 ${percent}%, #243149 ${percent}% 100%)`,
        filter: flagged > 0 ? "drop-shadow(0 0 8px rgba(124,140,248,0.45))" : "none",
      }}
      role="img"
      aria-label={`${flagged} of ${total} recent scores flagged`}
    >
      <div className="flex h-[64px] w-[64px] flex-col items-center justify-center rounded-full bg-ink-800">
        <span className="font-mono text-[15px] font-semibold text-ml">
          {total > 0 ? `${flagged}/${total}` : "-"}
        </span>
        <span className="mt-0.5 font-mono text-[8px] uppercase tracking-wider text-mute">flagged</span>
      </div>
    </div>
  );
}

function formatNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(4) : "-";
}

// Work out the ML status from the three flags the API documents. ml_alerting,
// not ml_ready, says whether ML can actually raise an alert, so it decides.
function describeMl(mlReady, mlAlerting) {
  if (mlReady === false) {
    return {
      label: "ML not loaded",
      tone: "text-critical",
      text: "The ML subsystem reports that it is not ready, so no ML alert can come from it.",
    };
  }
  if (mlAlerting === true) {
    return {
      label: "ML alerting on",
      tone: "text-signal",
      text: "ML is scoring and is allowed to raise alerts.",
    };
  }
  if (mlAlerting === false) {
    return {
      label: "ML scoring only",
      tone: "text-medium",
      text: "ML is scoring behaviour but is not allowed to raise alerts. A zero in ML alerts is expected in this state.",
    };
  }
  if (mlReady === true) {
    return {
      label: "ML ready",
      tone: "text-signal",
      text: "ML is loaded, but the API did not say whether it can alert.",
    };
  }
  return {
    label: "ML status unknown",
    tone: "text-mute",
    text: "The API response does not say enough to tell what ML is doing.",
  };
}

export default function Evaluation() {
  const healthPoll = usePoll(api.health, 3000);
  const alertsPoll = usePoll(api.alerts, 5000);
  const anomalyPoll = usePoll(api.anomaly, 5000);

  const health = healthPoll.data;
  const anomaly = anomalyPoll.data;

  const alerts = useMemo(() => alertsPoll.data?.alerts ?? [], [alertsPoll.data]);
  const scores = useMemo(() => anomaly?.scores ?? [], [anomaly]);
  const alertsLoaded = Boolean(alertsPoll.data);
  const flaggedScores = scores.filter((row) => row.is_anomaly).length;

  const { ruleCount, mlCount, techniques } = useMemo(() => {
    const byTechnique = new Map();
    let ml = 0;

    alerts.forEach((alert) => {
      if (alert.rule === ML_RULE) {
        ml += 1;
      } else if (alert.technique) {
        byTechnique.set(alert.technique, (byTechnique.get(alert.technique) || 0) + 1);
      }
    });

    return {
      ruleCount: alerts.length - ml,
      mlCount: ml,
      techniques: [...byTechnique.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    };
  }, [alerts]);

  const mlReady = health?.ml_ready ?? anomaly?.ml_ready;
  const mlAlerting = health?.ml_alerting ?? anomaly?.ml_alerting;
  const ml = describeMl(mlReady, mlAlerting);

  const errors = [
    healthPoll.error && "/api/health",
    alertsPoll.error && "/api/alerts",
    anomalyPoll.error && "/api/anomaly",
  ].filter(Boolean);

  const maxTechnique = Math.max(0, ...techniques.map((item) => item.count));
  const maxKind = Math.max(ruleCount, mlCount);
  const show = (value) => (typeof value === "number" ? value.toLocaleString("en-US") : "-");

  // Say why a zero is a zero. A bare 0 reads as "broken" in a viva.
  let mlZeroNote = null;
  if (alertsLoaded && mlCount === 0) {
    mlZeroNote =
      mlAlerting === false
        ? "0 ML alerts because ML is not allowed to alert in this configuration."
        : mlAlerting === true
          ? "0 ML alerts: no score crossed the alert threshold in the returned alerts."
          : "0 ML alerts. The API did not say whether ML can alert.";
  }

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Detection quality</div>
        <h1>Evaluation</h1>
        <p>
          Rule alerts, ML status and recent anomaly scores, all from the API. The counts cover the
          latest alerts the API returns (at most 300).
        </p>
      </div>

      {errors.length > 0 && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load: {errors.join(", ")}
        </div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Total events" value={show(health?.counts?.events)} sub="from /api/health" tone="signal" />
        <StatCard label="Total alerts" value={show(health?.counts?.alerts)} sub="from /api/health" tone="high" />
        <StatCard
          label="Rule alerts"
          value={alertsLoaded ? ruleCount : "-"}
          sub="counted from alert records"
          tone="signal"
        />
        <StatCard
          label="ML alerts"
          value={alertsLoaded ? mlCount : "-"}
          sub={`rule id ${ML_RULE}`}
          tone="ml"
        />
      </div>

      <div className="mb-3 grid gap-3 xl:grid-cols-[320px_minmax(0,1fr)]">
        <div className="panel self-start">
          <div className="panel-label">ML status</div>
          <div className="panel-body">
            <p className={`font-display text-[16px] font-semibold ${ml.tone}`}>{ml.label}</p>
            <p className="mt-1 text-[12px] leading-snug text-mute">{ml.text}</p>

            <div className="mt-3 grid grid-cols-2 gap-2">
              <div className="rounded border border-line px-2.5 py-2">
                <div className="eyebrow">Subsystem</div>
                <div className="mt-1 text-[12px]">
                  {mlReady === undefined ? "unknown" : mlReady ? "ready" : "not ready"}
                </div>
              </div>
              <div className="rounded border border-line px-2.5 py-2">
                <div className="eyebrow">Autoencoder</div>
                <div className="mt-1 text-[12px]">
                  {health?.ml_has_autoencoder === undefined
                    ? "unknown"
                    : health.ml_has_autoencoder
                      ? "loaded"
                      : "not loaded"}
                </div>
              </div>
            </div>

            <div className="mt-3 flex items-center gap-3">
              <FlagRing flagged={flaggedScores} total={scores.length} />
              <div className="font-mono text-[11px] leading-relaxed text-mute">
                <div>of the last {scores.length} scores</div>
                <div>mode {health?.ml_mode ?? "-"}</div>
                <div>API total flagged {show(anomaly?.anomaly_count)}</div>
              </div>
            </div>
            {mlZeroNote && <p className="mt-2 text-[11px] leading-snug text-medium">{mlZeroNote}</p>}
          </div>
        </div>

        <div className="panel min-w-0">
          <div className="panel-label">Recent anomaly scores</div>
          {scores.length === 0 ? (
            <div className="panel-body font-mono text-[11px] text-mute">
              {anomalyPoll.data
                ? "No scores yet. ML has not scored any process."
                : "Waiting for /api/anomaly."}
            </div>
          ) : (
            <div className="max-h-[260px] overflow-y-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="sticky top-0 bg-ink-800 text-mute">
                  <tr className="eyebrow">
                    <th className="px-3 py-1.5">kts</th>
                    <th className="px-3 py-1.5">pid</th>
                    <th className="px-3 py-1.5">comm</th>
                    <th className="px-3 py-1.5 text-right">iforest</th>
                    <th className="px-3 py-1.5 text-right">recon error</th>
                    <th className="px-3 py-1.5">flag</th>
                  </tr>
                </thead>
                <tbody>
                  {scores.slice(0, 50).map((row, i) => (
                    <tr key={`${row.pid}-${row.ts}-${i}`} className="border-t border-line/60">
                      <td className="px-3 py-1 font-mono text-mute">{formatKts(row.ts)}</td>
                      <td className="px-3 py-1 font-mono">{row.pid}</td>
                      <td className="px-3 py-1 font-mono">{row.comm}</td>
                      <td className="px-3 py-1 text-right font-mono">{formatNumber(row.iforest_score)}</td>
                      <td className="px-3 py-1 text-right font-mono">
                        {row.recon_error === null || row.recon_error === undefined
                          ? "none"
                          : formatNumber(row.recon_error)}
                      </td>
                      <td className={`px-3 py-1 font-mono ${row.is_anomaly ? "text-critical" : "text-mute"}`}>
                        {row.is_anomaly ? "anomaly" : "normal"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <div className="panel">
          <div className="panel-label">Rule engine vs ML anomaly</div>
          <div className="panel-body grid gap-2.5">
            <Bar label="rule alerts" count={ruleCount} max={maxKind} bar="bg-signal" />
            <Bar label="ml alerts" count={mlCount} max={maxKind} bar="bg-ml" />
            <p className="font-mono text-[10px] leading-relaxed text-mute">
              Compares alert records only. It says nothing about event volume.
            </p>
          </div>
        </div>

        <div className="panel">
          <div className="panel-label">Rule alerts by technique</div>
          <div className="panel-body grid gap-2.5">
            {techniques.length === 0 ? (
              <p className="font-mono text-[11px] text-mute">
                {alertsLoaded ? "No technique ids in the returned alerts." : "Waiting for alerts."}
              </p>
            ) : (
              techniques.map((item) => (
                <Bar key={item.name} label={item.name} count={item.count} max={maxTechnique} bar="bg-high" />
              ))
            )}
          </div>
        </div>
      </div>

      <p className="mt-3 font-mono text-[10px] leading-relaxed text-mute">
        Sources: /api/health, /api/alerts, /api/anomaly. kts is kernel time in seconds since boot,
        not wall-clock time.
      </p>
    </div>
  );
}
