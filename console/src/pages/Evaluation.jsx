import { useMemo } from "react";
import { api, usePoll } from "../api";
import StatCard from "../components/StatCard";
import { formatKts } from "../format";

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

function checksFired(row) {
  const fired = [];
  if (row.iforest_anomaly) fired.push("forest");
  if (row.ae_anomaly) fired.push("autoencoder");
  if (row.limit_anomaly) fired.push("limit");
  if (fired.length === 0 && row.is_anomaly) fired.push("model");
  return fired.join(", ");
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
  const healthPoll = usePoll(api.health, 5000);
  const evaluationPoll = usePoll(api.evaluation, 5000);
  const anomalyPoll = usePoll(api.anomaly, 5000);

  const health = healthPoll.data;
  const evaluation = evaluationPoll.data;
  const anomaly = anomalyPoll.data;

  const scores = useMemo(() => anomaly?.scores ?? [], [anomaly]);
  const flaggedScores = scores.filter((row) => row.is_anomaly).length;

  const evaluationLoaded = Boolean(evaluation);
  const ruleCount = evaluation?.rule_alerts ?? 0;
  const mlCount = evaluation?.ml_alerts ?? 0;
  const techniques = useMemo(
    () =>
      Object.entries(evaluation?.by_technique ?? {})
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    [evaluation]
  );

  const mlReady = evaluation?.ml_ready ?? health?.ml_ready;
  const mlAlerting = evaluation?.ml_alerting ?? health?.ml_alerting;
  const ml = describeMl(mlReady, mlAlerting);

  const scoredTotal = evaluation?.anomaly_scores;
  const flaggedTotal = evaluation?.anomalies_flagged;
  const flaggedShare =
    typeof scoredTotal === "number" && scoredTotal > 0 && typeof flaggedTotal === "number"
      ? `${((flaggedTotal / scoredTotal) * 100).toFixed(2)}%`
      : "-";

  const errors = [
    healthPoll.error && "/api/health",
    evaluationPoll.error && "/api/evaluation",
    anomalyPoll.error && "/api/anomaly",
  ].filter(Boolean);

  const maxTechnique = Math.max(0, ...techniques.map((item) => item.count));
  const maxKind = Math.max(ruleCount, mlCount);
  const show = (value) => (typeof value === "number" ? value.toLocaleString("en-US") : "-");

  let mlZeroNote = null;
  if (evaluationLoaded && mlCount === 0) {
    mlZeroNote =
      mlReady === false
        ? "0 ML alerts because no model is loaded. The server was started with --no-ml or found no model files in server/ml/."
        : mlAlerting === false
          ? "0 ML alerts because ML alerting is off. The model scores every event, but only the server started with --ml-alerting turns a flagged score into an ML-ANOM alert. Off is the default, because a flag rate of a few percent would bury the rule alerts."
          : mlAlerting === true
            ? "0 ML alerts: ML alerting is on, but no flagged score has been turned into an alert yet."
            : "0 ML alerts. The API did not say whether ML can alert.";
  }

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">Detection quality</div>
        <h1>Evaluation</h1>
        <p>
          Counts come from /api/evaluation and cover everything stored since the database was
          created. The ring and the score table come from /api/anomaly, which keeps only the newest
          300 scores.
        </p>
      </div>

      {errors.length > 0 && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load: {errors.join(", ")}
        </div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Total events" value={show(evaluation?.total_events)} sub="stored events" tone="signal" />
        <StatCard label="Total alerts" value={show(evaluation?.total_alerts)} sub="stored alerts" tone="high" />
        <StatCard label="Rule alerts" value={show(evaluation?.rule_alerts)} sub="raised by YAML rules" tone="signal" />
        <StatCard label="ML alerts" value={show(evaluation?.ml_alerts)} sub="technique ML-ANOM" tone="ml" />
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Incidents" value={show(evaluation?.incidents)} sub="grouped alerts" />
        <StatCard
          label="Alerts per incident"
          value={evaluationLoaded ? evaluation.alerts_per_incident : "-"}
          sub="alerts in incidents / incidents"
        />
        <StatCard
          label="Events scored by ML"
          value={show(scoredTotal)}
          sub="since the server started"
          tone="ml"
        />
        <StatCard
          label="Flagged by ML"
          value={show(flaggedTotal)}
          sub={`${flaggedShare} of scored, since the server started`}
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
                <div>flagged in that window {show(anomaly?.anomaly_count)}</div>
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
                    <th className="px-3 py-1.5">checks</th>
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
                      <td className="px-3 py-1 font-mono text-[11px] text-mute">{checksFired(row) || "-"}</td>
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
                {evaluationLoaded ? "No rule alerts stored yet." : "Waiting for /api/evaluation."}
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
        Sources: /api/evaluation, /api/anomaly, /api/health. Stored counts start again when
        data/hids.db is deleted, the ML counters when the server restarts. kts is kernel time in
        seconds since boot, not wall-clock time.
      </p>
    </div>
  );
}
