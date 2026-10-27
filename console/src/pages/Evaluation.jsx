
import { useMemo } from "react";
import { api, usePoll } from "../api";

const severityStyles = {
  critical: "text-red-400",
  high: "text-orange-300",
  medium: "text-yellow-300",
  low: "text-teal-300",
};

function Panel({ title, children }) {
  return (
    <section className="panel min-w-0 overflow-hidden">
      <div className="border-b border-line px-4 py-3">
        <p className="eyebrow">{title}</p>
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function StatCard({ label, value, detail, color = "text-text" }) {
  return (
    <section className="panel min-w-0 p-4">
      <p className="eyebrow">{label}</p>
      <p className={`stat-num mt-3 break-words text-3xl ${color}`}>
        {value}
      </p>
      {detail && (
        <p className="mt-2 text-xs leading-5 text-mute">{detail}</p>
      )}
    </section>
  );
}

function formatScore(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return value <= 1
    ? `${(value * 100).toFixed(0)}%`
    : `${value.toFixed(1)}`;
}

export default function Evaluation() {
  const healthPoll = usePoll(api.health, 3000);
  const alertsPoll = usePoll(api.alerts, 5000);
  const anomalyPoll = usePoll(api.anomaly, 5000);

  const health = healthPoll.data;
  const alertResponse = alertsPoll.data;
  const anomaly = anomalyPoll.data;

  const alerts = useMemo(() => {
    if (Array.isArray(alertResponse)) return alertResponse;
    if (Array.isArray(alertResponse?.alerts)) {
      return alertResponse.alerts;
    }
    return [];
  }, [alertResponse]);

  const ruleAlerts = alerts.filter(
    (alert) => alert.rule && alert.rule !== "ML-ANOM"
  );

  const mlAlerts = alerts.filter(
    (alert) => alert.rule === "ML-ANOM"
  );

  const techniques = useMemo(() => {
    const counts = new Map();

    alerts.forEach((alert) => {
      const technique = alert.technique;

      if (
        technique &&
        technique !== "ML-ANOM" &&
        technique !== "N/A"
      ) {
        counts.set(technique, (counts.get(technique) || 0) + 1);
      }
    });

    return [...counts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [alerts]);

  const scoreValue =
    typeof anomaly?.score === "number"
      ? anomaly.score
      : typeof anomaly?.anomaly_score === "number"
        ? anomaly.anomaly_score
        : null;

  const scoreLabel = formatScore(scoreValue);
  const gaugeValue =
    scoreValue === null
      ? 0
      : Math.max(0, Math.min(100, scoreValue <= 1 ? scoreValue * 100 : scoreValue));

  const threshold =
    typeof anomaly?.threshold === "number"
      ? anomaly.threshold
      : null;

  const mlReady = health?.ml_ready ?? anomaly?.ml_ready;
  const mlAlerting = health?.ml_alerting ?? anomaly?.ml_alerting;
  const autoencoderLoaded =
    health?.ml_has_autoencoder ?? anomaly?.ml_has_autoencoder;

  let mlStatus = "ML STATUS UNAVAILABLE";
  let mlStatusDetail =
    "The current API response does not provide enough information to determine ML status.";
  let mlStatusColor = "text-mute";

  if (mlReady === false) {
    mlStatus = "ML NOT READY";
    mlStatusDetail =
      "The ML subsystem reports that it is not ready. ML alerting cannot be assumed to be active.";
    mlStatusColor = "text-red-400";
  } else if (mlAlerting === true) {
    mlStatus = "ML ALERTING ON";
    mlStatusDetail =
      "The API reports that ML alerting is enabled.";
    mlStatusColor = "text-signal";
  } else if (mlAlerting === false) {
    mlStatus = "ML ALERTING OFF";
    mlStatusDetail =
      "The ML subsystem may be available for scoring, but it is not currently configured to raise ML alerts.";
    mlStatusColor = "text-yellow-300";
  } else if (mlReady === true) {
    mlStatus = "ML READY";
    mlStatusDetail =
      "The ML subsystem is ready, but its alerting state is not available.";
    mlStatusColor = "text-signal";
  }

  const dataErrors = [
    healthPoll.error && "Health API request failed.",
    alertsPoll.error && "Alerts API request failed.",
    anomalyPoll.error && "Anomaly API request failed.",
  ].filter(Boolean);

  const maxTechniqueCount = Math.max(
    1,
    ...techniques.map((item) => item.count)
  );

  return (
    <main className="min-h-full space-y-5 p-4 text-text sm:p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">DETECTION QUALITY / MEASURED RESULTS</p>
          <h1 className="mt-2 font-display text-2xl font-semibold">
            Evaluation
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-mute">
            Review rule detections, ML alerting status, technique coverage
            and the available anomaly score using data returned by the API.
          </p>
        </div>

        <div className="panel px-4 py-3">
          <p className="eyebrow">DATA STATUS</p>
          <p className="mt-2 font-mono text-sm text-signal">
            {healthPoll.data ? "HEALTH RECEIVED" : "WAITING FOR API"}
          </p>
        </div>
      </header>

      {dataErrors.length > 0 && (
        <section className="panel border-red-500/40 p-4">
          <p className="font-semibold text-red-400">
            Some evaluation data could not be loaded
          </p>
          <ul className="mt-2 space-y-1 text-sm text-mute">
            {dataErrors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="TOTAL EVENTS"
          value={health?.counts?.events ?? "—"}
          detail="Events reported by the health API"
        />
        <StatCard
          label="TOTAL ALERTS"
          value={health?.counts?.alerts ?? "—"}
          detail="Alerts reported by the health API"
          color="text-orange-300"
        />
        <StatCard
          label="RULE ALERTS"
          value={alertsPoll.data ? ruleAlerts.length : "—"}
          detail={
            alertsPoll.data
              ? "Counted from the returned alert records"
              : "Waiting for alert records"
          }
          color="text-signal"
        />
        <StatCard
          label="ML ALERTS"
          value={alertsPoll.data ? mlAlerts.length : "—"}
          detail={
            alertsPoll.data
              ? "Records identified with rule ID ML-ANOM"
              : "Waiting for alert records"
          }
          color="text-ml"
        />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="RULE ENGINE VS ML ANOMALY">
          <div className="space-y-6">
            {[
              {
                label: "rule alerts",
                count: ruleAlerts.length,
                color: "bg-signal",
                textColor: "text-signal",
              },
              {
                label: "ml alerts",
                count: mlAlerts.length,
                color: "bg-ml",
                textColor: "text-ml",
              },
            ].map((item) => {
              const total = ruleAlerts.length + mlAlerts.length;
              const width =
                total > 0 ? (item.count / total) * 100 : 0;

              return (
                <div key={item.label}>
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <span className="font-mono text-xs text-mute">
                      {item.label}
                    </span>
                    <span className={`font-mono text-sm ${item.textColor}`}>
                      {alertsPoll.data ? item.count : "—"}
                    </span>
                  </div>

                  <div
                    className="h-3 overflow-hidden rounded-sm bg-ink-700"
                    role="img"
                    aria-label={`${item.label}: ${alertsPoll.data ? item.count : "unavailable"}`}
                  >
                    {alertsPoll.data && total > 0 && (
                      <div
                        className={`h-full rounded-sm transition-all duration-500 ${item.color}`}
                        style={{ width: `${width}%` }}
                      />
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <p className="mt-5 border-t border-line pt-3 text-xs leading-5 text-mute">
            {alertsPoll.data
              ? "These bars compare the alert records returned by the API. They do not represent event volume."
              : "Separate rule and ML alert counts are unavailable until the alerts API returns records."}
          </p>
        </Panel>

        <Panel title="ANOMALY GAUGE">
          <div className="flex flex-wrap items-center gap-6">
            <div
              className="relative flex h-36 w-36 shrink-0 items-center justify-center rounded-full"
              style={{
                background: `conic-gradient(var(--ml, #7c8cf8) ${gaugeValue}%, var(--gauge-track, #243149) ${gaugeValue}% 100%)`,
              }}
              role="img"
              aria-label={`Anomaly score: ${scoreLabel ?? "unavailable"}`}
            >
              <div className="flex h-28 w-28 flex-col items-center justify-center rounded-full bg-ink-800">
                <span className="font-mono text-2xl font-semibold text-ml">
                  {scoreLabel ?? "—"}
                </span>
                <span className="eyebrow mt-1">SCORE</span>
              </div>
            </div>

            <div className="min-w-0 flex-1 space-y-3">
              <div>
                <p className="eyebrow">MODEL</p>
                <p className="mt-1 break-words font-mono text-sm">
                  {anomaly?.model ?? health?.ml_mode ?? "Unavailable"}
                </p>
              </div>

              <div>
                <p className="eyebrow">THRESHOLD</p>
                <p className="mt-1 font-mono text-sm">
                  {threshold === null ? "Unavailable" : formatScore(threshold)}
                </p>
              </div>

              <div>
                <p className="eyebrow">ANOMALY STATUS</p>
                <p className="mt-1 font-mono text-sm text-ml">
                  {anomaly?.status ?? "Not provided by API"}
                </p>
              </div>
            </div>
          </div>

          <p className="mt-5 border-t border-line pt-3 text-xs leading-5 text-mute">
            The gauge displays the score returned by the anomaly API. It does
            not independently decide whether an event is malicious.
          </p>
        </Panel>
      </section>

      <Panel title="PER-TECHNIQUE ALERT BREAKDOWN">
        {techniques.length > 0 ? (
          <div className="space-y-4">
            {techniques.map((item) => (
              <div key={item.name}>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <span className="break-all font-mono text-xs text-mute">
                    {item.name}
                  </span>
                  <span className="font-mono text-xs">
                    {item.count}
                  </span>
                </div>

                <div className="h-2 overflow-hidden rounded-sm bg-ink-700">
                  <div
                    className="h-full rounded-sm bg-orange-300 transition-all duration-500"
                    style={{
                      width: `${(item.count / maxTechniqueCount) * 100}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm leading-6 text-mute">
            {alertsPoll.data
              ? "No MITRE technique records were available in the returned alerts."
              : "Technique breakdown is unavailable until alert data loads."}
          </p>
        )}
      </Panel>

      <section className="panel overflow-hidden">
        <div className="border-b border-line px-4 py-3">
          <p className="eyebrow">ML STATUS / WHY IT MATTERS</p>
        </div>

        <div className="p-4">
          <p className={`font-display text-lg font-semibold ${mlStatusColor}`}>
            {mlStatus}
          </p>
          <p className="mt-2 text-sm leading-6 text-mute">
            {mlStatusDetail}
          </p>

          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-line p-3">
              <p className="eyebrow">ML SUBSYSTEM</p>
              <p className="mt-2 text-sm">
                {mlReady === undefined
                  ? "Status unavailable"
                  : mlReady
                    ? "Ready"
                    : "Not ready"}
              </p>
            </div>

            <div className="rounded-md border border-line p-3">
              <p className="eyebrow">AUTOENCODER</p>
              <p className="mt-2 text-sm">
                {autoencoderLoaded === undefined
                  ? "Status unavailable"
                  : autoencoderLoaded
                    ? "Loaded"
                    : "Not loaded"}
              </p>
            </div>
          </div>
        </div>
      </section>

      <p className="text-xs leading-5 text-mute">
        DATA SOURCE: /api/health, /api/alerts, /api/anomaly. MITRE technique
        totals are derived from returned alert records; no separate MITRE API
        is assumed by this page.
      </p>
    </main>
  );
}
