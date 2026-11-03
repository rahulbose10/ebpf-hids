import { useState } from "react";
import GaugeBar from "../components/GaugeBar";
import SeverityChip from "../components/SeverityChip";
import { api, usePoll } from "../api";
import { formatEvent, formatKts } from "../format";

function gaugeNote(health) {
  if (!health) return "Waiting for /api/health.";
  if (!health.ml_ready) {
    return "ML models are not loaded, so there is no anomaly score to show.";
  }
  if (health.ml_alerting) {
    return "ML alerting is on. Anomaly scores can raise alerts.";
  }
  const base =
    "Gauge only. ML alerting is off, so the rule engine carries detection.";
  return health.ml_has_autoencoder === false
    ? `${base} No autoencoder is loaded.`
    : base;
}

function aeRatio(row, threshold) {
  if (typeof row?.recon_error !== "number" || typeof threshold !== "number" || threshold <= 0) {
    return null;
  }
  return row.recon_error / threshold;
}

function flaggedBy(row) {
  if (!row?.is_anomaly) return "-";
  const parts = [];
  if (row.iforest_anomaly) parts.push("forest");
  if (row.ae_anomaly) parts.push("autoencoder");
  if (row.limit_anomaly) {
    const names = Array.isArray(row.over_limit) ? row.over_limit.join(", ") : "";
    parts.push(names ? `limits (${names})` : "limits");
  }
  return parts.length ? parts.join(", ") : "model";
}

function fixed(value, digits = 4) {
  return typeof value === "number" ? value.toFixed(digits) : "-";
}

function Field({ label, children }) {
  return (
    <div className="flex gap-3 border-b border-line/50 py-2 last:border-b-0">
      <dt className="w-28 shrink-0 font-mono text-[10.5px] uppercase tracking-[0.12em] text-mute">
        {label}
      </dt>
      <dd className="min-w-0 break-words text-[12.5px] text-text">{children}</dd>
    </div>
  );
}

function ScoreCard({ title, row, threshold, empty, note }) {
  const ratio = aeRatio(row, threshold);

  return (
    <div className="min-w-0 rounded border border-line bg-ink-700/40 px-3 py-2">
      <div className="eyebrow mb-1">{title}</div>
      {!row ? (
        <p className="py-3 font-mono text-[11px] text-mute">{empty}</p>
      ) : (
        <dl>
          <Field label="Process">
            {row.comm || "-"} <span className="text-mute">pid {row.pid ?? "-"}</span>
          </Field>
          <Field label="Kernel ts">
            <span className="font-mono">{formatKts(row.ts)}</span>
          </Field>
          <Field label="Verdict">
            <span className={row.is_anomaly ? "text-critical" : ""}>
              {row.is_anomaly ? "anomaly" : "normal"}
            </span>
          </Field>
          <Field label="Flagged by">{flaggedBy(row)}</Field>
          <Field label="Forest">
            <span className={`font-mono ${row.iforest_anomaly ? "text-critical" : ""}`}>
              {fixed(row.iforest_score)}
            </span>
            <span className="text-mute"> flags below 0</span>
          </Field>
          <Field label="Autoencoder">
            <span className={`font-mono ${row.ae_anomaly ? "text-critical" : ""}`}>
              {fixed(row.recon_error)}
            </span>
            <span className="text-mute">
              {ratio === null ? " no autoencoder score" : ` = ${ratio.toFixed(2)}x threshold`}
            </span>
          </Field>
        </dl>
      )}
      {note && <p className="pb-1 pt-2 font-mono text-[10.5px] text-mute">{note}</p>}
    </div>
  );
}

function Detection() {
  const { data } = usePoll(api.alerts, 3000);
  const [kept, setKept] = useState(null);
  const { data: anomaly } = usePoll(async () => {
    const result = await api.anomaly();
    const flagged = result?.scores?.find((row) => row.is_anomaly);
    if (flagged) {
      setKept((old) => (old && old.ts >= flagged.ts ? old : flagged));
    }
    return result;
  }, 3000);
  const { data: health } = usePoll(api.health, 4000);

  const alerts = data?.alerts || [];
  const scores = anomaly?.scores ?? [];
  const latest = anomaly?.latest ?? null;
  const keptInWindow = kept
    ? scores.some((row) => row.ts === kept.ts && row.pid === kept.pid)
    : false;
  const threshold = anomaly?.ae_threshold;
  const ratio = aeRatio(latest, threshold);
  const byCheck = {
    forest: scores.filter((row) => row.iforest_anomaly).length,
    autoencoder: scores.filter((row) => row.ae_anomaly).length,
    limits: scores.filter((row) => row.limit_anomaly).length,
  };
  const [selected, setSelected] = useState(null);

  const picked = selected !== null ? alerts[selected] : null;
  const info =
    picked && typeof picked.detail === "object" && picked.detail
      ? picked.detail
      : {};

  return (
    <div className="flex flex-col gap-3">
      <div className="page-header">
        <h1>Detection</h1>
        <p>
          Rule detections mapped to MITRE ATT&CK techniques, plus the ML anomaly
          gauge.
        </p>
      </div>

      <section className="panel overflow-hidden">
        <header className="flex h-10 items-center border-b border-line px-4">
          <span className="eyebrow">Anomaly gauge · autoencoder error / threshold, latest scored row</span>
        </header>

        <div className="p-4">
          <p className="mb-3 text-[12.5px] text-mute">{gaugeNote(health)}</p>

          <GaugeBar
            fill={ratio === null ? 0 : ratio / 2}
            mark={ratio === null ? null : 0.5}
            alarm={Boolean(latest?.ae_anomaly)}
          />
          <div className="mt-1 flex justify-between font-mono text-[10px] text-mute">
            <span>0</span>
            <span>{ratio === null ? "no autoencoder score" : "threshold"}</span>
            <span>2x</span>
          </div>
          <p className="mt-2 text-[11px] text-mute">
            The bar shows only the autoencoder and turns red only when the autoencoder flags the
            latest row. A row can also be flagged by the isolation forest or by the feature limits,
            so the cards below say which check fired.
          </p>

          <div className="mt-3 flex flex-wrap gap-x-8 gap-y-1 font-mono text-[11.5px] text-mute">
            <span>
              mode <strong className="ml-1 text-text">{health?.ml_mode ?? "-"}</strong>
            </span>
            <span>
              error / threshold{" "}
              <strong className="ml-1 text-text">{ratio === null ? "-" : `${ratio.toFixed(2)}x`}</strong>
            </span>
            <span>
              flagged in last {scores.length}{" "}
              <strong className="ml-1 text-text">{anomaly?.anomaly_count ?? "-"}</strong>
            </span>
            <span>
              forest <strong className="ml-1 text-text">{byCheck.forest}</strong>
            </span>
            <span>
              autoencoder <strong className="ml-1 text-text">{byCheck.autoencoder}</strong>
            </span>
            <span>
              limits <strong className="ml-1 text-text">{byCheck.limits}</strong>
            </span>
          </div>

          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <ScoreCard
              title="Latest scored row"
              row={latest}
              threshold={threshold}
              empty="Nothing scored yet."
            />
            <ScoreCard
              title="Newest flagged row since this page opened"
              row={kept}
              threshold={threshold}
              empty="No row flagged since this page opened."
              note={
                kept
                  ? keptInWindow
                    ? `Still in the last ${scores.length} scores.`
                    : `Older than the last ${scores.length} scores, kept here so it can be read.`
                  : null
              }
            />
          </div>
        </div>
      </section>

      <div className="grid grid-cols-5 gap-3">
        <section className="panel col-span-3 flex flex-col overflow-hidden">
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <span className="eyebrow">Alert feed</span>
            <span className="font-mono text-[11px] text-mute">{alerts.length}</span>
          </header>

          <div className="h-[calc(100vh-400px)] min-h-[260px] overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="px-4 py-6 text-center font-mono text-xs text-mute">
                No alerts
              </div>
            ) : (
              alerts.map((alert, index) => (
                <button
                  key={`${alert.ts}-${alert.rule}-${index}`}
                  type="button"
                  onClick={() => setSelected(index)}
                  className={`flex w-full gap-3 border-b border-line/50 px-4 py-2.5 text-left transition-colors hover:bg-ink-700 ${
                    selected === index ? "bg-ink-700" : ""
                  }`}
                >
                  <span className="mt-px">
                    <SeverityChip severity={alert.severity} />
                  </span>

                  <span className="min-w-0">
                    <span className="block text-[12.5px] leading-snug text-text">
                      <span className="mr-2 font-mono text-signal">{alert.rule}</span>
                      {alert.summary}
                    </span>
                    <span className="mt-1 block font-mono text-[10.5px] text-mute">
                      pid {alert.pid ?? "-"} · {alert.comm || "-"}
                      {alert.technique ? ` · ${alert.technique}` : ""}
                      {alert.confidence != null ? ` · conf ${alert.confidence}` : ""}
                    </span>
                  </span>
                </button>
              ))
            )}
          </div>
        </section>

        <section className="panel col-span-2 flex flex-col overflow-hidden">
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <span className="eyebrow">Investigation</span>
            {picked && (
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="font-mono text-[11px] text-mute hover:text-text"
              >
                clear
              </button>
            )}
          </header>

          <div className="h-[calc(100vh-400px)] min-h-[260px] overflow-y-auto px-4 py-2">
            {!picked ? (
              <div className="pt-8 text-center font-mono text-xs text-mute">
                Select an alert from the feed
              </div>
            ) : (
              <dl>
                <Field label="Severity">
                  <SeverityChip severity={picked.severity} />
                </Field>
                <Field label="Rule">
                  <span className="font-mono text-signal">{picked.rule}</span>
                </Field>
                <Field label="Summary">{picked.summary}</Field>
                <Field label="Process">
                  {picked.comm || "-"} <span className="text-mute">pid {picked.pid ?? "-"}</span>
                </Field>
                <Field label="ATT&CK">
                  {picked.technique || "-"}
                  {info.technique && info.technique !== picked.technique ? ` · ${info.technique}` : ""}
                </Field>
                {info.tactic && <Field label="Tactic">{info.tactic}</Field>}
                {info.event && <Field label="Trigger event">{formatEvent(info.event)}</Field>}
                <Field label="Confidence">{picked.confidence ?? "-"}</Field>
                <Field label="Kernel ts">
                  <span className="font-mono">{formatKts(picked.ts)}</span>
                </Field>
              </dl>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

export default Detection;
