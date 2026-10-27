
import { useState } from "react";
import { threatIntelMock } from "../mock";

export default function ThreatIntel() {
  const [indicators, setIndicators] = useState(
    (threatIntelMock?.iocs ?? []).map((item) => ({
      id: item.id,
      type: item.type === "FILE" ? "PATH" : item.type,
      value: item.indicator,
      label: item.category || item.source || "",
      severity: item.severity || "medium",
    }))
  );

  const [type, setType] = useState("IP");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [severity, setSeverity] = useState("high");

  const ipIndicators = indicators.filter((item) => item.type === "IP");
  const pathIndicators = indicators.filter(
    (item) => item.type === "PATH"
  );

  function addIndicator(event) {
    event.preventDefault();

    const cleanValue = value.trim();

    if (!cleanValue) return;

    const exists = indicators.some(
      (item) =>
        item.type === type &&
        item.value.toLowerCase() === cleanValue.toLowerCase()
    );

    if (exists) return;

    setIndicators((current) => [
      ...current,
      {
        id: Date.now(),
        type,
        value: cleanValue,
        label: label.trim(),
        severity,
      },
    ]);

    setValue("");
    setLabel("");
  }

  function deleteIndicator(id) {
    setIndicators((current) =>
      current.filter((item) => item.id !== id)
    );
  }

  function IndicatorTable({ title, items }) {
    return (
      <section className="panel overflow-hidden">
        <div className="border-b border-line px-4 py-3">
          <p className="eyebrow">
            {title} <span className="text-signal">• {items.length}</span>
          </p>
        </div>

        <div className="flex min-h-16 items-center justify-center px-4 py-5">
          {items.length === 0 ? (
            <p className="text-sm text-mute">
              no {title.toLowerCase()}
            </p>
          ) : (
            <div className="w-full space-y-3">
              {items.map((item) => (
                <div
                  key={item.id}
                  className="flex flex-wrap items-center justify-between gap-3 border-b border-line/70 py-2 last:border-0"
                >
                  <div className="min-w-0 flex-1">
                    <p className="break-all font-mono text-sm text-text">
                      {item.value}
                    </p>
                    {item.label && (
                      <p className="mt-1 text-xs text-mute">
                        {item.label}
                      </p>
                    )}
                  </div>

                  <span className="font-mono text-xs uppercase text-mute">
                    {item.severity}
                  </span>

                  <button
                    type="button"
                    onClick={() => deleteIndicator(item.id)}
                    className="rounded border border-red-500/30 px-2 py-1 text-xs text-red-400 hover:bg-red-500/10"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    );
  }

  return (
    <main className="min-h-full space-y-5 p-4 text-text sm:p-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold">
            Threat Intelligence
          </h1>
          <p className="mt-2 text-sm leading-6 text-mute">
            Indicators of compromise matched live against the event stream.
            IP indicators hit on outbound connects and listening binds;
            path indicators hit on file touch, unlink, rename and chmod.
          </p>
        </div>

        <div className="text-right">
          <p className="stat-num text-3xl text-signal">
            {indicators.length}
          </p>
          <p className="eyebrow">INDICATORS INDEXED</p>
        </div>
      </header>

      <section className="panel overflow-hidden">
        <div className="border-b border-line px-4 py-3">
          <p className="eyebrow">ADD INDICATOR</p>
        </div>

        <form
          onSubmit={addIndicator}
          className="grid gap-3 p-4 xl:grid-cols-[100px_minmax(160px,1fr)_minmax(160px,1fr)_110px_auto]"
        >
          <label className="space-y-2">
            <span className="eyebrow">TYPE</span>
            <select
              value={type}
              onChange={(event) => setType(event.target.value)}
              className="w-full rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            >
              <option value="IP">IP address</option>
              <option value="PATH">Path</option>
            </select>
          </label>

          <label className="space-y-2">
            <span className="eyebrow">VALUE</span>
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={
                type === "IP" ? "203.0.113.10" : "/tmp/test-file"
              }
              className="w-full rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            />
          </label>

          <label className="space-y-2">
            <span className="eyebrow">LABEL</span>
            <input
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="C2 server / ransom note"
              className="w-full rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            />
          </label>

          <label className="space-y-2">
            <span className="eyebrow">SEVERITY</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="w-full rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>

          <div className="flex items-end">
            <button
              type="submit"
              className="w-full rounded-md border border-signal/40 bg-signal/10 px-4 py-2.5 text-sm text-signal hover:bg-signal/20"
            >
              Add
            </button>
          </div>
        </form>

        <p className="px-4 pb-4 text-xs text-mute">
          Path indicators accept glob patterns (*, ?). Use lab-only test
          artifacts.
        </p>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <IndicatorTable
          title="IP INDICATORS"
          items={ipIndicators}
        />

        <IndicatorTable
          title="PATH INDICATORS"
          items={pathIndicators}
        />
      </section>
    </main>
  );
}
