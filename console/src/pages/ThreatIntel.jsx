import { useState } from "react";
import { threatIntelMock } from "../mock";
import SeverityChip from "../components/SeverityChip";

// The engine matches IP indicators on connect/bind and path indicators on
// file events, so those are the only two types this page can hold.
const SHOWN_TYPES = ["IP", "PATH"];

const FIELD =
  "w-full rounded border border-line bg-ink px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-signal";

function fromMock(item) {
  return {
    id: item.id,
    type: item.type === "FILE" ? "PATH" : item.type,
    value: item.indicator,
    label: item.category || item.source || "",
    severity: item.severity || "medium",
  };
}

// Defined at module level, not inside ThreatIntel. A component declared inside
// another one is a new component on every render, so React throws away its DOM
// each time the parent updates.
function IndicatorTable({ title, items, onDelete }) {
  return (
    <div className="panel">
      <div className="panel-label">
        {title} <span className="ml-2 text-signal">{items.length}</span>
      </div>

      <div className="panel-body">
        {items.length === 0 ? (
          <p className="py-2 font-mono text-[11px] text-mute">none</p>
        ) : (
          items.map((item) => (
            <div
              key={item.id}
              className="flex items-center gap-3 border-b border-line/60 py-2 last:border-0"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-[12px] text-text" title={item.value}>
                  {item.value}
                </p>
                {item.label && <p className="truncate text-[11px] text-mute">{item.label}</p>}
              </div>

              <SeverityChip severity={item.severity} />

              <button
                type="button"
                onClick={() => onDelete(item.id)}
                className="rounded border border-critical/30 px-2 py-0.5 text-[11px] text-critical hover:bg-critical/10"
              >
                Delete
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default function ThreatIntel() {
  const [indicators, setIndicators] = useState((threatIntelMock?.iocs ?? []).map(fromMock));

  const [type, setType] = useState("IP");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [severity, setSeverity] = useState("high");

  const shown = indicators.filter((item) => SHOWN_TYPES.includes(item.type));
  const hidden = indicators.length - shown.length;
  const ipIndicators = shown.filter((item) => item.type === "IP");
  const pathIndicators = shown.filter((item) => item.type === "PATH");

  function addIndicator(event) {
    event.preventDefault();
    const cleanValue = value.trim();
    if (!cleanValue) return;

    const exists = indicators.some(
      (item) => item.type === type && item.value.toLowerCase() === cleanValue.toLowerCase()
    );
    if (exists) return;

    setIndicators((current) => [
      ...current,
      { id: Date.now(), type, value: cleanValue, label: label.trim(), severity },
    ]);
    setValue("");
    setLabel("");
  }

  function deleteIndicator(id) {
    setIndicators((current) => current.filter((item) => item.id !== id));
  }

  return (
    <div>
      <div className="page-header flex items-start justify-between gap-4">
        <div>
          <div className="eyebrow">Indicators of compromise</div>
          <h1>Threat Intelligence</h1>
          <p>
            IP indicators match outbound connects and listening binds. Path indicators match file
            touch, unlink, rename and chmod.
          </p>
        </div>

        <div className="shrink-0 text-right">
          <div className="font-mono text-2xl leading-none text-signal">{shown.length}</div>
          <div className="eyebrow mt-1">Indexed</div>
        </div>
      </div>

      <div className="mb-3 rounded border border-medium/40 bg-medium/10 px-3 py-2 font-mono text-[11px] text-medium">
        Demo data. Indicators here live in this browser tab only. Nothing is sent to the backend, so
        the engine does not match against them, and a reload resets the list.
        {hidden > 0 && ` ${hidden} sample entry of an unsupported type (domain) is not shown.`}
      </div>

      <div className="panel mb-3">
        <div className="panel-label">Add indicator</div>
        <form
          onSubmit={addIndicator}
          className="grid gap-3 p-3 xl:grid-cols-[140px_minmax(160px,1fr)_minmax(160px,1fr)_110px_auto]"
        >
          <label className="grid gap-1">
            <span className="eyebrow">Type</span>
            <select value={type} onChange={(e) => setType(e.target.value)} className={FIELD}>
              <option value="IP">IP address</option>
              <option value="PATH">Path</option>
            </select>
          </label>

          <label className="grid gap-1">
            <span className="eyebrow">Value</span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={type === "IP" ? "203.0.113.10" : "/tmp/test-file"}
              className={FIELD}
            />
          </label>

          <label className="grid gap-1">
            <span className="eyebrow">Label</span>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="C2 server / ransom note"
              className={FIELD}
            />
          </label>

          <label className="grid gap-1">
            <span className="eyebrow">Severity</span>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={FIELD}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>

          <div className="flex items-end">
            <button
              type="submit"
              className="w-full rounded border border-signal/40 bg-signal/10 px-4 py-1.5 text-[12px] text-signal hover:bg-signal/20"
            >
              Add
            </button>
          </div>
        </form>

        <p className="px-3 pb-3 text-[11px] text-mute">
          Path indicators accept glob patterns (*, ?). Use lab-only test artifacts.
        </p>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        <IndicatorTable title="IP indicators" items={ipIndicators} onDelete={deleteIndicator} />
        <IndicatorTable title="Path indicators" items={pathIndicators} onDelete={deleteIndicator} />
      </div>
    </div>
  );
}
