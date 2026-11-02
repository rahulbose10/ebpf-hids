import { useState } from "react";
import { api, roleAtLeast, usePoll, useSession } from "../api";
import { formatWallTime } from "../format";

const FIELD =
  "w-full rounded border border-line bg-ink px-2.5 py-1.5 font-mono text-[12px] outline-none focus:border-signal disabled:cursor-not-allowed disabled:opacity-50";

const TYPE_INFO = {
  ip: {
    title: "IP indicators",
    placeholder: "203.0.113.10 or 10.0.0.*",
    hint: "Compared with the address of a CONNECT or BIND event.",
  },
  path: {
    title: "Path indicators",
    placeholder: "/tmp/payload or */evil.sh",
    hint: "Compared with the path of a file event. Paths are case sensitive.",
  },
  hash: {
    title: "Hash indicators",
    placeholder: "md5, sha1 or sha256 in hex",
    hint: "Stored, but never matches: the sensor does not hash files.",
  },
};

function IndicatorTable({ type, items, canEdit, busyId, onDelete }) {
  const info = TYPE_INFO[type] ?? { title: type, hint: "" };

  return (
    <div className="panel min-w-0">
      <div className="panel-label">
        {info.title} <span className="ml-2 text-signal">{items.length}</span>
      </div>

      <div className="panel-body">
        <p className="mb-2 text-[11px] text-mute">{info.hint}</p>
        {items.length === 0 ? (
          <p className="py-2 font-mono text-[11px] text-mute">none</p>
        ) : (
          items.map((item) => (
            <div key={item.id} className="flex items-center gap-3 border-b border-line/60 py-2 last:border-0">
              <div className="min-w-0 flex-1">
                <p className="break-all font-mono text-[12px] text-text">{item.value}</p>
                {item.description && <p className="text-[11px] text-mute">{item.description}</p>}
                <p className="font-mono text-[10px] text-mute">
                  #{item.id} added by {item.added_by ?? "-"} at {formatWallTime(item.ts)}
                </p>
              </div>

              <button
                type="button"
                onClick={() => onDelete(item.id)}
                disabled={!canEdit || busyId === item.id}
                className="rounded border border-critical/30 px-2 py-0.5 text-[11px] text-critical hover:bg-critical/10 disabled:cursor-not-allowed disabled:opacity-50"
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
  const me = useSession();
  const canEdit = roleAtLeast(me?.role, "analyst");

  const poll = usePoll(api.iocs, 5000);
  const iocs = poll.data?.iocs ?? [];
  const types = poll.data?.types ?? ["ip", "path", "hash"];

  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [adding, setAdding] = useState(false);
  const [formError, setFormError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [busyId, setBusyId] = useState(null);

  async function addIndicator(event) {
    event.preventDefault();
    setAdding(true);
    setFormError("");
    setFormMessage("");
    try {
      const created = await api.addIoc(type, value, description);
      setFormMessage(`Added #${created.id}: ${created.type} ${created.value}`);
      setValue("");
      setDescription("");
      await poll.refresh();
    } catch (err) {
      setFormError(err?.error || "The server did not accept the indicator.");
    } finally {
      setAdding(false);
    }
  }

  async function deleteIndicator(id) {
    setBusyId(id);
    setFormError("");
    setFormMessage("");
    try {
      await api.deleteIoc(id);
      setFormMessage(`Deleted #${id}.`);
      await poll.refresh();
    } catch (err) {
      setFormError(err?.error || "The server did not delete the indicator.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <div className="page-header flex items-start justify-between gap-4">
        <div>
          <div className="eyebrow">Indicators of compromise</div>
          <h1>Threat Intelligence</h1>
          <p>
            Indicators are stored on the server. When a rule raises an alert, its event is compared
            with them and any match is attached to the alert.
          </p>
        </div>

        <div className="shrink-0 text-right">
          <div className="font-mono text-2xl leading-none text-signal">{poll.data ? iocs.length : "-"}</div>
          <div className="eyebrow mt-1">Stored</div>
        </div>
      </div>

      {poll.error && (
        <div className="mb-3 rounded border border-critical/45 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
          Could not load /api/iocs: {poll.error.error || "no answer"}
        </div>
      )}

      {poll.data?.note && (
        <div className="mb-3 rounded border border-line bg-ink-700 px-3 py-2 font-mono text-[11px] text-mute">
          Server note: {poll.data.note}. Indicators added now only affect alerts raised from now on.
        </div>
      )}

      <div className="panel mb-3">
        <div className="panel-label">Add indicator</div>
        <form
          onSubmit={addIndicator}
          className="grid gap-3 p-3 xl:grid-cols-[140px_minmax(180px,1fr)_minmax(180px,1fr)_auto]"
        >
          <label className="grid gap-1">
            <span className="eyebrow">Type</span>
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              disabled={!canEdit}
              className={FIELD}
            >
              {types.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>

          <label className="grid gap-1">
            <span className="eyebrow">Value</span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={TYPE_INFO[type]?.placeholder}
              disabled={!canEdit}
              className={FIELD}
            />
          </label>

          <label className="grid gap-1">
            <span className="eyebrow">Description (optional)</span>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="lab test indicator"
              disabled={!canEdit}
              className={FIELD}
            />
          </label>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={!canEdit || adding || value.trim() === ""}
              className="w-full rounded border border-signal/40 bg-signal/10 px-4 py-1.5 text-[12px] text-signal hover:bg-signal/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {adding ? "Adding..." : "Add"}
            </button>
          </div>
        </form>

        <div className="px-3 pb-3 text-[11px] text-mute">
          <p>
            * and ? work as wildcards in ip and path values. The server trims the value, writes IP
            addresses in standard form and lowercases hashes, so what is stored can differ from what
            was typed.
          </p>
          {!canEdit && (
            <p className="mt-1">
              Adding and deleting needs the analyst role. You are signed in as {me?.role ?? "unknown role"}.
            </p>
          )}
          {formError && <p className="mt-1 font-mono text-critical">{formError}</p>}
          {formMessage && <p className="mt-1 font-mono text-signal">{formMessage}</p>}
        </div>
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        {types.map((name) => (
          <IndicatorTable
            key={name}
            type={name}
            items={iocs.filter((item) => item.type === name)}
            canEdit={canEdit}
            busyId={busyId}
            onDelete={deleteIndicator}
          />
        ))}
      </div>

      <p className="mt-3 font-mono text-[10px] text-mute">Times on this page are the server&apos;s wall clock.</p>
    </div>
  );
}
