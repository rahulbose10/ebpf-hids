import { useState } from "react";
import { api, roleAtLeast, usePoll, useSession } from "../api";
import { formatWallTime } from "../format";

const FIELD =
  "w-full min-w-0 rounded border border-line bg-ink px-2.5 py-1.5 text-[12px] text-text outline-none [color-scheme:dark] placeholder:text-mute focus:border-signal disabled:cursor-not-allowed disabled:opacity-50";

const PRIMARY =
  "rounded border border-signal/40 bg-signal/10 px-3 py-1.5 text-[12px] font-medium text-signal transition hover:bg-signal/20 disabled:cursor-not-allowed disabled:opacity-50";

const SECONDARY =
  "rounded border border-line bg-ink px-3 py-1.5 text-[12px] text-text transition hover:border-mute disabled:cursor-not-allowed disabled:opacity-50";

const DANGER =
  "shrink-0 rounded border border-critical/30 px-2 py-1 text-[11px] text-critical transition hover:bg-critical/10 disabled:cursor-not-allowed disabled:opacity-50";

const STATUS_STYLE = {
  sent: "text-signal",
  failed: "text-critical",
};

function Message({ error, text }) {
  if (error) return <p className="mt-2 font-mono text-[11px] text-critical">{error}</p>;
  if (text) return <p className="mt-2 font-mono text-[11px] text-signal">{text}</p>;
  return null;
}

function LoadError({ error, path }) {
  if (!error) return null;
  return (
    <p className="mb-2 font-mono text-[11px] text-critical">
      Could not load {path}: {error.error || "no answer"}
    </p>
  );
}

function AlertingForm({ state, onSaved }) {
  const [enabled, setEnabled] = useState(Boolean(state.enabled));
  const [minSeverity, setMinSeverity] = useState(state.min_severity);
  const [throttle, setThrottle] = useState(String(state.throttle_seconds));
  const [webhookUrl, setWebhookUrl] = useState(state.webhook_url);
  const [syslogEnabled, setSyslogEnabled] = useState(Boolean(state.syslog_enabled));
  const [syslogHost, setSyslogHost] = useState(state.syslog_host);
  const [syslogPort, setSyslogPort] = useState(String(state.syslog_port));

  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [testResults, setTestResults] = useState(null);

  const asNumber = (text) => (/^\d+$/.test(text.trim()) ? Number(text.trim()) : text);

  async function save(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");
    try {
      await api.setAlerting({
        enabled,
        min_severity: minSeverity,
        throttle_seconds: asNumber(throttle),
        webhook_url: webhookUrl.trim(),
        syslog_enabled: syslogEnabled,
        syslog_host: syslogHost.trim(),
        syslog_port: asNumber(syslogPort),
      });
      setMessage("Saved. The server applies it until it restarts.");
      await onSaved();
    } catch (err) {
      setError(err?.error || "The server did not accept the settings.");
    } finally {
      setSaving(false);
    }
  }

  async function sendTest() {
    setTesting(true);
    setError("");
    setMessage("");
    setTestResults(null);
    try {
      const reply = await api.testAlerting();
      setTestResults(reply.results);
      await onSaved();
    } catch (err) {
      setError(err?.error || "The test did not run.");
    } finally {
      setTesting(false);
    }
  }

  return (
    <form onSubmit={save} className="grid gap-3">
      <label className="flex cursor-pointer items-center gap-2 text-[12px] text-text">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-4 w-4 accent-signal"
        />
        Send notifications for new alerts
      </label>

      <label className="grid gap-1">
        <span className="eyebrow">Webhook URL (POST JSON on alert)</span>
        <input
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
          className={FIELD}
          placeholder="http://127.0.0.1:9000/hook"
        />
      </label>

      <div className="grid grid-cols-2 gap-3">
        <label className="grid gap-1">
          <span className="eyebrow">Minimum severity</span>
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)} className={FIELD}>
            {state.severities.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1">
          <span className="eyebrow">Throttle (seconds per rule)</span>
          <input value={throttle} onChange={(e) => setThrottle(e.target.value)} className={FIELD} inputMode="numeric" />
        </label>
      </div>

      <label className="flex cursor-pointer items-center gap-2 text-[12px] text-text">
        <input
          type="checkbox"
          checked={syslogEnabled}
          onChange={(e) => setSyslogEnabled(e.target.checked)}
          className="h-4 w-4 accent-signal"
        />
        Send alerts as syslog over UDP
      </label>

      <div className="grid grid-cols-[1fr_110px] gap-3">
        <label className="grid gap-1">
          <span className="eyebrow">Syslog host</span>
          <input value={syslogHost} onChange={(e) => setSyslogHost(e.target.value)} className={FIELD} />
        </label>
        <label className="grid gap-1">
          <span className="eyebrow">UDP port</span>
          <input value={syslogPort} onChange={(e) => setSyslogPort(e.target.value)} className={FIELD} inputMode="numeric" />
        </label>
      </div>

      <div className="flex flex-wrap gap-2">
        <button type="submit" disabled={saving} className={PRIMARY}>
          {saving ? "Saving..." : "Save"}
        </button>
        <button type="button" onClick={sendTest} disabled={testing} className={SECONDARY}>
          {testing ? "Sending..." : "Send test alert"}
        </button>
      </div>

      <p className="text-[11px] leading-snug text-mute">
        The test sends a made-up low severity alert to every channel that is set and ignores the
        throttle and the minimum severity. Save first, because the test uses the saved settings.
      </p>

      <Message error={error} text={message} />

      {testResults && (
        <div className="rounded border border-line px-3 py-2 font-mono text-[11px]">
          {Object.entries(testResults).map(([channel, result]) => (
            <p key={channel}>
              <span className="text-text">{channel}</span>{" "}
              <span className={STATUS_STYLE[result.status] || "text-mute"}>{result.status}</span>{" "}
              <span className="text-mute">{result.detail}</span>
            </p>
          ))}
        </div>
      )}
    </form>
  );
}

function AlertingPanel() {
  const poll = usePoll(api.alerting, 5000);
  const state = poll.data;
  const deliveries = state?.deliveries ?? [];

  return (
    <div className="panel self-start">
      <div className="panel-label">Alerting</div>
      <div className="panel-body">
        <LoadError error={poll.error} path="/api/alerting" />
        {state ? (
          <AlertingForm state={state} onSaved={poll.refresh} />
        ) : (
          !poll.error && <p className="font-mono text-[11px] text-mute">Loading.</p>
        )}

        {state && (
          <>
            <p className="mt-3 font-mono text-[11px] text-mute">
              Active channels: {state.channels.length ? state.channels.join(", ") : "none"}. Since the
              server started: {state.stats.sent} sent, {state.stats.failed} failed, {state.stats.throttled}{" "}
              throttled, {state.stats.below_severity} below the minimum severity.
            </p>
            {state.note && <p className="font-mono text-[11px] text-mute">Server note: {state.note}.</p>}

            <div className="mt-3 rounded border border-line">
              <div className="eyebrow border-b border-line px-3 py-2">Recent deliveries {deliveries.length}</div>
              {deliveries.length === 0 ? (
                <p className="px-3 py-3 font-mono text-[11px] text-mute">No deliveries since the database was created.</p>
              ) : (
                <div className="max-h-[260px] overflow-y-auto">
                  {deliveries.map((delivery) => (
                    <div key={delivery.id} className="border-b border-line/60 px-3 py-2 last:border-0">
                      <div className="flex flex-wrap justify-between gap-2 font-mono text-[10px] text-mute">
                        <span>
                          #{delivery.id} {delivery.channel}{" "}
                          <span className={STATUS_STYLE[delivery.status] || ""}>{delivery.status}</span>
                          {delivery.alert_id != null && ` alert ${delivery.alert_id}`}
                        </span>
                        <span>{formatWallTime(delivery.ts)}</span>
                      </div>
                      <p className="mt-0.5 break-words text-[12px]">{delivery.detail}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function UsersPanel({ self }) {
  const poll = usePoll(api.users, 5000);
  const users = poll.data?.users ?? [];
  const roles = poll.data?.roles ?? ["viewer", "analyst", "admin"];

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function run(label, job, done) {
    setBusy(label);
    setError("");
    setMessage("");
    try {
      await job();
      setMessage(done);
      await poll.refresh();
    } catch (err) {
      setError(err?.error || "The server did not accept the change.");
    } finally {
      setBusy("");
    }
  }

  async function createUser(event) {
    event.preventDefault();
    await run(
      "create",
      async () => {
        await api.addUser(username.trim(), password, role);
        setUsername("");
        setPassword("");
      },
      `Created ${username.trim()} as ${role}.`
    );
  }

  return (
    <div className="panel">
      <div className="panel-label">Users and roles</div>
      <div className="panel-body">
        <LoadError error={poll.error} path="/api/users" />

        <form onSubmit={createUser} className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_100px_auto]">
          <label className="grid gap-1">
            <span className="eyebrow">Username</span>
            <input value={username} onChange={(e) => setUsername(e.target.value)} className={FIELD} autoComplete="off" />
          </label>
          <label className="grid gap-1">
            <span className="eyebrow">Password (8 or more)</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={FIELD}
              autoComplete="new-password"
            />
          </label>
          <label className="grid gap-1">
            <span className="eyebrow">Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value)} className={FIELD}>
              {roles.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={busy !== "" || username.trim() === "" || password === ""} className={PRIMARY}>
            Add
          </button>
        </form>

        <Message error={error} text={message} />

        <div className="mt-3 rounded border border-line">
          <div className="grid grid-cols-[1fr_110px_60px] gap-3 border-b border-line px-3 py-2">
            <span className="eyebrow">Username</span>
            <span className="eyebrow">Role</span>
            <span />
          </div>

          {users.length === 0 ? (
            <p className="px-3 py-3 font-mono text-[11px] text-mute">{poll.data ? "No users." : "Loading."}</p>
          ) : (
            users.map((user) => {
              const isSelf = user.username === self;
              return (
                <div
                  key={user.username}
                  className="grid grid-cols-[1fr_110px_60px] items-center gap-3 border-b border-line/60 px-3 py-1.5 last:border-0"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[12px]">
                      {user.username}
                      {isSelf && <span className="ml-2 text-mute">(you)</span>}
                    </p>
                    <p className="font-mono text-[10px] text-mute">created {formatWallTime(user.created_at)}</p>
                  </div>
                  <select
                    value={user.role}
                    disabled={isSelf || busy !== ""}
                    onChange={(e) =>
                      run(
                        `role-${user.username}`,
                        () => api.setUserRole(user.username, e.target.value),
                        `${user.username} is now ${e.target.value}.`
                      )
                    }
                    className={FIELD}
                    aria-label={`Role for ${user.username}`}
                  >
                    {roles.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    disabled={isSelf || busy !== ""}
                    onClick={() =>
                      run(`delete-${user.username}`, () => api.deleteUser(user.username), `Deleted ${user.username}.`)
                    }
                    className={DANGER}
                    aria-label={`Delete ${user.username}`}
                  >
                    Delete
                  </button>
                </div>
              );
            })
          )}
        </div>
        <p className="mt-2 text-[11px] text-mute">
          You cannot change or delete your own account, and the last admin cannot be removed.
        </p>
      </div>
    </div>
  );
}

function ApiKeysPanel() {
  const poll = usePoll(api.apikeys, 5000);
  const keys = poll.data?.apikeys ?? [];

  const [name, setName] = useState("");
  const [role, setRole] = useState("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [fresh, setFresh] = useState(null);

  async function createKey(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    setFresh(null);
    try {
      const created = await api.addApiKey(name.trim(), role);
      setFresh(created);
      setName("");
      await poll.refresh();
    } catch (err) {
      setError(err?.error || "The server did not create the key.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(key) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await api.deleteApiKey(key.id);
      setMessage(`Revoked key ${key.id} (${key.name}).`);
      await poll.refresh();
    } catch (err) {
      setError(err?.error || "The server did not revoke the key.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <div className="panel-label">API keys</div>
      <div className="panel-body">
        <LoadError error={poll.error} path="/api/apikeys" />

        <form onSubmit={createKey} className="grid items-end gap-3 sm:grid-cols-[1fr_110px_auto]">
          <label className="grid gap-1">
            <span className="eyebrow">Key name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} className={FIELD} autoComplete="off" />
          </label>
          <label className="grid gap-1">
            <span className="eyebrow">Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value)} className={FIELD}>
              {["viewer", "analyst", "admin"].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={busy || name.trim() === ""} className={PRIMARY}>
            Create key
          </button>
        </form>

        <Message error={error} text={message} />

        {fresh && (
          <div className="mt-3 rounded border border-medium/50 bg-medium/10 px-3 py-2">
            <p className="text-[12px] font-medium text-medium">
              Copy this key now. It is shown once and the server cannot show it again.
            </p>
            <code className="mt-1 block break-all font-mono text-[12px] text-text">{fresh.key}</code>
            <p className="mt-1 font-mono text-[10px] text-mute">
              key {fresh.id}, name {fresh.name}, role {fresh.role}
            </p>
            <button type="button" onClick={() => setFresh(null)} className={`${SECONDARY} mt-2`}>
              I have copied it
            </button>
          </div>
        )}

        <div className="mt-3 rounded border border-line">
          {keys.length === 0 ? (
            <p className="px-3 py-3 font-mono text-[11px] text-mute">{poll.data ? "No API keys." : "Loading."}</p>
          ) : (
            keys.map((key) => (
              <div key={key.id} className="flex items-center justify-between gap-3 border-b border-line/60 px-3 py-2 last:border-0">
                <div className="min-w-0">
                  <p className="text-[12px]">
                    {key.name} <span className="font-mono text-[11px] text-mute">#{key.id} {key.role}</span>
                  </p>
                  <p className="font-mono text-[10px] text-mute">
                    created {formatWallTime(key.created_at)}, last used{" "}
                    {key.last_used ? formatWallTime(key.last_used) : "never"}
                  </p>
                </div>
                <button type="button" disabled={busy} onClick={() => revoke(key)} className={DANGER}>
                  Revoke
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export default function Settings() {
  const me = useSession();
  const isAdmin = roleAtLeast(me?.role, "admin");

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">System / configuration</div>
        <h1>Settings</h1>
        <p>Alerting, users and API keys. Every change here goes to the server.</p>
      </div>

      {!isAdmin ? (
        <div className="panel">
          <div className="panel-label">Admin only</div>
          <div className="panel-body text-[12px] text-mute">
            Settings need the admin role. You are signed in as {me?.role ?? "unknown role"}.
          </div>
        </div>
      ) : (
        <div className="grid gap-3 xl:grid-cols-2">
          <AlertingPanel />
          <div className="grid content-start gap-3">
            <UsersPanel self={me?.user} />
            <ApiKeysPanel />
          </div>
        </div>
      )}
    </div>
  );
}
