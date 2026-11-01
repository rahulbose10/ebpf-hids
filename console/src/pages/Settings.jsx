import { useState } from "react";

// Everything on this page lives in React state. Nothing is sent to the
// backend: the user, API key and alerting endpoints (/api/users, /api/apikeys,
// /api/alerting) belong to L4 and are not wired yet. The page says so at the
// top, and every action says so again in the notice line.

const FIELD =
  "w-full min-w-0 rounded border border-line bg-ink px-2.5 py-1.5 text-[12px] text-text outline-none [color-scheme:dark] placeholder:text-mute focus:border-signal";

const PRIMARY =
  "rounded border border-signal/40 bg-signal/10 px-3 py-1.5 text-[12px] font-medium text-signal transition hover:bg-signal/20";

const SECONDARY =
  "rounded border border-line bg-ink px-3 py-1.5 text-[12px] text-text transition hover:border-mute";

const KEY_CHARS = "abcdefghijkmnopqrstuvwxyz23456789";

export default function Settings() {
  const [users, setUsers] = useState([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");

  const [apiKeys, setApiKeys] = useState([]);

  const [webhookUrl, setWebhookUrl] = useState("");
  const [severity, setSeverity] = useState("high");
  const [throttle, setThrottle] = useState("60");
  const [mirrorSyslog, setMirrorSyslog] = useState(false);
  const [deliveries, setDeliveries] = useState([]);

  const [notice, setNotice] = useState("");

  function createUser(event) {
    event.preventDefault();
    const name = username.trim();

    if (!name || !password) {
      setNotice("Enter a username and a password.");
      return;
    }
    if (users.some((user) => user.name === name)) {
      setNotice("That username is already in the local list.");
      return;
    }

    setUsers((current) => [...current, { id: Date.now(), name, role }]);
    setUsername("");
    // The password is never kept: it is cleared as soon as the row is added.
    setPassword("");
    setNotice("Added to the local list only. No server account was created.");
  }

  function changeRole(id, nextRole) {
    setUsers((current) => current.map((user) => (user.id === id ? { ...user, role: nextRole } : user)));
    setNotice("Role changed in the local list only.");
  }

  function deleteUser(id) {
    setUsers((current) => current.filter((user) => user.id !== id));
    setNotice("Removed from the local list only.");
  }

  function createApiKey() {
    const random = Array.from({ length: 24 }, () => KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)]).join("");
    const value = `demo_${random}`;

    setApiKeys((current) => [...current, { id: Date.now(), name: `Demo key ${current.length + 1}`, value }]);
    setNotice("Demo key made in the browser. It is not a real API key and the server does not know it.");
  }

  function revokeApiKey(id) {
    setApiKeys((current) => current.filter((key) => key.id !== id));
    setNotice("Demo key removed from the local list.");
  }

  function saveAlerting(event) {
    event.preventDefault();
    const seconds = Number(throttle);

    if (!Number.isFinite(seconds) || seconds < 0) {
      setNotice("Throttle must be zero or a positive number.");
      return;
    }
    setNotice("Values checked in the browser. No server setting was changed.");
  }

  function testAlerting() {
    setDeliveries((current) => [
      {
        id: Date.now(),
        time: new Date().toLocaleTimeString("en-GB"),
        message: `Local test at ${severity} severity. Nothing was sent.`,
      },
      ...current,
    ]);
    setNotice("Test recorded in this page only. No webhook was called.");
  }

  return (
    <div>
      <div className="page-header">
        <div className="eyebrow">System / configuration</div>
        <h1>Settings</h1>
        <p>Alerting, users and API keys.</p>
      </div>

      <div className="mb-3 rounded border border-medium/40 bg-medium/10 px-3 py-2 font-mono text-[11px] text-medium">
        Demo mode. Nothing on this page is saved to the server, and a reload clears it. Real management
        needs the backend endpoints /api/alerting, /api/users and /api/apikeys.
      </div>

      {notice && (
        <div role="status" className="mb-3 rounded border border-signal/30 bg-signal/5 px-3 py-2 text-[12px] text-signal">
          {notice}
        </div>
      )}

      <div className="grid gap-3 xl:grid-cols-2">
        <div className="panel self-start">
          <div className="panel-label">Alerting</div>
          <div className="panel-body">
            <form onSubmit={saveAlerting} className="grid gap-3">
              <label className="grid gap-1">
                <span className="eyebrow">Webhook URL (POST JSON on alert)</span>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  className={FIELD}
                  placeholder="https://hooks.example/lab"
                />
              </label>

              <div className="grid grid-cols-2 gap-3">
                <label className="grid gap-1">
                  <span className="eyebrow">Minimum severity</span>
                  <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={FIELD}>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                    <option value="critical">critical</option>
                  </select>
                </label>

                <label className="grid gap-1">
                  <span className="eyebrow">Throttle (s per rule)</span>
                  <input
                    type="number"
                    min="0"
                    value={throttle}
                    onChange={(e) => setThrottle(e.target.value)}
                    className={FIELD}
                  />
                </label>
              </div>

              <label className="flex cursor-pointer items-center gap-2 text-[12px] text-mute">
                <input
                  type="checkbox"
                  checked={mirrorSyslog}
                  onChange={(e) => setMirrorSyslog(e.target.checked)}
                  className="h-4 w-4 accent-signal"
                />
                mirror alerts to local syslog (/dev/log)
              </label>

              <div className="flex flex-wrap gap-2">
                <button type="submit" className={PRIMARY}>
                  Save config
                </button>
                <button type="button" onClick={testAlerting} className={SECONDARY}>
                  Send test alert
                </button>
              </div>
            </form>

            <div className="mt-4 rounded border border-line">
              <div className="eyebrow border-b border-line px-3 py-2">Recent deliveries {deliveries.length}</div>
              {deliveries.length === 0 ? (
                <p className="px-3 py-3 font-mono text-[11px] text-mute">No deliveries.</p>
              ) : (
                deliveries.map((delivery) => (
                  <div key={delivery.id} className="border-b border-line/60 px-3 py-2 last:border-0">
                    <div className="flex justify-between font-mono text-[10px] text-mute">
                      <span className="text-medium">LOCAL TEST</span>
                      <span>browser time {delivery.time}</span>
                    </div>
                    <p className="mt-0.5 text-[12px]">{delivery.message}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="grid content-start gap-3">
          <div className="panel">
            <div className="panel-label">Users and roles</div>
            <div className="panel-body">
              <form onSubmit={createUser} className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_100px_auto]">
                <label className="grid gap-1">
                  <span className="eyebrow">Username</span>
                  <input value={username} onChange={(e) => setUsername(e.target.value)} className={FIELD} autoComplete="off" />
                </label>
                <label className="grid gap-1">
                  <span className="eyebrow">Password</span>
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
                    <option value="viewer">viewer</option>
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                </label>
                <button type="submit" className={PRIMARY}>
                  Add
                </button>
              </form>

              <div className="mt-3 rounded border border-line">
                <div className="grid grid-cols-[1fr_110px_24px] gap-3 border-b border-line px-3 py-2">
                  <span className="eyebrow">Username</span>
                  <span className="eyebrow">Role</span>
                  <span />
                </div>

                {users.length === 0 ? (
                  <p className="px-3 py-3 font-mono text-[11px] text-mute">
                    No users loaded. /api/users is not connected.
                  </p>
                ) : (
                  users.map((user) => (
                    <div
                      key={user.id}
                      className="grid grid-cols-[1fr_110px_24px] items-center gap-3 border-b border-line/60 px-3 py-1.5 last:border-0"
                    >
                      <span className="truncate font-mono text-[12px]">{user.name}</span>
                      <select
                        value={user.role}
                        onChange={(e) => changeRole(user.id, e.target.value)}
                        className={FIELD}
                        aria-label={`Role for ${user.name}`}
                      >
                        <option value="admin">admin</option>
                        <option value="analyst">analyst</option>
                        <option value="viewer">viewer</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => deleteUser(user.id)}
                        className="text-[14px] text-mute transition hover:text-critical"
                        aria-label={`Delete ${user.name}`}
                        title="Delete user"
                      >
                        x
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-label">API keys</div>
            <div className="panel-body">
              <p className="mb-3 text-[12px] leading-snug text-mute">
                Demo keys are generated in the browser only. Do not use them for authentication.
              </p>

              <button type="button" onClick={createApiKey} className={PRIMARY}>
                Create demo key
              </button>

              {apiKeys.length > 0 && (
                <div className="mt-3 grid gap-2">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="flex items-center justify-between gap-3 rounded border border-line px-3 py-2">
                      <div className="min-w-0">
                        <p className="text-[12px]">{key.name}</p>
                        <code className="block break-all font-mono text-[11px] text-mute">{key.value}</code>
                      </div>
                      <button
                        type="button"
                        onClick={() => revokeApiKey(key.id)}
                        className="shrink-0 rounded border border-critical/30 px-2 py-1 text-[11px] text-critical transition hover:bg-critical/10"
                      >
                        Revoke
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
