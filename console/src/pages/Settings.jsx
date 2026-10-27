
import { useState } from "react";

const initialUsers = [
  {
    id: 1,
    name: "SOC Admin",
    email: "admin@ebpf-hids.local",
    role: "Admin",
  },
  {
    id: 2,
    name: "SOC Analyst",
    email: "analyst@ebpf-hids.local",
    role: "Analyst",
  },
];

const fieldClass =
  "w-full min-w-0 rounded border border-line bg-[#111827] px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 outline-none focus:border-signal";

const buttonClass =
  "rounded border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-medium text-signal transition hover:bg-signal/20";

const secondaryButtonClass =
  "rounded border border-line bg-[#111827] px-3 py-2 text-sm text-slate-300 transition hover:bg-slate-800";

function SectionLabel({ children }) {
  return <p className="eyebrow">{children}</p>;
}

export default function Settings() {
  const [users, setUsers] = useState(initialUsers);

  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("Analyst");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [createRole, setCreateRole] = useState("viewer");

  const [apiKeys, setApiKeys] = useState([]);
  const [newKey, setNewKey] = useState("");

  const [webhookUrl, setWebhookUrl] = useState(
    "https://hooks.example/lab"
  );
  const [severity, setSeverity] = useState("high");
  const [throttle, setThrottle] = useState("60");
  const [mirrorSyslog, setMirrorSyslog] = useState(false);
  const [deliveries, setDeliveries] = useState([]);

  const [notice, setNotice] = useState("");

  function addUser(event) {
    event.preventDefault();

    if (!userName.trim() || !userEmail.trim()) {
      setNotice("Please enter the user's name and email.");
      return;
    }

    setUsers((current) => [
      ...current,
      {
        id: Date.now(),
        name: userName.trim(),
        email: userEmail.trim(),
        role: userRole,
      },
    ]);

    setUserName("");
    setUserEmail("");
    setNotice("Demo user added locally. The server was not changed.");
  }

  function changeRole(id, role) {
    setUsers((current) =>
      current.map((user) =>
        user.id === id ? { ...user, role } : user
      )
    );

    setNotice("Demo role updated locally.");
  }

  function deleteUser(id) {
    setUsers((current) =>
      current.filter((user) => user.id !== id)
    );

    setNotice("Demo user removed locally.");
  }

  function createApiKey() {
    const chars = "abcdefghijkmnopqrstuvwxyz23456789";

    const randomPart = Array.from(
      { length: 24 },
      () => chars[Math.floor(Math.random() * chars.length)]
    ).join("");

    const key = `demo_${randomPart}`;
    const id = Date.now();

    setApiKeys((current) => [
      ...current,
      {
        id,
        name: `Demo key ${current.length + 1}`,
        value: key,
      },
    ]);

    setNewKey(key);
    setNotice(
      "Demo key created in the browser. It is not a real API key."
    );
  }

  function revokeApiKey(id) {
    setApiKeys((current) =>
      current.filter((key) => key.id !== id)
    );

    setNewKey("");
    setNotice("Demo key revoked locally.");
  }

  function createUser(event) {
    event.preventDefault();

    if (!username.trim() || !password) {
      setNotice("Enter a username and password.");
      return;
    }

    setNotice(
      "User creation is a UI demo only. No server account was created."
    );
  }

  function saveAlerting(event) {
    event.preventDefault();

    const seconds = Number(throttle);

    if (!Number.isFinite(seconds) || seconds < 0) {
      setNotice("Throttle must be zero or a positive number.");
      return;
    }

    setNotice(
      "Configuration validated locally. No server settings were changed."
    );
  }

  function testAlerting() {
    const entry = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      status: "DEMO",
      message: `Local test requested at ${severity} severity.`,
    };

    setDeliveries((current) => [entry, ...current]);

    setNotice(
      "Demo test recorded locally. No webhook or server alert was sent."
    );
  }

  return (
    <main className="settings-page min-h-full space-y-5 p-4 text-text sm:p-6">
      <style>{`
        .settings-page input,
        .settings-page select,
        .settings-page textarea {
          color-scheme: dark;
          background-color: #111827;
          color: #e2e8f0;
          border-color: #334155;
        }

        .settings-page input::placeholder {
          color: #64748b;
          opacity: 1;
        }

        .settings-page select option {
          background-color: #111827;
          color: #e2e8f0;
        }

        .settings-page input[type="checkbox"] {
          accent-color: #43d9c5;
        }
      `}</style>

      <header>
        <SectionLabel>SYSTEM / CONFIGURATION</SectionLabel>

        <h1 className="mt-2 font-display text-2xl font-semibold">
          Settings
        </h1>

        <p className="mt-2 max-w-3xl text-sm leading-6 text-mute">
          Alerting integrations and access control. Changes on this demo
          page remain local and are not saved to the server.
        </p>
      </header>

      {notice && (
        <div
          className="panel border-signal/30 p-3 text-sm text-signal"
          role="status"
        >
          {notice}
        </div>
      )}

      <section className="panel p-4 sm:p-5">
        <SectionLabel>ALERTING</SectionLabel>

        <div className="mt-4 grid grid-cols-1 gap-5 xl:grid-cols-[1.05fr_1fr]">
          <form onSubmit={saveAlerting} className="space-y-4">
            <label className="block">
              <span className="eyebrow">
                WEBHOOK URL (POST JSON ON ALERT)
              </span>

              <input
                type="url"
                value={webhookUrl}
                onChange={(event) =>
                  setWebhookUrl(event.target.value)
                }
                className={`${fieldClass} mt-2`}
                placeholder="https://hooks.example/lab"
              />
            </label>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="eyebrow">MINIMUM SEVERITY</span>

                <select
                  value={severity}
                  onChange={(event) =>
                    setSeverity(event.target.value)
                  }
                  className={`${fieldClass} mt-2`}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>

              <label className="block">
                <span className="eyebrow">
                  THROTTLE (SECONDS/RULE)
                </span>

                <input
                  type="number"
                  min="0"
                  value={throttle}
                  onChange={(event) =>
                    setThrottle(event.target.value)
                  }
                  className={`${fieldClass} mt-2`}
                />
              </label>
            </div>

            <label className="flex cursor-pointer items-center gap-2 text-sm text-mute">
              <input
                type="checkbox"
                checked={mirrorSyslog}
                onChange={(event) =>
                  setMirrorSyslog(event.target.checked)
                }
                className="h-4 w-4"
              />

              mirror alerts to local syslog (/dev/log)
            </label>

            <div className="flex flex-wrap gap-2 pt-1">
              <button type="submit" className={buttonClass}>
                Save config
              </button>

              <button
                type="button"
                onClick={testAlerting}
                className={secondaryButtonClass}
              >
                Send test alert
              </button>
            </div>
          </form>

          <div className="overflow-hidden rounded-md border border-line">
            <div className="border-b border-line px-3 py-3">
              <SectionLabel>
                RECENT DELIVERIES · {deliveries.length}
              </SectionLabel>
            </div>

            {deliveries.length === 0 ? (
              <div className="flex min-h-36 items-center justify-center p-5 text-center">
                <p className="text-xs leading-5 text-mute">
                  No deliveries yet. Alerts above the severity floor
                  will appear here.
                </p>
              </div>
            ) : (
              <div>
                {deliveries.map((delivery) => (
                  <div
                    key={delivery.id}
                    className="border-b border-line p-3 last:border-b-0"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs text-signal">
                        {delivery.status}
                      </span>

                      <span className="font-mono text-xs text-mute">
                        {delivery.time}
                      </span>
                    </div>

                    <p className="mt-2 text-sm">
                      {delivery.message}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="panel p-4 sm:p-5">
        <SectionLabel>USERS &amp; ROLES</SectionLabel>

        <form
          onSubmit={createUser}
          className="mt-4 grid grid-cols-1 items-end gap-3 lg:grid-cols-[1fr_1fr_120px_auto]"
        >
          <label className="block">
            <span className="eyebrow">USERNAME</span>

            <input
              value={username}
              onChange={(event) =>
                setUsername(event.target.value)
              }
              className={`${fieldClass} mt-2`}
              autoComplete="off"
            />
          </label>

          <label className="block">
            <span className="eyebrow">PASSWORD</span>

            <input
              type="password"
              value={password}
              onChange={(event) =>
                setPassword(event.target.value)
              }
              className={`${fieldClass} mt-2`}
              autoComplete="new-password"
            />
          </label>

          <label className="block">
            <span className="eyebrow">ROLE</span>

            <select
              value={createRole}
              onChange={(event) =>
                setCreateRole(event.target.value)
              }
              className={`${fieldClass} mt-2`}
            >
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
          </label>

          <button type="submit" className={buttonClass}>
            Create
          </button>
        </form>

        <div className="mt-4 overflow-x-auto rounded-md border border-line">
          <div className="grid min-w-[540px] grid-cols-[1fr_100px_100px_24px] gap-3 border-b border-line px-3 py-3">
            <SectionLabel>USERNAME</SectionLabel>
            <SectionLabel>ROLE</SectionLabel>
            <SectionLabel>CREATED</SectionLabel>
            <span />
          </div>

          {users.map((user) => (
            <div
              key={user.id}
              className="grid min-w-[540px] grid-cols-[1fr_100px_100px_24px] items-center gap-3 border-b border-line px-3 py-3 last:border-b-0"
            >
              <div className="min-w-0">
                <p className="truncate text-sm">{user.name}</p>

                <p className="mt-1 truncate text-xs text-mute">
                  {user.email}
                </p>
              </div>

              <select
                value={user.role}
                onChange={(event) =>
                  changeRole(user.id, event.target.value)
                }
                className="w-full rounded border border-line bg-[#111827] px-2 py-1.5 text-xs text-slate-200"
                aria-label={`Role for ${user.name}`}
              >
                <option value="Admin">admin</option>
                <option value="Analyst">analyst</option>
                <option value="Viewer">viewer</option>
              </select>

              <span className="text-xs text-mute">demo</span>

              <button
                type="button"
                onClick={() => deleteUser(user.id)}
                className="text-sm text-mute transition hover:text-red-400"
                aria-label={`Delete ${user.name}`}
                title="Delete user"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-4 sm:p-5">
        <SectionLabel>API KEYS</SectionLabel>

        <h2 className="mt-2 text-base font-semibold">
          API Keys
        </h2>

        <p className="mt-2 text-sm text-mute">
          Demo keys are generated in the browser only. Do not use
          them for authentication.
        </p>

        <button
          type="button"
          onClick={createApiKey}
          className={`${buttonClass} mt-4`}
        >
          Create demo key
        </button>

        {newKey && (
          <div className="mt-4 rounded border border-yellow-400/30 bg-yellow-400/5 p-3">
            <p className="eyebrow text-yellow-300">
              DEMO KEY · SHOWN FOR THIS SESSION
            </p>

            <code className="mt-2 block break-all text-sm text-slate-200">
              {newKey}
            </code>
          </div>
        )}

        {apiKeys.length > 0 && (
          <div className="mt-4 space-y-2">
            {apiKeys.map((key) => (
              <div
                key={key.id}
                className="flex flex-wrap items-center justify-between gap-3 rounded border border-line p-3"
              >
                <div>
                  <p className="text-sm">{key.name}</p>

                  <p className="mt-1 text-xs text-mute">
                    Browser-only demo key
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => revokeApiKey(key.id)}
                  className="rounded border border-red-500/30 px-3 py-2 text-sm text-red-400 transition hover:bg-red-500/10"
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <p className="text-xs leading-5 text-mute">
        DEMO MODE: user, API key and alerting changes are stored in
        React state only. Refreshing the page resets them. Real
        management requires supported backend API endpoints.
      </p>
    </main>
  );
}
