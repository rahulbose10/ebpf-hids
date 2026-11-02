
import { useState, useEffect, useRef, useCallback } from "react";

async function req(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    headers: {
      "Content-Type": "application/json",
    },
    credentials: "same-origin",
    ...opts,
  });

  if (res.status === 401) {
    if (path !== "/login") {
      window.dispatchEvent(new Event("hids:unauth"));
    }
    throw { unauth: true };
  }

  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw { error: `Request failed (${res.status})`, ...body, status: res.status };
  }

  return body;
}

function send(path, method, payload) {
  return req(path, {
    method,
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

export const api = {
  health: () => req("/health"),

  login: (username, password) =>
    req("/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    req("/logout", {
      method: "POST",
    }),

  me: () => req("/me"),

  events: (limit = 60) =>
    req(`/events?limit=${limit}`),

  processes: () => req("/processes"),

  alerts: () => req("/alerts"),

  anomaly: () => req("/anomaly"),
  launchSimulation: (id) =>
  req(`/sim/${encodeURIComponent(id)}`, {
    method: "POST",
  }),

  incidents: () => req("/incidents"),

  incident: (id) =>
    req(`/incidents/${id}`),

  setStatus: (id, status, note) =>
    req(`/incidents/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status, note }),
    }),

  mitre: () => req("/mitre"),

  navigatorDownload: () => req("/navigator/download"),

  rules: () => req("/rules"),
  toggleRule: (id) => send(`/rules/${encodeURIComponent(id)}/toggle`, "POST"),

  evaluation: () => req("/evaluation"),
  reportSummary: () => req("/reports/summary"),

  lineage: (pid) => req(`/lineage/${pid}`),
  tree: (root) => req(`/tree/${root}`),

  enforcement: (limit = 100) => req(`/enforcement?limit=${limit}`),
  setEnforcement: (settings) => send("/enforcement", "POST", settings),
  enforceProcess: (pid, comm) => send("/enforcement/action", "POST", { pid, comm }),
  clearEnforcement: () => send("/enforcement/clear", "POST"),

  iocs: () => req("/iocs"),
  addIoc: (type, value, description) => send("/iocs", "POST", { type, value, description }),
  deleteIoc: (id) => send(`/iocs/${id}`, "DELETE"),

  users: () => req("/users"),
  addUser: (username, password, role) => send("/users", "POST", { username, password, role }),
  deleteUser: (name) => send(`/users/${encodeURIComponent(name)}`, "DELETE"),
  setUserRole: (name, role) => send(`/users/${encodeURIComponent(name)}/role`, "POST", { role }),

  apikeys: () => req("/apikeys"),
  addApiKey: (name, role) => send("/apikeys", "POST", { name, role }),
  deleteApiKey: (id) => send(`/apikeys/${id}`, "DELETE"),

  alerting: () => req("/alerting"),
  setAlerting: (settings) => send("/alerting", "POST", settings),
  testAlerting: () => send("/alerting/test", "POST"),
};

export function usePoll(fn, intervalMs = 3000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const saved = useRef(fn);

  useEffect(() => {
    saved.current = fn;
  });

  const tickRef = useRef(() => {});

  useEffect(() => {
    let alive = true;

    const tick = async () => {
      try {
        const result = await saved.current();

        if (alive) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (alive) {
          setError(err);
        }
      }
    };

    tickRef.current = tick;

    tick();

    const id = setInterval(tick, intervalMs);

    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [intervalMs]);

  const refresh = useCallback(() => tickRef.current(), []);

  return {
    data,
    error,
    refresh,
  };
}
