
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
    throw { unauth: true };
  }

  const body = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw body;
  }

  return body;
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
};

export function usePoll(fn, intervalMs = 3000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const saved = useRef(fn);
  saved.current = fn;

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
  }, deps);

  const refresh = useCallback(() => tickRef.current(), []);

  return {
    data,
    error,
    refresh,
  };
}
