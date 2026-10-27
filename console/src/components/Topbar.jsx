import "../styles/topbar.css";
import { useEffect, useState } from "react";
import { api, usePoll } from "../api";

// Works out what the two status lights should say from /api/health.
// "tone" picks the dot colour in topbar.css, "pulse" makes the dot breathe.
function sensorStatus(health, backendDown) {
  if (backendDown) {
    return { tone: "down", pulse: false, text: "backend unreachable" };
  }
  if (!health) {
    return { tone: "off", pulse: false, text: "connecting" };
  }
  if (!health.sensor_ready) {
    return { tone: "down", pulse: false, text: "sensor offline" };
  }
  return { tone: "signal", pulse: true, text: "sensor attached" };
}

// ml_ready: models loaded. ml_alerting: the ML side is allowed to raise alerts.
// Three states, not two: not loaded, loaded as a gauge only, loaded and alerting.
function mlStatus(health) {
  if (!health || !health.ml_ready) {
    return { tone: "off", pulse: false, text: "ml not loaded" };
  }
  if (health.ml_alerting) {
    return { tone: "ml", pulse: true, text: "ml alerting" };
  }
  return { tone: "ml", pulse: false, text: "ml gauge only, no alerts" };
}

function Light({ tone, pulse, text }) {
  return (
    <span className="tb-status">
      <span className={`tb-dot tb-dot-${tone} ${pulse ? "tb-pulse" : ""}`} />
      <span>{text}</span>
    </span>
  );
}

function TopBar() {
  const { data, error } = usePoll(api.health, 3000);
  const counts = data?.counts || {};

  const [clock, setClock] = useState("");

  useEffect(() => {
    const updateClock = () => {
      setClock(
        new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        })
      );
    };

    updateClock();
    const id = setInterval(updateClock, 1000);

    return () => clearInterval(id);
  }, []);

  const backendDown = Boolean(error);

  return (
    <header className="tb">
      <div className="tb-group">
        <Light {...sensorStatus(data, backendDown)} />
        <Light {...mlStatus(backendDown ? null : data)} />
      </div>

      <div className="tb-group">
        <span className="tb-clock">{clock}</span>

        <span className="tb-count">
          events <strong>{counts.events ?? 0}</strong>
        </span>
        <span className="tb-count">
          alerts <strong>{counts.alerts ?? 0}</strong>
        </span>
        <span className="tb-count">
          incidents <strong>{counts.incidents ?? 0}</strong>
        </span>

        <Light
          tone={backendDown ? "down" : "signal"}
          pulse={!backendDown}
          text={backendDown ? "stalled" : "live"}
        />
      </div>
    </header>
  );
}

export default TopBar;
