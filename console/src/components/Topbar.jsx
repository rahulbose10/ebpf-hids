import "../styles/topbar.css";
import { useEffect, useState } from "react";
import { api, usePoll } from "../api";

function TopBar() {

  const { data } = usePoll(api.health, 3000);
  const counts = data?.counts || {};

  const [clock, setClock] = useState("");

  useEffect(() => {

    const updateClock = () => {

      setClock(
        new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );

    };

    updateClock();

    const id = setInterval(updateClock, 1000);

    return () => clearInterval(id);

  }, []);

  return (

    <header className="topbar">

      <div className="topbar-left">

        <div className="status">

          <span className="dot signal"></span>

          <span>
            {data?.sensor_ready ? "sensor attached" : "sensor offline"}
          </span>

        </div>

        <div className="status">

          <span className="dot ml"></span>

          <span>
            {data?.ml_alerting
              ? "ml autoencoder enabled"
              : "ml gauge only – no alerts"}
          </span>

        </div>

      </div>

      <div className="topbar-right">

        <span className="topbar-time">
          {clock}
        </span>

        <span>
          events <strong>{counts.events ?? 0}</strong>
        </span>

        <span>
          alerts <strong>{counts.alerts ?? 0}</strong>
        </span>

        <span>
          incidents <strong>{counts.incidents ?? 0}</strong>
        </span>

        <div className="status live">

          <span className="dot signal"></span>

          <span>
            live
          </span>

        </div>

      </div>

    </header>

  );

}

export default TopBar;