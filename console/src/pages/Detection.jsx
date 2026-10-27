import { useState } from "react";
import GaugeBar from "../components/GaugeBar";
import { api, usePoll } from "../api";

function Detection() {

  const { data } = usePoll(api.alerts, 3000);
  const { data: anomaly } = usePoll(api.anomaly, 3000);

  const alerts = data?.alerts || [];

  const [selectedAlert, setSelectedAlert] = useState(null);

  return (

    <div className="flex flex-col gap-6">

      {/* Header */}

      <div className="page-header">

        <h1>
          Detection
        </h1>

        <p>
          Rule detections mapped to MITRE ATT&CK techniques,
          plus the Isolation Forest anomaly gauge.
        </p>

      </div>

      {/* ================= ANOMALY GAUGE ================= */}

      <div className="anomaly-section">

        <div className="panel-label anomaly-title">
          ANOMALY GAUGE — ISOLATION FOREST
        </div>

        <div className="panel">

          <div className="panel-body">

            <p className="gauge-info">
              isolation forest only — scoring 300 windows as a gauge.
              ML alerting is off (no autoencoder); the rule engine
              carries detection.
            </p>

            <GaugeBar score={anomaly?.score ?? 0} />

            <div className="gauge-status">

              <span>
                Model:
                <strong> {anomaly?.model}</strong>
              </span>

              <span>
                Status:
                <strong> {anomaly?.status}</strong>
              </span>

              <span>
                Threshold:
                <strong> {anomaly?.threshold}</strong>
              </span>

            </div>

          </div>

        </div>

      </div>

      {/* ================= ALERT FEED ================= */}

      <div className="alert-feed">

        <div className="panel-label alert-title-label">
          ALERT FEED
        </div>

        {alerts.length === 0 ? (

          <div className="empty-alert">
            No Alerts
          </div>

        ) : (

          alerts.map((alert, index) => (

           <div
              key={alert.incident_id ?? index}
              className={`alert-card ${
                selectedAlert?.incident_id === alert.incident_id
                  ? "alert-card-active"
                  : ""
              }`}
              onClick={() => setSelectedAlert(alert)}
            >

              <span
                className={`severity ${alert.severity}`}
              >
                {alert.severity.toUpperCase()}
              </span>

              <div className="alert-content">

                <div className="alert-title">
                  {alert.summary}
                </div>

                <div className="alert-meta">

                  <span>
                    {alert.technique}
                  </span>

                  <span>
                    rule={alert.rule}
                  </span>

                  <span>
                    pid {alert.pid}
                  </span>

                  <span>
                    {alert.comm}
                  </span>

                  <span>
                    conf {alert.confidence}
                  </span>

                </div>

              </div>

            </div>

          ))

        )}

      </div>

      {/* ================= INVESTIGATION DETAILS ================= */}

      {selectedAlert && (

        <div className="panel">

          <div className="panel-label investigation-header">

  <span>

    INVESTIGATION DETAILS

  </span>

  <button
    className="close-btn"
    onClick={() => setSelectedAlert(null)}
  >
    ✕
  </button>

</div>

          <div className="panel-body">

            <p>

              <strong>Rule:</strong> {selectedAlert.rule}

            </p>

            <p>

              <strong>Process:</strong> {selectedAlert.comm}

            </p>

            <p>

              <strong>PID:</strong> {selectedAlert.pid}

            </p>

            <p>

              <strong>MITRE:</strong> {selectedAlert.technique}

            </p>

            <p>

              <strong>Confidence:</strong> {selectedAlert.confidence}

            </p>

            <p>

              <strong>Summary:</strong> {selectedAlert.summary}

            </p>

          </div>

        </div>

      )}

    </div>

  );

}

export default Detection;