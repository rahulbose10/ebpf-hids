import os
import glob
from features import ProcessState
from rules_dsl import load_rules, check_condition

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_all_rules(rules_dir=None):
    rules_dir = rules_dir or RULES_DIR
    all_rules = []
    for filepath in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        all_rules.extend(load_rules(filepath))
    return all_rules


class Engine:
    def __init__(self, anomaly_model=None, rules_path=None):
        self.processes = {}
        self.alerts = []
        self.anomaly_model = anomaly_model

        if rules_path is not None:
            self.rules = load_rules(rules_path)
        else:
            self.rules = load_all_rules()

        self.last_alert_time = {}
        self.dedupe_window = 60.0

    def process_event(self, evt, now=None):
        pid = evt["pid"]

        if pid not in self.processes:
            self.processes[pid] = ProcessState(
                pid=pid,
                ppid=evt["ppid"],
                comm=evt["comm"],
                uid=evt["uid"],
            )

        state = self.processes[pid]
        state.update(evt)

        new_alerts = []
        for rule in self.rules:
            if all(check_condition(cond, state, self, now if now is not None else evt["ts"], evt) for cond in rule.where):
                key = (pid, rule.id)
                current_ts = evt["ts"]
                last_ts = self.last_alert_time.get(key)

                if last_ts is not None and (current_ts - last_ts) < self.dedupe_window:
                    continue

                self.last_alert_time[key] = current_ts

                alert = {
                    "ts": evt["ts"],
                    "rule": rule.id,
                    "technique": rule.technique,
                    "severity": rule.severity,
                    "confidence": 1.0,
                    "pid": pid,
                    "comm": state.comm,
                    "summary": rule.description,
                    "detail": {"event": evt, "tactic": None, "technique": rule.technique},
                    "incident_id": None,
                }
                new_alerts.append(alert)
                self.alerts.append(alert)

        if self.anomaly_model is not None:
            score = self.anomaly_model.score(state)
            if score is not None and score >= self.anomaly_model.threshold:
                anomaly_alert = {
                    "ts": evt["ts"],
                    "rule": "ml_anomaly",
                    "technique": None,
                    "severity": "medium",
                    "confidence": score,
                    "pid": pid,
                    "comm": state.comm,
                    "summary": f"Anomalous behavior detected (score={score:.2f})",
                    "detail": {"event": evt, "tactic": None, "technique": None},
                    "incident_id": None,
                }
                new_alerts.append(anomaly_alert)
                self.alerts.append(anomaly_alert)

        return new_alerts