import posixpath
import threading
from collections import Counter, OrderedDict, deque
from pathlib import Path

from server import features
from server.features import ProcessState, rename_paths
from server.mitre import tactic_for
from server.rules_dsl import load_rules_dir

RULES_DIR = Path(__file__).resolve().parent / "rules"
REQUIRED_KEYS = ("ts", "pid", "ppid", "uid", "comm", "type", "detail")
MAX_DEPTH = 64


def normalise(evt):
    if not isinstance(evt, dict):
        raise ValueError(f"event must be a JSON object, got {type(evt).__name__}")
    missing = [k for k in REQUIRED_KEYS if k not in evt]
    if missing:
        raise ValueError(f"event is missing {missing}")
    try:
        return {
            "ts": float(evt["ts"]),
            "pid": int(evt["pid"]),
            "ppid": int(evt["ppid"]),
            "uid": int(evt["uid"]),
            "comm": str(evt["comm"] or ""),
            "type": str(evt["type"]),
            "detail": str(evt["detail"] or ""),
        }
    except (TypeError, ValueError) as exc:
        raise ValueError(f"event has a badly typed field: {exc}") from exc


def _norm_path(path):
    if not path:
        return None
    return posixpath.normpath(path)


class Engine:
    def __init__(self, anomaly_model=None, rules_dir=None, featurize=None,
                 dedupe_window=60.0, max_processes=4096, max_alerts=1000,
                 max_tracked_writes=2048, ignore_pids=()):
        self.anomaly_model = anomaly_model
        if anomaly_model is not None and featurize is None:
            featurize = getattr(features, "extract_features", None)
            if featurize is None:
                raise RuntimeError(
                    "anomaly_model was given but server/features.py has no "
                    "extract_features yet (that is L3's half of the file)"
                )
        self.featurize = featurize

        self.rules, self.rule_errors = load_rules_dir(rules_dir or RULES_DIR)
        self.dedupe_window = dedupe_window
        self.max_processes = max_processes
        self.max_tracked_writes = max_tracked_writes
        self.ignore_pids = set(ignore_pids)
        self.lock = threading.RLock()

        self.processes = OrderedDict()
        self.written_by = OrderedDict()
        self.alerts = deque(maxlen=max_alerts)
        self.anomaly_scores = deque(maxlen=500)

        self.rule_hits = Counter()
        self.technique_counts = Counter()
        self.events_seen = 0
        self.rule_alert_count = 0
        self.ml_alert_count = 0
        self.ml_errors = 0
        self.last_ml_error = None

    def process_event(self, evt, now=None):
        evt = normalise(evt)
        with self.lock:
            return self._process(evt, evt["ts"] if now is None else now)

    def _process(self, evt, now):
        self.events_seen += 1

        state = self._state_for(evt)
        state.update(evt)
        self._track_write(evt, state)

        if evt["pid"] in self.ignore_pids:
            return []

        new_alerts = []
        for rule in self.rules:
            if not rule.enabled or not rule.matches(state, self, evt, now):
                continue
            alert = self._raise(state, evt, rule.id, rule.technique, rule.severity,
                                1.0, rule.description)
            if alert is not None:
                self.rule_hits[rule.id] += 1
                self.rule_alert_count += 1
                new_alerts.append(alert)

        if self.anomaly_model is not None:
            alert = self._score(state, evt)
            if alert is not None:
                self.ml_alert_count += 1
                new_alerts.append(alert)

        return new_alerts

    def _state_for(self, evt):
        pid = evt["pid"]
        state = self.processes.get(pid)
        if state is None:
            state = ProcessState(pid=pid, ppid=evt["ppid"], comm=evt["comm"], uid=evt["uid"])
            self.processes[pid] = state
            if len(self.processes) > self.max_processes:
                self.processes.popitem(last=False)
        else:
            self.processes.move_to_end(pid)
        return state

    def _track_write(self, evt, state):
        if evt["type"] == "OPEN":
            path = _norm_path(evt["detail"])
        elif evt["type"] == "RENAME":
            path = _norm_path(rename_paths(evt["detail"])[1])
        else:
            return
        if path is None:
            return
        self.written_by[path] = (state.pid, evt["ts"], state.net_connect_count > 0)
        self.written_by.move_to_end(path)
        if len(self.written_by) > self.max_tracked_writes:
            self.written_by.popitem(last=False)

    def fetched_age(self, path, now):
        record = self.written_by.get(_norm_path(path))
        if record is None:
            return None
        writer_pid, written_ts, writer_was_online = record
        writer = self.processes.get(writer_pid)
        online = writer_was_online or (writer is not None and writer.net_connect_count > 0)
        return now - written_ts if online else None

    def _raise(self, state, evt, rule_id, technique, severity, confidence, description):
        last = state.last_alert.get(rule_id)
        if last is not None and evt["ts"] - last < self.dedupe_window:
            return None
        state.last_alert[rule_id] = evt["ts"]

        alert = {
            "ts": evt["ts"],
            "rule": rule_id,
            "technique": technique,
            "severity": severity,
            "confidence": confidence,
            "pid": state.pid,
            "comm": state.comm,
            "summary": f"{description} ({state.exe_name} pid {state.pid}: {evt['type']} {evt['detail']})",
            "detail": {"event": evt, "tactic": tactic_for(technique), "technique": technique},
            "incident_id": None,
        }
        self.technique_counts[technique] += 1
        self.alerts.append(alert)
        return alert

    def _score(self, state, evt):
        try:
            vec = self.featurize(state, self.depth(state.pid))
            result = self.anomaly_model.score(vec)
            if not isinstance(result, dict):
                raise TypeError(f"score() must return a dict, got {type(result).__name__}")
        except Exception as exc:
            self.ml_errors += 1
            self.last_ml_error = f"{type(exc).__name__}: {exc}"
            return None

        row = {
            "pid": state.pid,
            "comm": state.comm,
            "ts": evt["ts"],
            "iforest_score": result.get("iforest_score"),
            "recon_error": result.get("recon_error"),
            "is_anomaly": bool(result.get("is_anomaly")),
        }
        self.anomaly_scores.append(row)
        if not row["is_anomaly"]:
            return None
        return self._raise(state, evt, "ml_anomaly", "ML-ANOM", "medium",
                           float(result.get("confidence", 0.5)),
                           "Behaviour far from the learned baseline")

    def lineage(self, pid):
        chain = []
        current = pid
        while current in self.processes and current not in chain and len(chain) < MAX_DEPTH:
            chain.append(current)
            current = self.processes[current].ppid
        return chain

    def depth(self, pid):
        return max(len(self.lineage(pid)) - 1, 0)

    def process_rows(self, limit=None):
        with self.lock:
            states = sorted(self.processes.values(), key=lambda s: s.last_ts or 0.0, reverse=True)
            if limit is not None:
                states = states[:limit]
            return [s.to_dict(self.depth(s.pid)) for s in states]

    def recent_alerts(self, limit=300):
        with self.lock:
            return list(self.alerts)[-limit:][::-1]

    def recent_anomaly_scores(self, limit=100):
        with self.lock:
            return list(self.anomaly_scores)[-limit:][::-1]

    def rules_info(self):
        with self.lock:
            return {
                "rules": [r.to_dict(self.rule_hits[r.id]) for r in self.rules],
                "errors": list(self.rule_errors),
            }

    def set_rule_enabled(self, rule_id, enabled):
        with self.lock:
            for rule in self.rules:
                if rule.id == rule_id:
                    rule.enabled = bool(enabled)
                    return rule.to_dict(self.rule_hits[rule.id])
        raise KeyError(rule_id)
