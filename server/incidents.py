import time

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

TRANSITIONS = {
    "open": {"investigating", "resolved", "false_positive"},
    "investigating": {"open", "resolved", "false_positive"},
    "resolved": {"open"},
    "false_positive": {"open"},
}
CLOSED = {"resolved", "false_positive"}

SESSION_ROOTS = {
    "systemd", "init", "sshd", "login", "cron", "gdm-session-wor",
    "gnome-shell", "gnome-terminal-server", "gnome-terminal-",
    "xfce4-terminal", "konsole", "tmux", "screen", "containerd-shim",
}

MAX_ALERTS_PER_INCIDENT = 500


def find_root_pid(engine, pid):
    root = pid
    seen = {pid}
    while True:
        state = engine.processes.get(root)
        if state is None:
            return root
        parent_pid = state.ppid
        if parent_pid in (0, 1, root) or parent_pid in seen:
            return root
        parent = engine.processes.get(parent_pid)
        if parent is None or parent.exe_name in SESSION_ROOTS or parent.comm in SESSION_ROOTS:
            return root
        seen.add(parent_pid)
        root = parent_pid


class Incident:
    def __init__(self, incident_id, root_pid, root_comm, first_alert):
        self.id = incident_id
        self.root_pid = root_pid
        self.root_comm = root_comm
        self.title = f"Suspicious activity under {root_comm} (pid {root_pid})"
        self.status = "open"
        self.first_seen = first_alert["ts"]
        self.last_seen = first_alert["ts"]
        self.severity = first_alert["severity"]
        self.alert_count = 0
        self.alerts = []
        self.audit_log = []
        self.add_alert(first_alert)

    def add_alert(self, alert):
        alert["incident_id"] = self.id
        self.alert_count += 1
        if len(self.alerts) < MAX_ALERTS_PER_INCIDENT:
            self.alerts.append(alert)
        self.first_seen = min(self.first_seen, alert["ts"])
        self.last_seen = max(self.last_seen, alert["ts"])
        if SEVERITY_RANK[alert["severity"]] > SEVERITY_RANK[self.severity]:
            self.severity = alert["severity"]

    def set_status(self, new_status, actor, note="", when=None):
        if new_status not in TRANSITIONS:
            raise ValueError(f"invalid status '{new_status}', must be one of {sorted(TRANSITIONS)}")
        if new_status not in TRANSITIONS[self.status]:
            raise ValueError(f"cannot move incident {self.id} from '{self.status}' to '{new_status}'")
        if not actor:
            raise ValueError("actor is required for an audit entry")

        entry = {
            "incident_id": self.id,
            "ts": time.time() if when is None else when,
            "from_status": self.status,
            "to_status": new_status,
            "actor": actor,
            "note": note,
        }
        self.status = new_status
        self.audit_log.append(entry)
        return entry

    def to_dict(self, include_alerts=False):
        row = {
            "id": self.id,
            "title": self.title,
            "root_pid": self.root_pid,
            "root_comm": self.root_comm,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alert_count": self.alert_count,
        }
        if include_alerts:
            row["alerts"] = list(self.alerts)
        return row


class IncidentManager:
    def __init__(self, next_id=1):
        self.next_id = next_id
        self.by_id = {}
        self.open_by_root = {}

    def correlate(self, engine, alert):
        root_pid = find_root_pid(engine, alert["pid"])
        incident = self.open_by_root.get(root_pid)
        if incident is not None and incident.status not in CLOSED:
            incident.add_alert(alert)
            return incident

        root_state = engine.processes.get(root_pid)
        root_comm = root_state.comm if root_state is not None else alert.get("comm", "unknown")
        incident = Incident(self.next_id, root_pid, root_comm, alert)
        self.next_id += 1
        self.by_id[incident.id] = incident
        self.open_by_root[root_pid] = incident
        return incident

    def get(self, incident_id):
        return self.by_id.get(incident_id)

    def set_status(self, incident_id, new_status, actor, note=""):
        incident = self.by_id.get(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        return incident.set_status(new_status, actor, note)

    def all_incidents(self):
        return sorted(self.by_id.values(), key=lambda i: i.last_seen, reverse=True)
