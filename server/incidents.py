SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

VALID_STATUSES = {"open", "investigating", "resolved", "false_positive"}


def find_root_pid(engine, pid):
    current_pid = pid
    seen = set()

    while True:
        if current_pid in seen:
            return current_pid

        seen.add(current_pid)

        state = engine.processes.get(current_pid)
        if state is None:
            return current_pid

        if state.ppid == 0 or state.ppid == current_pid:
            return current_pid

        if state.ppid not in engine.processes:
            return current_pid

        current_pid = state.ppid


class Incident:
    _next_id = 1

    def __init__(self, root_pid, root_comm, first_alert):
        self.id = Incident._next_id
        Incident._next_id += 1

        self.root_pid = root_pid
        self.root_comm = root_comm
        self.title = f"Suspicious activity from {root_comm} (pid {root_pid})"
        self.status = "open"
        self.first_seen = first_alert["ts"]
        self.last_seen = first_alert["ts"]
        self.severity = first_alert["severity"]
        self.alerts = []
        self.audit_log = []

        self.add_alert(first_alert)

    def add_alert(self, alert):
        self.alerts.append(alert)
        alert["incident_id"] = self.id

        if alert["ts"] < self.first_seen:
            self.first_seen = alert["ts"]
        if alert["ts"] > self.last_seen:
            self.last_seen = alert["ts"]

        if SEVERITY_RANK[alert["severity"]] > SEVERITY_RANK[self.severity]:
            self.severity = alert["severity"]

    def set_status(self, new_status, actor, note=""):
        if new_status not in VALID_STATUSES:
            raise ValueError(
                f"invalid status '{new_status}', must be one of {sorted(VALID_STATUSES)}"
            )

        old_status = self.status
        self.status = new_status

        self.audit_log.append({
            "from_status": old_status,
            "to_status": new_status,
            "actor": actor,
            "note": note,
        })

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "root_pid": self.root_pid,
            "root_comm": self.root_comm,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alert_count": len(self.alerts),
            "alerts": self.alerts,
        }


class IncidentManager:
    def __init__(self):
        self.incidents_by_root = {}

    def ingest(self, engine, alert):
        root_pid = find_root_pid(engine, alert["pid"])

        if root_pid in self.incidents_by_root:
            incident = self.incidents_by_root[root_pid]
            incident.add_alert(alert)
        else:
            root_state = engine.processes.get(root_pid)
            root_comm = root_state.comm if root_state is not None else "unknown"
            incident = Incident(root_pid, root_comm, alert)
            self.incidents_by_root[root_pid] = incident

        return incident

    def all_incidents(self):
        return list(self.incidents_by_root.values())