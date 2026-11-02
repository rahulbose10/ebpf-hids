import json
import sqlite3
import threading
import time

from server import config

POOL_SIZE = 8

_pool_lock = threading.Lock()
_idle = []
_idle_path = None


class PooledConnection(sqlite3.Connection):
    def close(self):
        if self.in_transaction:
            self.rollback()
        with _pool_lock:
            if any(c is self for c in _idle):
                return
            if self.db_path == _idle_path and len(_idle) < POOL_SIZE:
                _idle.append(self)
                return
        super().close()


def get_connection():
    global _idle_path
    path = str(config.DATABASE_PATH)
    stale = []
    with _pool_lock:
        if path != _idle_path:
            stale = list(_idle)
            _idle.clear()
            _idle_path = path
        conn = _idle.pop() if _idle else None
    for old_conn in stale:
        sqlite3.Connection.close(old_conn)
    if conn is not None:
        return conn
    conn = sqlite3.connect(path, timeout=10, factory=PooledConnection, check_same_thread=False)
    conn.db_path = path
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at REAL NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            pid INTEGER NOT NULL,
            ppid INTEGER,
            uid INTEGER,
            comm TEXT,
            type TEXT NOT NULL,
            detail TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            rule TEXT,
            technique TEXT,
            severity TEXT NOT NULL,
            confidence REAL,
            pid INTEGER,
            comm TEXT,
            summary TEXT,
            detail TEXT,
            incident_id INTEGER
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            root_pid INTEGER,
            root_comm TEXT,
            severity TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            first_seen REAL,
            last_seen REAL,
            alert_count INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT,
            changed_by TEXT,
            ts REAL NOT NULL,
            note TEXT
        )
    """)

    cur.execute("DROP TABLE IF EXISTS anomaly_scores")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            added_by TEXT,
            ts REAL NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL,
            name TEXT,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at REAL NOT NULL,
            last_used REAL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alert_delivery_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            channel TEXT,
            status TEXT,
            ts REAL NOT NULL,
            detail TEXT
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_pid ON events (pid, id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts (incident_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_technique ON alerts (technique)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_incident ON incident_audit (incident_id)")

    _add_column_if_missing(cur, "incident_audit", "note", "TEXT")

    conn.commit()
    conn.close()


def _add_column_if_missing(cur, table, column, sql_type):
    columns = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")


def insert_user(username, password_hash, salt, role):
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, salt, role, time.time())
    )
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def count_users():
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return n


KEEP_ONE_ADMIN = "(role != 'admin' OR (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1)"


def list_users():
    conn = get_connection()
    rows = conn.execute("SELECT username, role, created_at FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def set_user_role(username, role):
    conn = get_connection()
    changed = conn.execute(
        "UPDATE users SET role = ? WHERE username = ? AND (? = 'admin' OR " + KEEP_ONE_ADMIN + ")",
        (role, username, role)
    ).rowcount > 0
    conn.commit()
    conn.close()
    return changed


def delete_user(username):
    conn = get_connection()
    deleted = conn.execute(
        "DELETE FROM users WHERE username = ? AND " + KEEP_ONE_ADMIN,
        (username,)
    ).rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def insert_event(ts, pid, ppid, uid, comm, type_, detail):
    conn = get_connection()
    conn.execute(
        "INSERT INTO events (ts, pid, ppid, uid, comm, type, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, pid, ppid, uid, comm, type_, detail)
    )
    conn.commit()
    conn.close()


def insert_events(events):
    if not events:
        return
    conn = get_connection()
    conn.executemany(
        "INSERT INTO events (ts, pid, ppid, uid, comm, type, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(e["ts"], e["pid"], e["ppid"], e["uid"], e["comm"], e["type"], e["detail"]) for e in events]
    )
    conn.commit()
    conn.close()


def insert_alert(ts, rule, technique, severity, confidence, pid, comm, summary, detail, incident_id=None):
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO alerts (ts, rule, technique, severity, confidence, pid, comm, summary, detail, incident_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, rule, technique, severity, confidence, pid, comm, summary, json.dumps(detail), incident_id)
    )
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    return alert_id


def recent_events(limit=100, pid=None):
    conn = get_connection()
    if pid is not None:
        rows = conn.execute(
            "SELECT * FROM events WHERE pid = ? ORDER BY id DESC LIMIT ?",
            (pid, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def recent_alerts(limit=300):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alert = dict(row)
        if alert.get("detail"):
            alert["detail"] = json.loads(alert["detail"])
        alerts.append(alert)
    return alerts


def counts():
    conn = get_connection()
    result = {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "processes": conn.execute("SELECT COUNT(DISTINCT pid) FROM events").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
    }
    conn.close()
    return result


def upsert_incident(row):
    conn = get_connection()
    conn.execute(
        """INSERT INTO incidents
           (id, title, root_pid, root_comm, severity, status, first_seen, last_seen, alert_count)
           VALUES (:id, :title, :root_pid, :root_comm, :severity, :status, :first_seen, :last_seen, :alert_count)
           ON CONFLICT(id) DO UPDATE SET
               severity = excluded.severity,
               first_seen = excluded.first_seen,
               last_seen = excluded.last_seen,
               alert_count = excluded.alert_count""",
        row
    )
    conn.commit()
    conn.close()


def max_incident_id():
    conn = get_connection()
    value = conn.execute("SELECT MAX(id) FROM incidents").fetchone()[0]
    conn.close()
    return value or 0


def list_incidents(limit=200):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_incident(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        conn.close()
        return None

    incident = dict(row)
    alert_rows = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY id ASC",
        (incident_id,)
    ).fetchall()
    conn.close()

    alerts = []
    for alert_row in alert_rows:
        alert = dict(alert_row)
        if alert.get("detail"):
            alert["detail"] = json.loads(alert["detail"])
        alerts.append(alert)

    incident["alerts"] = alerts
    return incident


def set_incident_status(incident_id, new_status, changed_by, note=""):
    conn = get_connection()
    row = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        conn.close()
        return False

    old_status = row["status"]
    if old_status != new_status:
        conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        conn.execute(
            """INSERT INTO incident_audit (incident_id, old_status, new_status, changed_by, ts, note)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (incident_id, old_status, new_status, changed_by, time.time(), note)
        )
        conn.commit()
    conn.close()
    return True


def export_alerts(limit):
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, ts, rule, technique, severity, confidence, pid, comm, summary, incident_id
           FROM alerts ORDER BY id ASC LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def export_incidents(limit):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def report_numbers():
    conn = get_connection()
    by_severity = {
        row["severity"]: row["n"]
        for row in conn.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")
    }
    top_rules = [
        {"rule": row["rule"], "technique": row["technique"], "count": row["n"]}
        for row in conn.execute(
            """SELECT rule, technique, COUNT(*) AS n FROM alerts
               GROUP BY rule, technique ORDER BY n DESC, rule ASC LIMIT 10"""
        )
    ]
    by_status = {
        row["status"]: row["n"]
        for row in conn.execute("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status")
    }
    conn.close()
    return {"by_severity": by_severity, "top_rules": top_rules, "by_status": by_status}


def insert_delivery(alert_id, channel, status, detail):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alert_delivery_log (alert_id, channel, status, ts, detail) VALUES (?, ?, ?, ?, ?)",
        (alert_id, channel, status, time.time(), detail)
    )
    conn.commit()
    conn.close()


def recent_deliveries(limit=50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alert_delivery_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def incident_audit(incident_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM incident_audit WHERE incident_id = ? ORDER BY ts ASC",
        (incident_id,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def technique_counts():
    conn = get_connection()
    rows = conn.execute(
        """SELECT technique, COUNT(*) AS n FROM alerts
           WHERE technique IS NOT NULL AND technique != 'ML-ANOM'
           GROUP BY technique"""
    ).fetchall()
    conn.close()
    return {row["technique"]: row["n"] for row in rows}


def list_iocs():
    conn = get_connection()
    rows = conn.execute("SELECT id, type, value, description, added_by, ts FROM iocs ORDER BY id").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_ioc(ioc_type, value, description, added_by):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO iocs (type, value, description, added_by, ts) VALUES (?, ?, ?, ?, ?)",
        (ioc_type, value, description, added_by, time.time())
    )
    ioc_id = cur.lastrowid
    conn.commit()
    conn.close()
    return ioc_id


def delete_ioc(ioc_id):
    conn = get_connection()
    deleted = conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,)).rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def evaluation_numbers():
    conn = get_connection()

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    ml_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE technique = 'ML-ANOM'"
    ).fetchone()[0]

    incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    alerts_in_incidents = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE incident_id IS NOT NULL"
    ).fetchone()[0]
    conn.close()

    if incident_count > 0:
        alerts_per_incident = round(alerts_in_incidents / incident_count, 2)
    else:
        alerts_per_incident = 0.0

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "rule_alerts": total_alerts - ml_alerts,
        "ml_alerts": ml_alerts,
        "by_technique": technique_counts(),
        "incidents": incident_count,
        "alerts_per_incident": alerts_per_incident,
    }
def insert_api_key(name, role):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO api_keys (key_hash, name, role, created_at) VALUES ('', ?, ?, ?)",
        (name, role, time.time())
    )
    key_id = cur.lastrowid
    conn.commit()
    conn.close()
    return key_id


def set_api_key_hash(key_id, key_hash):
    conn = get_connection()
    conn.execute("UPDATE api_keys SET key_hash = ? WHERE id = ?", (key_hash, key_id))
    conn.commit()
    conn.close()


def get_api_key(key_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_api_keys():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, name, role, created_at, last_used FROM api_keys ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def delete_api_key(key_id):
    conn = get_connection()
    cur = conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def touch_api_key(key_id):
    conn = get_connection()
    conn.execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (time.time(), key_id))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized at:", config.DATABASE_PATH)
