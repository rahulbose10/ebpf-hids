import json
import sqlite3
import time

from server import config


def get_connection():
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=10)
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
            ts REAL NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            comm TEXT,
            ts REAL NOT NULL,
            iforest_score REAL,
            recon_error REAL,
            is_anomaly INTEGER NOT NULL DEFAULT 0
        )
    """)

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

    conn.commit()
    conn.close()


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


def set_user_role(username, role):
    conn = get_connection()
    changed = conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username)).rowcount > 0
    conn.commit()
    conn.close()
    return changed


def delete_user(username):
    conn = get_connection()
    deleted = conn.execute("DELETE FROM users WHERE username = ?", (username,)).rowcount > 0
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


def insert_alert(ts, rule, technique, severity, confidence, pid, comm, summary, detail, incident_id=None):
    conn = get_connection()
    conn.execute(
        """INSERT INTO alerts (ts, rule, technique, severity, confidence, pid, comm, summary, detail, incident_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, rule, technique, severity, confidence, pid, comm, summary, json.dumps(detail), incident_id)
    )
    conn.commit()
    conn.close()


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


def all_processes(limit=1000):
    conn = get_connection()
    rows = conn.execute("""
        SELECT pid,
               MIN(ppid) as ppid,
               MIN(uid) as uid,
               MIN(comm) as comm,
               COUNT(*) as exec_count
        FROM events
        GROUP BY pid
        ORDER BY pid DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def recent_anomaly_scores(limit=300):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM anomaly_scores ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    scores = []
    for row in rows:
        score = dict(row)
        score["is_anomaly"] = bool(score["is_anomaly"])
        scores.append(score)
    return scores


def counts():
    conn = get_connection()
    result = {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "processes": conn.execute("SELECT COUNT(DISTINCT pid) FROM events").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "anomalies": conn.execute("SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly = 1").fetchone()[0],
    }
    conn.close()
    return result


def insert_incident(title, root_pid, root_comm, severity, first_seen, last_seen):
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO incidents
           (title, root_pid, root_comm, severity, status, first_seen, last_seen, alert_count)
           VALUES (?, ?, ?, ?, 'open', ?, ?, 0)""",
        (title, root_pid, root_comm, severity, first_seen, last_seen)
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()
    return incident_id


def attach_alert_to_incident(alert_id, incident_id):
    conn = get_connection()
    conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
    conn.execute(
        """UPDATE incidents
           SET alert_count = (SELECT COUNT(*) FROM alerts WHERE incident_id = ?)
           WHERE id = ?""",
        (incident_id, incident_id)
    )
    conn.commit()
    conn.close()


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


def set_incident_status(incident_id, new_status, changed_by):
    conn = get_connection()
    row = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        conn.close()
        return False

    old_status = row["status"]
    if old_status != new_status:
        conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        conn.execute(
            """INSERT INTO incident_audit (incident_id, old_status, new_status, changed_by, ts)
               VALUES (?, ?, ?, ?, ?)""",
            (incident_id, old_status, new_status, changed_by, time.time())
        )
        conn.commit()
    conn.close()
    return True


def incident_audit(incident_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM incident_audit WHERE incident_id = ? ORDER BY ts ASC",
        (incident_id,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def evaluation_numbers():
    conn = get_connection()

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    ml_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE technique = 'ML-ANOM'"
    ).fetchone()[0]

    technique_rows = conn.execute(
        """SELECT technique, COUNT(*) AS n FROM alerts
           WHERE technique IS NOT NULL AND technique != 'ML-ANOM'
           GROUP BY technique"""
    ).fetchall()
    by_technique = {row["technique"]: row["n"] for row in technique_rows}

    incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    alerts_in_incidents = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE incident_id IS NOT NULL"
    ).fetchone()[0]
    anomaly_scores = conn.execute("SELECT COUNT(*) FROM anomaly_scores").fetchone()[0]
    anomalies_flagged = conn.execute(
        "SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly = 1"
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
        "by_technique": by_technique,
        "incidents": incident_count,
        "alerts_per_incident": alerts_per_incident,
        "anomaly_scores": anomaly_scores,
        "anomalies_flagged": anomalies_flagged,
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
