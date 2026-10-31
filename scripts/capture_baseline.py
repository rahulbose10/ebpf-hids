import sqlite3
import numpy as np
from server.features import extract_features


def fetch_events(db_path, start_ts, end_ts):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT ts, pid, ppid, uid, comm, type, detail FROM events "
        "WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
        (start_ts, end_ts),
    )
    rows = cursor.fetchall()
    conn.close()

    events = []

    for row in rows:
        events.append({
            "ts": row[0],
            "pid": row[1],
            "ppid": row[2],
            "uid": row[3],
            "comm": row[4],
            "type": row[5],
            "detail": row[6],
        })

    return events


def build_process_states(events):
    processes = {}

    for event in events:
        pid = event["pid"]

        if pid not in processes:
            processes[pid] = {
                "ppid": event["ppid"],
                "uid": event["uid"],
                "exec_count": 0,
                "connect_count": 0,
                "file_write_count": 0,
                "distinct_files_written": set(),
                "distinct_dst": set(),
                "ptrace_count": 0,
                "setuid_count": 0,
                "ran_as_root": event["uid"] == 0,
                "event_timestamps": [],
                "first_ts": event["ts"],
                "last_ts": event["ts"],
                "distinct_syscall_types": set(),
            }

        proc = processes[pid]

        proc["event_timestamps"].append(event["ts"])
        proc["first_ts"] = min(proc["first_ts"], event["ts"])
        proc["last_ts"] = max(proc["last_ts"], event["ts"])
        proc["distinct_syscall_types"].add(event["type"])

        if event["type"] == "EXEC":
            proc["exec_count"] += 1

        elif event["type"] == "CONNECT":
            proc["connect_count"] += 1
            proc["distinct_dst"].add(event["detail"])

        elif event["type"] == "OPEN":
            proc["file_write_count"] += 1
            proc["distinct_files_written"].add(event["detail"])

        elif event["type"] == "PTRACE":
            proc["ptrace_count"] += 1

        elif event["type"] == "SETUID":
            proc["setuid_count"] += 1

    for pid, proc in processes.items():
        proc["lifetime_s"] = proc["last_ts"] - proc["first_ts"]
        proc["ts"] = proc["first_ts"]

        proc["distinct_files_written"] = len(
            proc["distinct_files_written"]
        )

        proc["distinct_dst"] = len(proc["distinct_dst"])

        proc["distinct_syscall_types"] = len(
            proc["distinct_syscall_types"]
        )

    return processes


def compute_depths(processes):
    depths = {}

    def get_depth(pid, visited):
        if pid in depths:
            return depths[pid]

        if pid not in processes or pid in visited:
            return 0

        visited.add(pid)

        ppid = processes[pid]["ppid"]
        parent_depth = get_depth(ppid, visited)

        depth = parent_depth + 1

        depths[pid] = depth
        return depth

    for pid in processes:
        get_depth(pid, set())

    return depths


def capture_baseline(db_path, start_ts, end_ts):
    events = fetch_events(db_path, start_ts, end_ts)

    processes = build_process_states(events)
    depths = compute_depths(processes)

    rows = []

    for pid, proc in processes.items():
        if len(proc["event_timestamps"]) <= 1:
            continue

        depth = depths.get(pid, 0)

        features = extract_features(proc, depth)
        rows.append(features)

    return np.array(rows)
