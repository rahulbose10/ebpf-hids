import os
import signal
import threading
import time
from collections import deque

import config

DECISIONS = ("executed", "dry_run", "guard_blocked")

SEVERITY_ORDER = ("low", "medium", "high", "critical")

_log = deque(maxlen=config.RESPONSE_LOG_MAX)

_log_lock = threading.Lock()


def record_action(pid, comm, rule, severity, decision, reason):
    if decision not in DECISIONS:
        raise ValueError("unknown decision: " + str(decision))

    entry = {
        "ts": time.time(),
        "pid": pid,
        "comm": comm,
        "rule": rule,
        "severity": severity,
        "decision": decision,
        "reason": reason,
    }
    with _log_lock:
        _log.append(entry)
    return dict(entry)


def recent_actions(limit=100):
    limit = min(int(limit), config.RESPONSE_LOG_MAX)
    with _log_lock:
        items = list(_log)
    items.reverse()
    return [dict(item) for item in items[:limit]]


def clear_actions():
    with _log_lock:
        count = len(_log)
        _log.clear()
    return count


def _read_parent_map():
    parents = {}
    if not os.path.isdir("/proc"):
        return parents

    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/" + entry + "/stat") as stat_file:
                stat = stat_file.read()
        except OSError:
            continue

        fields = stat[stat.rfind(")") + 2:].split()
        try:
            parents[int(entry)] = int(fields[1])
        except (IndexError, ValueError):
            continue
    return parents


def own_pids():
    me = os.getpid()
    parents = _read_parent_map()

    family = {me, os.getppid()}

    pid = me
    seen = set()
    while pid in parents and pid not in seen:
        seen.add(pid)
        pid = parents[pid]
        family.add(pid)

    descendants = set()
    frontier = {me}
    while frontier:
        children = {
            child for child, parent in parents.items()
            if parent in frontier and child not in descendants and child != me
        }
        descendants |= children
        frontier = children

    return family | descendants


def protection_reason(pid, comm):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return "guard: invalid pid " + repr(pid)

    name = comm or ""
    if name in config.NEVER_KILL:
        return "guard: '" + name + "' is on the never-kill list"

    if pid < config.MIN_SAFE_PID:
        return "guard: pid " + str(pid) + " is below the safe floor of " + str(config.MIN_SAFE_PID)

    if pid == os.getpid():
        return "guard: that is the responder itself"
    if pid in own_pids():
        return "guard: pid is part of the responder's own process tree"

    return None


def severity_allows_action(severity):
    if severity not in SEVERITY_ORDER or config.RESPONSE_MIN_SEVERITY not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(config.RESPONSE_MIN_SEVERITY)


def _force_kill_if_needed(alert):
    pid = alert.get("pid")
    time.sleep(config.RESPONSE_GRACE_SECONDS)

    try:
        os.kill(pid, 0)
    except OSError:
        return

    try:
        os.kill(pid, signal.SIGKILL)
        record_action(pid, alert.get("comm"), alert.get("rule"), alert.get("severity"),
                      "executed", "still running after the grace period, sent SIGKILL")
    except OSError as error:
        record_action(pid, alert.get("comm"), alert.get("rule"), alert.get("severity"),
                      "guard_blocked", "the operating system refused SIGKILL: " + str(error))


def _terminate_process(alert):
    if os.name != "posix":
        raise OSError("this system cannot send kill signals (Linux only)")

    os.kill(alert["pid"], signal.SIGTERM)

    thread = threading.Thread(target=_force_kill_if_needed, args=(alert,), daemon=True)
    thread.start()
    return ("sent SIGTERM, SIGKILL follows after " + str(config.RESPONSE_GRACE_SECONDS)
            + " seconds if it is still running")


def respond(alert, terminate=None):
    if not config.RESPONSE_ENABLED:
        return None

    if not severity_allows_action(alert.get("severity")):
        return None

    pid = alert.get("pid")
    comm = alert.get("comm")
    rule = alert.get("rule")
    severity = alert.get("severity")

    reason = protection_reason(pid, comm)
    if reason is not None:
        return record_action(pid, comm, rule, severity, "guard_blocked", reason)

    if config.RESPONSE_DRY_RUN:
        return record_action(
            pid, comm, rule, severity, "dry_run",
            "dry-run is on: would have sent SIGTERM, then SIGKILL after "
            + str(config.RESPONSE_GRACE_SECONDS) + " seconds if still running"
        )

    kill = terminate or _terminate_process
    try:
        outcome = kill(alert)
    except OSError as error:
        return record_action(pid, comm, rule, severity, "guard_blocked",
                             "the operating system refused: " + str(error))
    return record_action(pid, comm, rule, severity, "executed", outcome)
