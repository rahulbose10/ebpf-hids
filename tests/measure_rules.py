import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.engine import Engine

ATTACK_PID_FLOOR = 2000


def ev(ts, pid, ppid, comm, typ, detail, uid=1000):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": uid, "comm": comm, "type": typ, "detail": detail}


def attacks():
    t = 1000.0
    yield "connect_after_exec", [
        ev(t, 2001, 1000, "bash", "EXEC", "/tmp/beacon"),
        ev(t + 1.0, 2001, 1000, "beacon", "CONNECT", "127.0.0.1:4444"),
    ]
    yield "network_parent_shell", [
        ev(t + 10, 2010, 1000, "python3", "CONNECT", "127.0.0.1:4444"),
        ev(t + 10.2, 2011, 2010, "python3", "EXEC", "/bin/sh"),
    ]
    yield "ptrace_then_exec", [
        ev(t + 20, 2020, 1000, "inject", "PTRACE", "target_pid=1001"),
        ev(t + 20.4, 2020, 1000, "inject", "EXEC", "/bin/sh"),
    ]
    yield "suid_shell", [
        ev(t + 30, 2030, 1000, "escalate", "SETUID", "old_uid=1000 new_uid=0"),
        ev(t + 30.2, 2030, 1000, "escalate", "EXEC", "/bin/sh", uid=0),
    ]
    yield "ransomware_burst", [
        ev(t + 40 + i * 0.1, 2040, 1000, "python3", "RENAME", f"/tmp/lab/f{i} -> /tmp/lab/f{i}.locked")
        for i in range(30)
    ]
    yield "log_tampering", [ev(t + 50, 2050, 1000, "rm", "UNLINK", "/var/log/auth.log", uid=0)]
    yield "persistence_autostart", [ev(t + 60, 2060, 1000, "tee", "OPEN", "/etc/cron.d/lab", uid=0)]
    yield "credential_access", [ev(t + 70, 2070, 1000, "tee", "OPEN", "/etc/shadow", uid=0)]
    yield "suid_backdoor", [ev(t + 80, 2080, 1000, "chmod", "CHMOD", "/tmp/lab/sh mode=4755")]
    yield "world_writable_sensitive", [ev(t + 90, 2090, 1000, "chmod", "CHMOD", "/etc/lab.conf mode=0666", uid=0)]
    yield "code_injection_rwx", [ev(t + 100, 2100, 1000, "sc", "MPROTECT", "addr=0x7f0000 prot=rwx suppressed=0")]
    yield "kernel_module_load", [ev(t + 110, 2110, 1000, "insmod", "MODULE", "dummy.ko", uid=0)]
    yield "backdoor_listener", [
        ev(t + 120, 2120, 1000, "bash", "EXEC", "/usr/bin/nc.openbsd"),
        ev(t + 120.1, 2120, 1000, "nc", "BIND", "127.0.0.1:4445"),
    ]
    yield "download_and_execute", [
        ev(t + 130, 2130, 1000, "curl", "CONNECT", "127.0.0.1:8000"),
        ev(t + 135, 2130, 1000, "curl", "OPEN", "/tmp/lab/payload"),
        ev(t + 137, 2131, 1000, "bash", "EXEC", "/tmp/lab/payload"),
    ]


def benign():
    t = 1000.0
    yield [ev(t, 1001, 1000, "bash", "EXEC", "/usr/bin/app"), ev(t + 100, 1001, 1000, "app", "CONNECT", "1.1.1.1:443")]
    yield [ev(t + 1, 1002, 1000, "bash", "EXEC", "/usr/bin/ping"), ev(t + 1.1, 1002, 1000, "ping", "CONNECT", "127.0.0.53:53")]
    yield [ev(t + 2, 1003, 1000, "python3", "CONNECT", "127.0.0.1:8000"), ev(t + 2.1, 1004, 1003, "python3", "EXEC", "/usr/bin/ls")]
    yield [ev(t + 3, 1005, 1000, "gdb", "PTRACE", "target_pid=1001"), ev(t + 99, 1005, 1000, "gdb", "EXEC", "/usr/bin/gdb")]
    yield [ev(t + 4, 1006, 1000, "ps", "PTRACE_CHECK", "target_pid=1 mode=0x5 suppressed=7"), ev(t + 4.1, 1006, 1000, "ps", "EXEC", "/bin/sh")]
    yield [ev(t + 5, 1007, 1000, "sudo", "SETUID", "old_uid=1000 new_uid=0"), ev(t + 5.1, 1007, 1000, "sudo", "EXEC", "/usr/bin/systemctl", uid=0)]
    yield [ev(t + 6 + i * 0.003, 1008, 999, "firefox", "RENAME", f"/home/u/.mozilla/s{i}.tmp -> /home/u/.mozilla/s{i}") for i in range(8)]
    yield [ev(t + 7 + i * 10, 1009, 1000, "tmpreaper", "UNLINK", f"/tmp/old{i}") for i in range(30)]
    yield [ev(t + 8, 1010, 1, "rs:main Q:Reg", "OPEN", "/var/log/syslog", uid=104)]
    yield [ev(t + 9, 1011, 0, "systemd", "OPEN", "/run/systemd/units/invocation:cron.service", uid=0)]
    yield [ev(t + 10, 1012, 0, "systemd", "OPEN", "/var/lib/systemd/timers/stamp-apt-daily.timer", uid=0)]
    yield [ev(t + 11, 1013, 1000, "ss-local", "OPEN", "/tmp/shadowsocks.json")]
    yield [ev(t + 12, 1014, 1000, "ssh-keygen", "OPEN", "/home/u/.ssh/id_ed25519")]
    yield [ev(t + 13, 1015, 1000, "chmod", "CHMOD", "/tmp/build.sh mode=0755")]
    yield [ev(t + 14, 1016, 1000, "chmod", "CHMOD", "/tmp mode=1777", uid=0)]
    yield [ev(t + 15, 1017, 1000, "chmod", "CHMOD", "/etc/hosts mode=0644", uid=0)]
    yield [ev(t + 16, 1018, 999, "gnome-shell", "MPROTECT", "addr=0x7f0000 prot=r-x suppressed=40")]
    yield [ev(t + 17, 1019, 1, "nginx", "BIND", "0.0.0.0:80", uid=0)]
    yield [ev(t + 18, 1020, 1000, "gcc", "OPEN", "/tmp/a.out"), ev(t + 19, 1021, 1000, "bash", "EXEC", "/tmp/a.out")]


def main():
    events = []
    expected = {}
    for rule_id, evs in attacks():
        events += evs
        expected[rule_id] = {e["pid"] for e in evs}
    for evs in benign():
        events += evs

    benign_pids = {e["pid"] for e in events if e["pid"] < ATTACK_PID_FLOOR}

    eng = Engine(anomaly_model=None)
    for e in sorted(events, key=lambda e: e["ts"]):
        eng.process_event(e)

    alerts = list(eng.alerts)
    true_alerts = [a for a in alerts if a["pid"] >= ATTACK_PID_FLOOR]
    false_alerts = [a for a in alerts if a["pid"] < ATTACK_PID_FLOOR]

    caught = {
        rule_id for rule_id, pids in expected.items()
        if any(a["rule"] == rule_id and a["pid"] in pids for a in alerts)
    }
    precision = len(true_alerts) / len(alerts) if alerts else 0.0
    recall = len(caught) / len(expected)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    techniques = sorted({a["technique"] for a in true_alerts})

    print(f"events: {len(events)}  alerts: {len(alerts)}  rules loaded: {len(eng.rules)}  rule errors: {len(eng.rule_errors)}")
    print(f"ground truth: pid >= {ATTACK_PID_FLOOR} is attack, set when the corpus was built, never by asking the rules")
    print(f"alert precision {precision:.3f}  ({len(true_alerts)} of {len(alerts)} alerts on attack pids)")
    print(f"scenario recall {recall:.3f}  ({len(caught)} of {len(expected)} attack scenarios caught by their rule)")
    print(f"F1 {f1:.3f}")
    print(f"benign pids alerted: {len({a['pid'] for a in false_alerts})} of {len(benign_pids)}")
    print()
    for rule_id in expected:
        print(f"  {rule_id:<26} {'fired' if rule_id in caught else 'MISSED'}")
    print()
    print(f"techniques covered ({len(techniques)}): {', '.join(techniques)}")
    for a in false_alerts:
        print(f"false alarm: {a['rule']} on pid {a['pid']} ({a['comm']}): {a['detail']['event']['detail']}")


if __name__ == "__main__":
    main()
