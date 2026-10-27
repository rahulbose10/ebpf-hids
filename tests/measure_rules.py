import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from engine import Engine


def build_corpus():
    """
    প্রতিটা rule-এর জন্য একটা malicious কেস (pid 1000+) আর একটা benign কেস (pid 2000+)।
    Ground truth PID অনুযায়ী আগে থেকেই ঠিক করা - rule চালিয়ে না, তাই এটা সৎ পরিমাপ।
    """
    events = []

    # 1. connect_after_exec (T1071) - malicious pid 1001, benign pid 2001
    events += [
        {"ts": 1.0, "pid": 1001, "ppid": 1, "uid": 1000, "comm": "mal", "type": "EXEC", "detail": "/tmp/x"},
        {"ts": 2.0, "pid": 1001, "ppid": 1, "uid": 1000, "comm": "mal", "type": "CONNECT", "detail": "1.2.3.4:4444"},
        {"ts": 1.0, "pid": 2001, "ppid": 1, "uid": 1000, "comm": "app", "type": "EXEC", "detail": "/usr/bin/app"},
        {"ts": 100.0, "pid": 2001, "ppid": 1, "uid": 1000, "comm": "app", "type": "CONNECT", "detail": "1.1.1.1:443"},
    ]

    # 2. network_parent_shell (T1059) - malicious pid 1011 (child of 1010), benign pid 2011
    events += [
        {"ts": 1.0, "pid": 1010, "ppid": 0, "uid": 0, "comm": "sshd", "type": "CONNECT", "detail": "1.2.3.4:22"},
        {"ts": 2.0, "pid": 1011, "ppid": 1010, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"},
        {"ts": 1.0, "pid": 2010, "ppid": 0, "uid": 1000, "comm": "systemd", "type": "EXEC", "detail": "/sbin/init"},
        {"ts": 2.0, "pid": 2011, "ppid": 2010, "uid": 1000, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"},
    ]

    # 3. ptrace_then_exec (T1055) - malicious pid 1020, benign pid 2020
    events += [
        {"ts": 1.0, "pid": 1020, "ppid": 1, "uid": 0, "comm": "gdb", "type": "PTRACE", "detail": "target_pid=200"},
        {"ts": 2.0, "pid": 1020, "ppid": 1, "uid": 0, "comm": "gdb", "type": "EXEC", "detail": "/usr/bin/gdb"},
        {"ts": 1.0, "pid": 2020, "ppid": 1, "uid": 0, "comm": "gdb", "type": "PTRACE", "detail": "target_pid=300"},
        {"ts": 100.0, "pid": 2020, "ppid": 1, "uid": 0, "comm": "gdb", "type": "EXEC", "detail": "/usr/bin/gdb"},
    ]

    # 4. suid_shell (T1548) - malicious pid 1030, benign pid 2030
    events += [
        {"ts": 1.0, "pid": 1030, "ppid": 1, "uid": 1000, "comm": "sudo", "type": "SETUID", "detail": "old_uid=1000 new_uid=0"},
        {"ts": 2.0, "pid": 1030, "ppid": 1, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"},
        {"ts": 1.0, "pid": 2030, "ppid": 1, "uid": 1000, "comm": "sudo", "type": "SETUID", "detail": "old_uid=1000 new_uid=0"},
        {"ts": 2.0, "pid": 2030, "ppid": 1, "uid": 0, "comm": "systemctl", "type": "EXEC", "detail": "/usr/bin/systemctl"},
    ]

    # 5. ransomware_burst (T1486) - malicious pid 1040, benign pid 2040
    for i in range(9):
        events.append({"ts": i * 0.5, "pid": 1040, "ppid": 1, "uid": 1000, "comm": "enc", "type": "UNLINK", "detail": f"/home/f{i}.txt"})
    for i in range(9):
        events.append({"ts": i * 10.0, "pid": 2040, "ppid": 1, "uid": 1000, "comm": "cleanup", "type": "UNLINK", "detail": f"/tmp/old{i}.txt"})

    # 6. log_tampering (T1070) - malicious pid 1050, benign pid 2050
    events += [
        {"ts": 1.0, "pid": 1050, "ppid": 0, "uid": 0, "comm": "attacker", "type": "UNLINK", "detail": "/var/log/auth.log"},
        {"ts": 1.0, "pid": 2050, "ppid": 0, "uid": 1000, "comm": "app", "type": "OPEN", "detail": "/home/user/notes.txt"},
    ]

    # 7. persistence_autostart (T1547) - malicious pid 1060, benign pid 2060
    events += [
        {"ts": 1.0, "pid": 1060, "ppid": 0, "uid": 0, "comm": "malware", "type": "OPEN", "detail": "/etc/cron.d/evil"},
        {"ts": 1.0, "pid": 2060, "ppid": 0, "uid": 1000, "comm": "app", "type": "OPEN", "detail": "/home/user/notes.txt"},
    ]

    # 8. credential_access (T1003) - malicious pid 1070, benign pid 2070
    events += [
        {"ts": 1.0, "pid": 1070, "ppid": 0, "uid": 1000, "comm": "cat", "type": "OPEN", "detail": "/etc/shadow"},
        {"ts": 1.0, "pid": 2070, "ppid": 0, "uid": 1000, "comm": "cat", "type": "OPEN", "detail": "/etc/hostname"},
    ]

    # 9. suid_backdoor (T1548) - malicious pid 1080, benign pid 2080
    events += [
        {"ts": 1.0, "pid": 1080, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/tmp/x mode=4755"},
        {"ts": 1.0, "pid": 2080, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/tmp/x mode=0755"},
    ]

    # 10. world_writable_sensitive (T1222) - malicious pid 1090, benign pid 2090
    events += [
        {"ts": 1.0, "pid": 1090, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/etc/passwd mode=0666"},
        {"ts": 1.0, "pid": 2090, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/etc/passwd mode=0644"},
    ]

    # 11. code_injection_rwx (T1055) - malicious pid 1100, benign pid 2100
    events += [
        {"ts": 1.0, "pid": 1100, "ppid": 0, "uid": 1000, "comm": "malware", "type": "MPROTECT", "detail": "addr=0x7f0000 prot=rwx"},
        {"ts": 1.0, "pid": 2100, "ppid": 0, "uid": 1000, "comm": "app", "type": "MPROTECT", "detail": "addr=0x7f0000 prot=rw"},
    ]

    # 12. kernel_module_load (T1547) - malicious pid 1110, benign pid 2110 (no MODULE event = negative)
    events += [
        {"ts": 1.0, "pid": 1110, "ppid": 0, "uid": 0, "comm": "insmod", "type": "MODULE", "detail": "evil.ko"},
        {"ts": 1.0, "pid": 2110, "ppid": 0, "uid": 1000, "comm": "app", "type": "EXEC", "detail": "/usr/bin/app"},
    ]

    # 13. backdoor_listener (T1071) - malicious pid 1120, benign pid 2120
    events += [
        {"ts": 1.0, "pid": 1120, "ppid": 0, "uid": 0, "comm": "bash", "type": "BIND", "detail": "0.0.0.0:4444"},
        {"ts": 1.0, "pid": 2120, "ppid": 0, "uid": 0, "comm": "nginx", "type": "BIND", "detail": "0.0.0.0:80"},
    ]

    # 14. download_and_execute (T1059) - malicious pid 1130, benign pid 2130
    events += [
        {"ts": 1.0, "pid": 1130, "ppid": 0, "uid": 1000, "comm": "curl", "type": "CONNECT", "detail": "9.9.9.9:80"},
        {"ts": 3.0, "pid": 1130, "ppid": 0, "uid": 1000, "comm": "curl", "type": "EXEC", "detail": "/tmp/payload"},
        {"ts": 1.0, "pid": 2130, "ppid": 0, "uid": 1000, "comm": "apt", "type": "CONNECT", "detail": "8.8.8.8:80"},
        {"ts": 3.0, "pid": 2130, "ppid": 0, "uid": 1000, "comm": "apt", "type": "EXEC", "detail": "/usr/bin/dpkg"},
    ]

    malicious_pids = {1001, 1011, 1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100, 1110, 1120, 1130}
    benign_pids = {2001, 2011, 2020, 2030, 2040, 2050, 2060, 2070, 2080, 2090, 2100, 2110, 2120, 2130}

    return events, malicious_pids, benign_pids


def main():
    events, malicious_pids, benign_pids = build_corpus()

    eng = Engine(anomaly_model=None)
    events_sorted = sorted(events, key=lambda e: e["ts"])
    for evt in events_sorted:
        eng.process_event(evt)

    alerted_pids = {a["pid"] for a in eng.alerts}
    techniques_seen = {a["technique"] for a in eng.alerts if a["technique"]}

    tp = len(malicious_pids & alerted_pids)
    fn = len(malicious_pids - alerted_pids)
    fp = len(benign_pids & alerted_pids)
    tn = len(benign_pids - alerted_pids)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print(f"Total events: {len(events_sorted)}")
    print(f"Total alerts: {len(eng.alerts)}")
    print(f"Rules loaded: {len(eng.rules)}")
    print()
    print(f"True Positives (malicious pid, alerted):  {tp} / {len(malicious_pids)}")
    print(f"False Negatives (malicious pid, missed):  {fn}")
    print(f"False Positives (benign pid, alerted):    {fp}")
    print(f"True Negatives (benign pid, silent):      {tn} / {len(benign_pids)}")
    print()
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")
    print()
    print(f"Techniques covered ({len(techniques_seen)}): {sorted(techniques_seen)}")

    if fn > 0:
        print()
        print("MISSED malicious pids:", malicious_pids - alerted_pids)
    if fp > 0:
        print()
        print("FALSE ALARM benign pids:", benign_pids & alerted_pids)


if __name__ == "__main__":
    main()