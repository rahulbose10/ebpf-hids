import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from engine import Engine


# ---------- 1. ransomware_burst (T1486) ----------

def test_ransomware_burst_positive():
    eng = Engine()
    for i in range(9):
        eng.process_event({"ts": i * 0.5, "pid": 1040, "ppid": 1, "uid": 1000, "comm": "enc", "type": "UNLINK", "detail": f"/home/f{i}.txt"})
    rule_ids = [a["rule"] for a in eng.alerts]
    assert "ransomware_burst" in rule_ids


def test_ransomware_burst_negative_slow_deletes():
    eng = Engine()
    for i in range(9):
        eng.process_event({"ts": i * 10.0, "pid": 2040, "ppid": 1, "uid": 1000, "comm": "cleanup", "type": "UNLINK", "detail": f"/tmp/old{i}.txt"})
    rule_ids = [a["rule"] for a in eng.alerts]
    assert "ransomware_burst" not in rule_ids


# ---------- 2. log_tampering (T1070) ----------

def test_log_tampering_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1050, "ppid": 0, "uid": 0, "comm": "attacker", "type": "UNLINK", "detail": "/var/log/auth.log"})
    assert any(a["rule"] == "log_tampering" for a in alerts)


def test_log_tampering_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2050, "ppid": 0, "uid": 1000, "comm": "app", "type": "OPEN", "detail": "/home/user/notes.txt"})
    assert not any(a["rule"] == "log_tampering" for a in alerts)


# ---------- 3. persistence_autostart (T1547) ----------

def test_persistence_autostart_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1060, "ppid": 0, "uid": 0, "comm": "malware", "type": "OPEN", "detail": "/etc/cron.d/evil"})
    assert any(a["rule"] == "persistence_autostart" for a in alerts)


def test_persistence_autostart_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2060, "ppid": 0, "uid": 1000, "comm": "app", "type": "OPEN", "detail": "/home/user/notes.txt"})
    assert not any(a["rule"] == "persistence_autostart" for a in alerts)


# ---------- 4. credential_access (T1003) ----------

def test_credential_access_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1070, "ppid": 0, "uid": 1000, "comm": "cat", "type": "OPEN", "detail": "/etc/shadow"})
    assert any(a["rule"] == "credential_access" for a in alerts)


def test_credential_access_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2070, "ppid": 0, "uid": 1000, "comm": "cat", "type": "OPEN", "detail": "/etc/hostname"})
    assert not any(a["rule"] == "credential_access" for a in alerts)


# ---------- 5. suid_backdoor (T1548) ----------

def test_suid_backdoor_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1080, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/tmp/x mode=4755"})
    assert any(a["rule"] == "suid_backdoor" for a in alerts)


def test_suid_backdoor_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2080, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/tmp/x mode=0755"})
    assert not any(a["rule"] == "suid_backdoor" for a in alerts)


# ---------- 6. world_writable_sensitive (T1222) ----------

def test_world_writable_sensitive_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1090, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/etc/passwd mode=0666"})
    assert any(a["rule"] == "world_writable_sensitive" for a in alerts)


def test_world_writable_sensitive_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2090, "ppid": 0, "uid": 0, "comm": "chmod", "type": "CHMOD", "detail": "/etc/passwd mode=0644"})
    assert not any(a["rule"] == "world_writable_sensitive" for a in alerts)


# ---------- 7. code_injection_rwx (T1055) ----------

def test_code_injection_rwx_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1100, "ppid": 0, "uid": 1000, "comm": "malware", "type": "MPROTECT", "detail": "addr=0x7f0000 prot=rwx"})
    assert any(a["rule"] == "code_injection_rwx" for a in alerts)


def test_code_injection_rwx_negative():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2100, "ppid": 0, "uid": 1000, "comm": "app", "type": "MPROTECT", "detail": "addr=0x7f0000 prot=rw"})
    assert not any(a["rule"] == "code_injection_rwx" for a in alerts)


# ---------- 8. kernel_module_load (T1547) ----------

def test_kernel_module_load_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1110, "ppid": 0, "uid": 0, "comm": "insmod", "type": "MODULE", "detail": "evil.ko"})
    assert any(a["rule"] == "kernel_module_load" for a in alerts)
    fired = [a for a in alerts if a["rule"] == "kernel_module_load"][0]
    assert fired["severity"] == "critical"


def test_kernel_module_load_negative_no_module_event():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2110, "ppid": 0, "uid": 1000, "comm": "app", "type": "EXEC", "detail": "/usr/bin/app"})
    assert not any(a["rule"] == "kernel_module_load" for a in alerts)


# ---------- 9. backdoor_listener (T1071) ----------

def test_backdoor_listener_positive():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 1120, "ppid": 0, "uid": 0, "comm": "bash", "type": "BIND", "detail": "0.0.0.0:4444"})
    assert any(a["rule"] == "backdoor_listener" for a in alerts)


def test_backdoor_listener_negative_normal_service():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 2120, "ppid": 0, "uid": 0, "comm": "nginx", "type": "BIND", "detail": "0.0.0.0:80"})
    assert not any(a["rule"] == "backdoor_listener" for a in alerts)


# ---------- 10. download_and_execute (T1059) ----------

def test_download_and_execute_positive():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 1130, "ppid": 0, "uid": 1000, "comm": "curl", "type": "CONNECT", "detail": "9.9.9.9:80"})
    alerts = eng.process_event({"ts": 3.0, "pid": 1130, "ppid": 0, "uid": 1000, "comm": "curl", "type": "EXEC", "detail": "/tmp/payload"})
    assert any(a["rule"] == "download_and_execute" for a in alerts)


def test_download_and_execute_negative_not_tmp():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 2130, "ppid": 0, "uid": 1000, "comm": "apt", "type": "CONNECT", "detail": "8.8.8.8:80"})
    alerts = eng.process_event({"ts": 3.0, "pid": 2130, "ppid": 0, "uid": 1000, "comm": "apt", "type": "EXEC", "detail": "/usr/bin/dpkg"})
    assert not any(a["rule"] == "download_and_execute" for a in alerts)