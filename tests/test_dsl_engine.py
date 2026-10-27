import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from engine import Engine
from rules_dsl import load_rules, check_condition, resolve_field


def test_rules_load_all_four():
    rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "server", "rules", "00_core.yml"))
    ids = [r.id for r in rules]
    assert "connect_after_exec" in ids
    assert "network_parent_shell" in ids
    assert "ptrace_then_exec" in ids
    assert "suid_shell" in ids


def test_connect_after_exec_positive():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 5, "ppid": 1, "uid": 1000, "comm": "malware", "type": "EXEC", "detail": "/tmp/x"})
    alerts = eng.process_event({"ts": 2.5, "pid": 5, "ppid": 1, "uid": 1000, "comm": "malware", "type": "CONNECT", "detail": "5.6.7.8:4444"})
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "connect_after_exec"


def test_connect_after_exec_negative():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 6, "ppid": 1, "uid": 1000, "comm": "normal_app", "type": "EXEC", "detail": "/usr/bin/app"})
    alerts = eng.process_event({"ts": 100.0, "pid": 6, "ppid": 1, "uid": 1000, "comm": "normal_app", "type": "CONNECT", "detail": "1.1.1.1:443"})
    assert len(alerts) == 0


def test_network_parent_shell_positive():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 10, "ppid": 0, "uid": 0, "comm": "sshd", "type": "CONNECT", "detail": "1.2.3.4:22"})
    alerts = eng.process_event({"ts": 2.0, "pid": 11, "ppid": 10, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"})
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "network_parent_shell"


def test_network_parent_shell_negative():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 20, "ppid": 0, "uid": 1000, "comm": "systemd", "type": "EXEC", "detail": "/sbin/init"})
    alerts = eng.process_event({"ts": 2.0, "pid": 21, "ppid": 20, "uid": 1000, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"})
    assert len(alerts) == 0


def test_ptrace_then_exec_positive():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 40, "ppid": 1, "uid": 0, "comm": "gdb", "type": "PTRACE", "detail": "target_pid=200"})
    alerts = eng.process_event({"ts": 2.0, "pid": 40, "ppid": 1, "uid": 0, "comm": "gdb", "type": "EXEC", "detail": "/usr/bin/gdb"})
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ptrace_then_exec"


def test_ptrace_alone_does_not_fire():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 41, "ppid": 1, "uid": 0, "comm": "gdb", "type": "PTRACE", "detail": "target_pid=201"})
    assert len(alerts) == 0


def test_ptrace_then_exec_negative_too_slow():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 50, "ppid": 1, "uid": 0, "comm": "gdb", "type": "PTRACE", "detail": "target_pid=300"})
    alerts = eng.process_event({"ts": 100.0, "pid": 50, "ppid": 1, "uid": 0, "comm": "gdb", "type": "EXEC", "detail": "/usr/bin/gdb"})
    assert len(alerts) == 0


def test_suid_shell_positive():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 60, "ppid": 1, "uid": 1000, "comm": "sudo", "type": "SETUID", "detail": "old_uid=1000 new_uid=0"})
    alerts = eng.process_event({"ts": 2.0, "pid": 60, "ppid": 1, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"})
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "suid_shell"


def test_suid_shell_negative_not_a_shell():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 80, "ppid": 1, "uid": 1000, "comm": "sudo", "type": "SETUID", "detail": "old_uid=1000 new_uid=0"})
    alerts = eng.process_event({"ts": 2.0, "pid": 80, "ppid": 1, "uid": 0, "comm": "systemctl", "type": "EXEC", "detail": "/usr/bin/systemctl"})
    assert len(alerts) == 0


def test_dedupe_suppresses_within_window():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 91, "ppid": 0, "uid": 0, "comm": "sshd", "type": "CONNECT", "detail": "1.2.3.4:22"})
    a1 = eng.process_event({"ts": 2.0, "pid": 92, "ppid": 91, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"})
    a2 = eng.process_event({"ts": 7.0, "pid": 92, "ppid": 91, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/ls"})
    assert len(a1) == 1
    assert len(a2) == 0


def test_dedupe_fires_again_after_window():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 91, "ppid": 0, "uid": 0, "comm": "sshd", "type": "CONNECT", "detail": "1.2.3.4:22"})
    eng.process_event({"ts": 2.0, "pid": 92, "ppid": 91, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/bash"})
    eng.process_event({"ts": 7.0, "pid": 92, "ppid": 91, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/ls"})
    a3 = eng.process_event({"ts": 68.0, "pid": 92, "ppid": 91, "uid": 0, "comm": "bash", "type": "EXEC", "detail": "/bin/pwd"})
    assert len(a3) == 1


def test_ml_seam_fires_with_model():
    class FakeModel:
        threshold = 0.5
        def score(self, state):
            return 0.9 if state.exec_count > 2 else 0.1

    eng = Engine(anomaly_model=FakeModel())
    eng.process_event({"ts": 1.0, "pid": 101, "ppid": 1, "uid": 1000, "comm": "test", "type": "EXEC", "detail": "/bin/a"})
    eng.process_event({"ts": 2.0, "pid": 101, "ppid": 1, "uid": 1000, "comm": "test", "type": "EXEC", "detail": "/bin/b"})
    alerts = eng.process_event({"ts": 3.0, "pid": 101, "ppid": 1, "uid": 1000, "comm": "test", "type": "EXEC", "detail": "/bin/c"})
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ml_anomaly"


def test_ml_seam_silent_without_model():
    eng = Engine()
    alerts = eng.process_event({"ts": 1.0, "pid": 100, "ppid": 1, "uid": 1000, "comm": "test", "type": "EXEC", "detail": "/bin/test"})
    assert len(alerts) == 0