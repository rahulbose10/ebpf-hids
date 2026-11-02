import os
import subprocess

import pytest

from server import config, response


class FakeKiller:
    def __init__(self):
        self.calls = []

    def __call__(self, alert):
        self.calls.append(alert["pid"])
        return "fake kill"


def make_alert(pid, comm, severity="critical"):
    return {"rule": "ptrace_then_exec", "severity": severity, "pid": pid, "comm": comm}


@pytest.fixture(autouse=True)
def clean_log():
    response.clear_actions()
    yield
    response.clear_actions()


@pytest.fixture
def killer():
    return FakeKiller()


@pytest.fixture
def live_mode(monkeypatch):
    monkeypatch.setattr(config, "RESPONSE_ENABLED", True)
    monkeypatch.setattr(config, "RESPONSE_DRY_RUN", False)


@pytest.fixture
def dry_mode(monkeypatch):
    monkeypatch.setattr(config, "RESPONSE_ENABLED", True)
    monkeypatch.setattr(config, "RESPONSE_DRY_RUN", True)


def test_kill_guards_block_pid1_sshd_and_itself(live_mode, killer):
    targets = [(1, "systemd"), (5000, "sshd"), (os.getpid(), "python")]

    for pid, comm in targets:
        entry = response.respond(make_alert(pid, comm), killer)
        assert entry["decision"] == "guard_blocked", f"pid {pid} ({comm}) was not blocked"
        assert entry["reason"].startswith("guard:"), f"pid {pid} has no recorded reason"

    assert killer.calls == []

    logged = response.recent_actions()
    assert len(logged) == 3
    assert all(item["decision"] == "guard_blocked" for item in logged)
    assert all(item["reason"] for item in logged)
    assert {item["pid"] for item in logged} == {1, 5000, os.getpid()}


def test_pid_floor_blocks_any_name(live_mode, killer):
    entry = response.respond(make_alert(120, "whatever"), killer)
    assert entry["decision"] == "guard_blocked"
    assert "floor" in entry["reason"]
    assert killer.calls == []


def test_own_parent_process_is_protected(live_mode, killer):
    entry = response.respond(make_alert(os.getppid(), "launcher"), killer)
    assert entry["decision"] == "guard_blocked"
    assert killer.calls == []


def test_invalid_pids_are_refused(live_mode, killer):
    for bad in (0, -1, None, "123", True, 3.5):
        entry = response.respond(make_alert(bad, "evil"), killer)
        assert entry["decision"] == "guard_blocked", f"{bad!r} was not refused"
        assert "invalid pid" in entry["reason"]
    assert killer.calls == []


def test_responder_ships_off_and_in_dry_run(killer):
    assert config.RESPONSE_ENABLED is False
    assert config.RESPONSE_DRY_RUN is True
    assert config.RESPONSE_MIN_SEVERITY == "critical"

    assert response.respond(make_alert(987654, "evil"), killer) is None
    assert killer.calls == []
    assert response.recent_actions() == []


def test_low_severity_is_ignored(live_mode, killer):
    for severity in ("low", "medium", "high", "bogus", None):
        assert response.respond(make_alert(987654, "evil", severity), killer) is None
    assert killer.calls == []
    assert response.recent_actions() == []


def test_dry_run_logs_but_never_kills(dry_mode, killer):
    entry = response.respond(make_alert(987654, "evil"), killer)
    assert entry["decision"] == "dry_run"
    assert "dry-run" in entry["reason"]
    assert killer.calls == []


def test_bash_is_not_protected_by_name(live_mode, killer):
    attackers = [(987650, "bash"), (987651, "sh"), (987652, "python")]
    for pid, name in attackers:
        assert name not in config.NEVER_KILL
        entry = response.respond(make_alert(pid, name), killer)
        assert entry["decision"] == "executed", f"{name} was wrongly protected"
    assert killer.calls == [987650, 987651, 987652]


def test_os_refusal_is_logged_not_crashed(live_mode):
    def refuse(alert):
        raise PermissionError("operation not permitted")

    entry = response.respond(make_alert(987654, "evil"), refuse)
    assert entry["decision"] == "guard_blocked"
    assert "operating system refused" in entry["reason"]


def test_log_is_bounded():
    total = config.RESPONSE_LOG_MAX + 5
    for number in range(total):
        response.record_action(number, "evil", "r", "critical", "dry_run", "test")

    assert len(response._log) == config.RESPONSE_LOG_MAX
    kept = response.recent_actions(limit=config.RESPONSE_LOG_MAX)
    assert kept[0]["pid"] == total - 1
    assert kept[-1]["pid"] == 5



@pytest.fixture
def no_proc(monkeypatch):
    monkeypatch.setattr(response, "_proc_comm", lambda pid: None)


def test_manual_request_blocks_pid1_sshd_and_itself_with_defaults(no_proc, killer):
    targets = [(1, "systemd"), (987650, "sshd"), (os.getpid(), "python")]
    for pid, comm in targets:
        entry = response.manual_request(pid, comm, "tester", killer)
        assert entry["decision"] == "guard_blocked", f"pid {pid} ({comm}) was not blocked"
        assert entry["reason"].startswith("guard:")
        assert entry["rule"] == "manual by tester"
    assert killer.calls == []
    assert len(response.recent_actions()) == 3


def test_manual_request_is_dry_run_unless_armed(no_proc, killer, monkeypatch):
    entry = response.manual_request(987654, "evil", "tester", killer)
    assert entry["decision"] == "dry_run"
    assert "responder is off" in entry["reason"]

    monkeypatch.setattr(config, "RESPONSE_ENABLED", True)
    entry = response.manual_request(987654, "evil", "tester", killer)
    assert entry["decision"] == "dry_run"
    assert "dry-run is on" in entry["reason"]

    monkeypatch.setattr(config, "RESPONSE_ENABLED", False)
    monkeypatch.setattr(config, "RESPONSE_DRY_RUN", False)
    entry = response.manual_request(987654, "evil", "tester", killer)
    assert entry["decision"] == "dry_run"

    assert killer.calls == []


def test_manual_request_executes_only_when_armed(no_proc, live_mode, killer):
    entry = response.manual_request(987654, "evil", "tester", killer)
    assert entry["decision"] == "executed"
    assert killer.calls == [987654]


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="needs /proc")
def test_manual_request_uses_the_real_name_not_the_given_one(killer):
    child = subprocess.Popen(["sleep", "30"])
    try:
        entry = response.manual_request(child.pid, "not-sleep", "tester", killer)
        assert entry["comm"] == "sleep"
        assert entry["decision"] == "guard_blocked"
    finally:
        child.kill()
        child.wait()
    assert killer.calls == []
