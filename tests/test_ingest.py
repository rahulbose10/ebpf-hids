import io
import json
from pathlib import Path

from server.engine import Engine
from server.ingest import run

MOCK = Path(__file__).resolve().parent / "data" / "mock_events.jsonl"


def test_bad_lines_are_counted_not_fatal():
    stream = io.StringIO(
        '{"ts": 1.0, "pid": 1, "ppid": 0, "uid": 0, "comm": "insmod", "type": "MODULE", "detail": "x.ko"}\r\n'
        "\n"
        "this is not json\n"
        '{"ts": 2.0, "pid": 2}\n'
        '{"ts": 3.0, "pid": 3, "ppid": 0, "uid": 0, "comm": "x", "type": "SETUID", "detail": ""}\n'
    )
    out, err = io.StringIO(), io.StringIO()
    stats = run(stream, Engine(), out=out, err=err)
    assert stats == {"lines": 4, "events": 2, "bad_lines": 2, "errors": 0, "alerts": 1}
    assert json.loads(out.getvalue().splitlines()[0])["rule"] == "kernel_module_load"
    assert "line 3 skipped" in err.getvalue()


def test_mock_file_matches_the_sensor_contract():
    keys = {"ts", "pid", "ppid", "uid", "comm", "type", "detail"}
    lines = [json.loads(l) for l in MOCK.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines
    assert all(set(e) == keys for e in lines)
    assert all(e["ts"] < 1e6 for e in lines)


def test_mock_file_raises_every_rule_and_benign_pids_stay_quiet():
    out, err = io.StringIO(), io.StringIO()
    with MOCK.open(encoding="utf-8") as stream:
        stats = run(stream, Engine(), out=out, err=err)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    assert stats["bad_lines"] == 0
    assert all(a["pid"] >= 2000 for a in alerts)
    assert {a["rule"] for a in alerts} == {
        "backdoor_listener", "code_injection_rwx", "connect_after_exec", "credential_access",
        "download_and_execute", "kernel_module_load", "log_tampering", "network_parent_shell",
        "persistence_autostart", "ptrace_then_exec", "ransomware_burst", "suid_backdoor",
        "suid_shell", "world_writable_sensitive",
    }
