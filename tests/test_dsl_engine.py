import pytest

from server import features
from server.engine import RULES_DIR, Engine, normalise
from server.rules_dsl import OPERATORS, Condition, RuleError, load_rules, load_rules_dir


def ev(ts, pid, ppid, comm, typ, detail, uid=1000):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": uid, "comm": comm, "type": typ, "detail": detail}


def test_rules_load_all_four_core():
    ids = [r.id for r in load_rules(RULES_DIR / "00_core.yml")]
    assert ids == ["connect_after_exec", "network_parent_shell", "ptrace_then_exec", "suid_shell"]


def test_all_fourteen_rules_load_with_no_errors():
    rules, errors = load_rules_dir(RULES_DIR)
    assert errors == []
    assert len(rules) == 14
    assert len({r.technique for r in rules}) == 9


def test_severities_match_the_team_mitre_map():
    expected = {
        "connect_after_exec": "medium", "network_parent_shell": "high",
        "ptrace_then_exec": "critical", "suid_shell": "high",
        "ransomware_burst": "critical", "log_tampering": "high",
        "persistence_autostart": "high", "credential_access": "high",
        "suid_backdoor": "high", "world_writable_sensitive": "medium",
        "code_injection_rwx": "high", "kernel_module_load": "critical",
        "backdoor_listener": "high", "download_and_execute": "high",
    }
    rules, _ = load_rules_dir(RULES_DIR)
    assert {r.id: r.severity for r in rules} == expected


@pytest.mark.parametrize("op,actual,value,result", [
    ("eq", "EXEC", "EXEC", True),
    ("eq", "OPEN", "EXEC", False),
    ("gte", 3, 3, True),
    ("gte", None, 1, False),
    ("lte", 2.9, 3.0, True),
    ("lte", None, 3.0, False),
    ("in_set", "sh", frozenset({"sh", "bash"}), True),
    ("in_set", None, frozenset({"sh"}), False),
    ("not_in_set", "nginx", frozenset({"sh"}), True),
    ("not_in_set", "sh", frozenset({"sh"}), False),
])
def test_operators(op, actual, value, result):
    assert OPERATORS[op](actual, value) is result


def test_matches_and_not_matches_use_compiled_regex():
    c = Condition({"field": "evt.detail", "op": "matches", "value": "^/var/log/"})
    assert c.func("/var/log/auth.log", c.value) is True
    assert c.func(None, c.value) is False
    n = Condition({"field": "evt.detail", "op": "not_matches", "value": ":53$"})
    assert n.func("127.0.0.53:53", n.value) is False
    assert n.func("1.2.3.4:443", n.value) is True


@pytest.mark.parametrize("raw", [
    {"field": "proc.conect_count", "op": "gte", "value": 1},
    {"field": "procs.connect_count", "op": "gte", "value": 1},
    {"field": "evt.colour", "op": "eq", "value": 1},
    {"field": "since.teleport", "op": "lte", "value": 1},
    {"field": "proc.connect_count", "op": "greater", "value": 1},
    {"field": "evt.detail", "op": "matches", "value": "("},
    {"field": "evt.type", "op": "in_set", "value": "EXEC"},
    {"field": "proc.connect_count", "op": "gte"},
])
def test_bad_conditions_are_rejected_at_load_time(raw):
    with pytest.raises(RuleError):
        Condition(raw)


def test_one_bad_rule_does_not_stop_the_others(tmp_path):
    (tmp_path / "00_ok.yml").write_text(
        "rules:\n"
        "  - id: good\n    technique: T1071\n    severity: low\n    description: ok\n"
        "    where:\n      - {field: evt.type, op: eq, value: CONNECT}\n"
        "  - id: typo\n    technique: T1071\n    severity: low\n    description: bad\n"
        "    where:\n      - {field: proc.conect_count, op: gte, value: 1}\n",
        encoding="utf-8",
    )
    (tmp_path / "10_broken.yml").write_text("rules: [this is: not: valid\n", encoding="utf-8")
    rules, errors = load_rules_dir(tmp_path)
    assert [r.id for r in rules] == ["good"]
    assert len(errors) == 2


def test_connect_after_exec_positive():
    eng = Engine()
    eng.process_event(ev(1.0, 5, 1, "bash", "EXEC", "/tmp/x"))
    alerts = eng.process_event(ev(2.5, 5, 1, "x", "CONNECT", "5.6.7.8:4444"))
    assert [a["rule"] for a in alerts] == ["connect_after_exec"]


def test_connect_after_exec_negative_slow():
    eng = Engine()
    eng.process_event(ev(1.0, 6, 1, "bash", "EXEC", "/usr/bin/app"))
    assert eng.process_event(ev(100.0, 6, 1, "app", "CONNECT", "1.1.1.1:443")) == []


def test_connect_after_exec_negative_dns_lookup():
    eng = Engine()
    eng.process_event(ev(1.0, 7, 1, "bash", "EXEC", "/usr/bin/ping"))
    assert eng.process_event(ev(1.2, 7, 1, "ping", "CONNECT", "127.0.0.53:53")) == []


def test_network_parent_shell_positive_comm_is_still_the_parent_name():
    eng = Engine()
    eng.process_event(ev(1.0, 10, 9, "python3", "CONNECT", "127.0.0.1:4444"))
    alerts = eng.process_event(ev(1.5, 11, 10, "python3", "EXEC", "/bin/sh"))
    assert [a["rule"] for a in alerts] == ["network_parent_shell"]
    assert alerts[0]["comm"] == "sh"


def test_network_parent_shell_negative_parent_never_connected():
    eng = Engine()
    eng.process_event(ev(1.0, 20, 1, "systemd", "EXEC", "/usr/bin/gnome-terminal-server"))
    assert eng.process_event(ev(2.0, 21, 20, "gnome-terminal-", "EXEC", "/bin/bash")) == []


def test_network_parent_shell_negative_child_is_not_a_shell():
    eng = Engine()
    eng.process_event(ev(1.0, 22, 1, "python3", "CONNECT", "127.0.0.1:8000"))
    assert eng.process_event(ev(1.1, 23, 22, "python3", "EXEC", "/usr/bin/ls")) == []


def test_ptrace_then_exec_positive():
    eng = Engine()
    eng.process_event(ev(1.0, 40, 1, "inj", "PTRACE", "target_pid=200"))
    alerts = eng.process_event(ev(2.0, 40, 1, "inj", "EXEC", "/bin/sh"))
    assert [a["rule"] for a in alerts] == ["ptrace_then_exec"]
    assert alerts[0]["severity"] == "critical"


def test_ptrace_alone_does_not_fire():
    eng = Engine()
    assert eng.process_event(ev(1.0, 41, 1, "gdb", "PTRACE", "target_pid=201")) == []


def test_ptrace_check_is_not_ptrace():
    eng = Engine()
    eng.process_event(ev(1.0, 42, 1, "ps", "PTRACE_CHECK", "target_pid=1 mode=0x5 suppressed=7"))
    assert eng.process_event(ev(1.5, 42, 1, "ps", "EXEC", "/bin/sh")) == []


def test_ptrace_then_exec_negative_too_slow():
    eng = Engine()
    eng.process_event(ev(1.0, 50, 1, "gdb", "PTRACE", "target_pid=300"))
    assert eng.process_event(ev(100.0, 50, 1, "gdb", "EXEC", "/usr/bin/gdb")) == []


def test_suid_shell_positive_comm_is_still_the_old_name():
    eng = Engine()
    eng.process_event(ev(1.0, 60, 1, "exploit", "SETUID", "old_uid=1000 new_uid=0"))
    alerts = eng.process_event(ev(1.2, 60, 1, "exploit", "EXEC", "/bin/sh", uid=0))
    assert [a["rule"] for a in alerts] == ["suid_shell"]


def test_suid_shell_negative_not_a_shell():
    eng = Engine()
    eng.process_event(ev(1.0, 80, 1, "sudo", "SETUID", "old_uid=1000 new_uid=0"))
    assert eng.process_event(ev(2.0, 80, 1, "sudo", "EXEC", "/usr/bin/systemctl", uid=0)) == []


def test_dedupe_suppresses_within_window():
    eng = Engine()
    eng.process_event(ev(1.0, 91, 1, "nc", "CONNECT", "1.2.3.4:4444"))
    a1 = eng.process_event(ev(2.0, 92, 91, "nc", "EXEC", "/bin/sh"))
    a2 = eng.process_event(ev(7.0, 92, 91, "sh", "EXEC", "/bin/bash"))
    assert len(a1) == 1
    assert a2 == []


def test_dedupe_fires_again_after_window():
    eng = Engine()
    eng.process_event(ev(1.0, 91, 1, "nc", "CONNECT", "1.2.3.4:4444"))
    eng.process_event(ev(2.0, 92, 91, "nc", "EXEC", "/bin/sh"))
    a3 = eng.process_event(ev(68.0, 92, 91, "sh", "EXEC", "/bin/bash"))
    assert [a["rule"] for a in a3] == ["network_parent_shell"]


def test_alert_dict_shape_matches_the_contract():
    eng = Engine()
    alert = eng.process_event(ev(1.0, 1110, 1, "insmod", "MODULE", "evil.ko", uid=0))[0]
    assert set(alert) == {"ts", "rule", "technique", "severity", "confidence", "pid",
                          "comm", "summary", "detail", "incident_id"}
    assert set(alert["detail"]) == {"event", "tactic", "technique"}
    assert alert["detail"]["tactic"] == "Persistence"
    assert alert["incident_id"] is None


def test_disabled_rule_does_not_fire_and_toggle_reports_back():
    eng = Engine()
    row = eng.set_rule_enabled("kernel_module_load", False)
    assert row["enabled"] is False
    assert eng.process_event(ev(1.0, 1, 0, "insmod", "MODULE", "x.ko", uid=0)) == []
    with pytest.raises(KeyError):
        eng.set_rule_enabled("no_such_rule", True)


def test_rules_info_counts_hits():
    eng = Engine()
    eng.process_event(ev(1.0, 1, 0, "insmod", "MODULE", "x.ko", uid=0))
    info = eng.rules_info()
    hits = {r["id"]: r["hits"] for r in info["rules"]}
    assert hits["kernel_module_load"] == 1
    assert info["errors"] == []


def test_bad_events_raise_value_error():
    with pytest.raises(ValueError):
        normalise({"ts": 1.0, "pid": 1})
    with pytest.raises(ValueError):
        normalise({"ts": "soon", "pid": 1, "ppid": 0, "uid": 0, "comm": "x", "type": "EXEC", "detail": ""})
    assert normalise({"ts": 1, "pid": "2", "ppid": 0, "uid": 0, "comm": None, "type": "EXEC", "detail": None})["comm"] == ""


def test_process_table_is_bounded():
    eng = Engine(max_processes=100)
    for i in range(1000):
        eng.process_event(ev(float(i), 10000 + i, 1, "true", "EXEC", "/usr/bin/true"))
    assert len(eng.processes) == 100
    assert 10999 in eng.processes and 10000 not in eng.processes


def test_alert_list_is_bounded_but_counts_are_not():
    eng = Engine(max_alerts=10)
    for i in range(50):
        eng.process_event(ev(float(i), 20000 + i, 1, "insmod", "MODULE", "x.ko", uid=0))
    assert len(eng.alerts) == 10
    assert eng.technique_counts["T1547"] == 50


def test_ignored_pid_never_alerts():
    eng = Engine(ignore_pids={4242})
    assert eng.process_event(ev(1.0, 4242, 1, "python3", "BIND", "127.0.0.1:5000")) == []


def test_depth_and_lineage():
    eng = Engine()
    eng.process_event(ev(1.0, 100, 1, "systemd", "EXEC", "/bin/bash"))
    eng.process_event(ev(2.0, 101, 100, "bash", "EXEC", "/usr/bin/python3"))
    eng.process_event(ev(3.0, 102, 101, "python3", "EXEC", "/bin/sh"))
    assert eng.lineage(102) == [102, 101, 100]
    assert eng.depth(102) == 2


class L3ShapedModel:
    def __init__(self, verdict=True):
        self.verdict = verdict
        self.seen = []

    def score(self, vec):
        self.seen.append(vec)
        return {"iforest_score": -0.3, "recon_error": None, "is_anomaly": self.verdict}


def fake_featurize(state, depth):
    return [float(state.exec_count), float(depth)] + [0.0] * 14


def test_ml_seam_passes_a_vector_and_raises_ml_anom():
    model = L3ShapedModel()
    eng = Engine(anomaly_model=model, featurize=fake_featurize)
    alerts = eng.process_event(ev(1.0, 101, 1, "x", "EXEC", "/bin/a"))
    assert model.seen[0][:2] == [1.0, 0.0]
    assert [a["rule"] for a in alerts] == ["ml_anomaly"]
    assert alerts[0]["technique"] == "ML-ANOM"
    assert eng.anomaly_scores[-1]["is_anomaly"] is True


def test_ml_alerts_are_deduped_like_rule_alerts():
    eng = Engine(anomaly_model=L3ShapedModel(), featurize=fake_featurize)
    for i in range(10):
        eng.process_event(ev(float(i), 102, 1, "x", "OPEN", f"/tmp/{i}"))
    assert sum(1 for a in eng.alerts if a["rule"] == "ml_anomaly") == 1
    assert len(eng.anomaly_scores) == 10


def test_ml_quiet_when_model_says_normal():
    eng = Engine(anomaly_model=L3ShapedModel(verdict=False), featurize=fake_featurize)
    assert eng.process_event(ev(1.0, 103, 1, "x", "EXEC", "/bin/a")) == []


def test_ml_crash_does_not_stop_the_rules():
    class Broken:
        def score(self, vec):
            raise RuntimeError("model file missing")

    eng = Engine(anomaly_model=Broken(), featurize=fake_featurize)
    alerts = eng.process_event(ev(1.0, 104, 1, "insmod", "MODULE", "x.ko", uid=0))
    assert [a["rule"] for a in alerts] == ["kernel_module_load"]
    assert eng.ml_errors == 1


def test_ml_seam_silent_without_model():
    eng = Engine()
    assert eng.process_event(ev(1.0, 100, 1, "test", "EXEC", "/bin/test")) == []


def test_model_without_featurizer_fails_loudly(monkeypatch):
    monkeypatch.delattr(features, "extract_features", raising=False)
    with pytest.raises(RuntimeError):
        Engine(anomaly_model=L3ShapedModel())


def test_recent_alerts_are_newest_first():
    eng = Engine()
    for i in range(3):
        eng.process_event(ev(float(i), 40000 + i, 1, "insmod", "MODULE", "x.ko", uid=0))
    assert [a["pid"] for a in eng.recent_alerts(limit=2)] == [40002, 40001]


# Shapes below were seen raising connect_after_exec during the 15 minute idle
# run on the dev VM (2026-10-27).

def started_then_connected(exe, dst, pid=40):
    eng = Engine()
    eng.process_event(ev(1.0, pid, 1, "bash", "EXEC", exe))
    return [a["rule"] for a in eng.process_event(ev(1.06, pid, 1, exe.rsplit("/", 1)[-1][:15], "CONNECT", dst))]


def test_connect_after_exec_negative_normal_network_clients():
    for exe, dst in [
        ("/usr/bin/curl", "104.20.23.154:443"),
        ("/usr/bin/wget", "104.20.23.154:443"),
        ("/usr/bin/ping", "142.251.220.110:1025"),
        ("/usr/lib/apt/methods/http", "91.189.91.82:80"),
        ("/usr/lib/apt/methods/https", "91.189.91.46:443"),
        ("/usr/lib/git-core/git-remote-https", "140.82.112.3:443"),
        ("/snap/thunderbird/700/thunderbird-bin", "54.192.151.117:443"),
    ]:
        assert started_then_connected(exe, dst) == [], exe


def test_connect_after_exec_positive_copied_client_outside_system_dirs():
    assert started_then_connected("/tmp/curl", "5.6.7.8:443") == ["connect_after_exec"]


def test_connect_after_exec_positive_interpreter_one_liner():
    assert started_then_connected("/usr/bin/python3", "127.0.0.1:4444") == ["connect_after_exec"]
