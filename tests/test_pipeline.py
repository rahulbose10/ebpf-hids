import json

import pytest

from server import config, db
from server.app import create_app
from server.pipeline import ReorderBuffer

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"

CONTRACT_PROCESS_KEYS = {
    "pid", "ppid", "comm", "uid", "exec_count", "connect_count", "file_write_count",
    "ptrace_count", "setuid_count", "destruction_count", "module_count", "bind_count",
    "mprotect_exec_count", "ran_as_root", "depth", "lifetime_s",
}


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def event(ts, etype, detail, pid=683409, ppid=683400, comm="victim"):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": 1000, "comm": comm, "type": etype, "detail": detail}


def line(evt):
    return json.dumps(evt) + "\n"


EXEC_LATE_KTS = event(8148.519372073, "EXEC", "/bin/true")
PTRACE_EARLY_KTS = event(8148.519116233, "PTRACE", "target_pid=1")


def test_buffer_puts_an_inverted_pair_back_in_kernel_order():
    clock = FakeClock()
    buf = ReorderBuffer(hold=0.15, clock=clock)
    buf.push(EXEC_LATE_KTS)
    clock.now += 0.01
    buf.push(PTRACE_EARLY_KTS)
    assert buf.pop_ready() == []
    clock.now += 0.2
    assert [e["type"] for e in buf.pop_ready()] == ["PTRACE", "EXEC"]
    assert buf.reordered == 1
    assert buf.late == 0


def test_buffer_lets_a_very_late_event_through_and_counts_it():
    clock = FakeClock()
    buf = ReorderBuffer(hold=0.15, clock=clock)
    buf.push(EXEC_LATE_KTS)
    clock.now += 0.2
    assert len(buf.pop_ready()) == 1
    buf.push(PTRACE_EARLY_KTS)
    clock.now += 0.2
    assert [e["type"] for e in buf.pop_ready()] == ["PTRACE"]
    assert buf.late == 1


def test_buffer_cap_forces_release_without_waiting():
    clock = FakeClock()
    buf = ReorderBuffer(hold=10.0, max_events=3, clock=clock)
    for i in range(5):
        buf.push(event(float(i), "OPEN", "/tmp/x"))
    released = buf.pop_ready()
    assert [e["ts"] for e in released] == [0.0, 1.0]
    assert len(buf) == 3


def test_flush_empties_the_buffer():
    buf = ReorderBuffer(hold=10.0, clock=FakeClock())
    buf.push(EXEC_LATE_KTS)
    buf.push(PTRACE_EARLY_KTS)
    assert len(buf.pop_ready(flush=True)) == 2
    assert len(buf) == 0


@pytest.fixture
def core(app):
    return app.extensions["hids"]


def feed(pipeline, lines):
    for raw in lines:
        pipeline.feed_line(raw)
    pipeline.drain(flush=True)


def test_ptrace_then_exec_fires_only_because_of_the_buffer(core):
    pipeline = core["pipeline"]
    feed(pipeline, [line(EXEC_LATE_KTS), line(PTRACE_EARLY_KTS)])
    rules = [a["rule"] for a in db.recent_alerts()]
    assert "ptrace_then_exec" in rules


def test_without_reordering_the_same_pair_is_missed(core, monkeypatch):
    pipeline = core["pipeline"]
    monkeypatch.setattr(pipeline.buffer, "hold", 0.0)
    pipeline.feed_line(line(EXEC_LATE_KTS))
    pipeline.drain()
    pipeline.feed_line(line(PTRACE_EARLY_KTS))
    pipeline.drain(flush=True)
    assert "ptrace_then_exec" not in [a["rule"] for a in db.recent_alerts()]
    assert pipeline.buffer.late == 1


def test_sample_file_replays_end_to_end(client, core):
    pipeline = core["pipeline"]
    feed(pipeline, SAMPLES.read_text(encoding="utf-8").splitlines())
    s = pipeline.summary()
    assert s["events"] == 160
    assert s["bad_lines"] == 0
    assert s["engine_errors"] == 0
    assert s["fanout_errors"] == 0
    assert s["alerts"] == 3

    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    assert len(client.get("/api/events?limit=1000").get_json()["events"]) == 160

    alerts = client.get("/api/alerts").get_json()["alerts"]
    assert len(alerts) == 3
    assert all(a["incident_id"] is not None for a in alerts)

    incident_ids = {i["id"] for i in client.get("/api/incidents").get_json()["incidents"]}
    assert {a["incident_id"] for a in alerts} <= incident_ids

    rows = client.get("/api/processes?limit=1000").get_json()["processes"]
    assert rows and all(set(r) == CONTRACT_PROCESS_KEYS for r in rows)

    techniques = client.get("/api/mitre").get_json()["techniques"]
    assert len(techniques) == 9
    assert sum(t["alert_count"] for t in techniques) == 3

    health = client.get("/api/health").get_json()
    assert health["sensor_ready"] is False
    assert health["counts"]["events"] == 160
    assert health["counts"]["alerts"] == 3


def test_kernel_ts_is_stored_unchanged(client, core):
    evt = event(1284.378298, "OPEN", "/tmp/x", pid=4314)
    feed(core["pipeline"], [line(evt)])
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    stored = client.get("/api/events?limit=1").get_json()["events"][0]
    assert stored["ts"] == 1284.378298


def test_own_events_are_dropped(core):
    pipeline = core["pipeline"]
    feed(pipeline, [line(event(1.0, "OPEN", "/data/hids.db", pid=pipeline.own_pid))])
    assert pipeline.summary()["self_events"] == 1
    assert db.counts()["events"] == 0


def test_bad_lines_are_counted_not_fatal(core):
    pipeline = core["pipeline"]
    feed(pipeline, ["not json", json.dumps({"ts": 1}), line(event(2.0, "OPEN", "/tmp/y"))])
    s = pipeline.summary()
    assert s["bad_lines"] == 2
    assert s["events"] == 1


def resolve_first_incident(client):
    incident = client.get("/api/incidents").get_json()["incidents"][-1]
    return incident["id"], client.post(
        f"/api/incidents/{incident['id']}/status", json={"status": "resolved", "note": "lab test"})


def test_status_change_reaches_the_live_correlator(client, core):
    feed(core["pipeline"], SAMPLES.read_text(encoding="utf-8").splitlines())
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    incident_id, response = resolve_first_incident(client)
    assert response.status_code == 200
    assert response.get_json()["status"] == "resolved"
    assert core["incidents"].get(incident_id).status == "resolved"
    assert db.incident_audit(incident_id)[-1]["note"] == "lab test"


def test_illegal_transition_is_refused_and_same_status_is_a_no_op(client, core):
    feed(core["pipeline"], SAMPLES.read_text(encoding="utf-8").splitlines())
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    incident_id, _ = resolve_first_incident(client)
    refused = client.post(f"/api/incidents/{incident_id}/status", json={"status": "investigating"})
    assert refused.status_code == 409
    again = client.post(f"/api/incidents/{incident_id}/status", json={"status": "resolved"})
    assert again.status_code == 200
    assert len(db.incident_audit(incident_id)) == 1


def test_incident_ids_continue_after_a_restart(app, core):
    feed(core["pipeline"], SAMPLES.read_text(encoding="utf-8").splitlines())
    highest = db.max_incident_id()
    assert highest >= 1
    restarted = create_app(start_ingest=False)
    assert restarted.extensions["hids"]["incidents"].next_id == highest + 1


def test_rule_toggle_reaches_the_engine(client, core):
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    rule = next(r for r in core["engine"].rules if r.id == "ptrace_then_exec")
    assert rule.enabled is True
    assert client.post("/api/rules/ptrace_then_exec/toggle").get_json()["enabled"] is False
    assert rule.enabled is False
    feed(core["pipeline"], [line(PTRACE_EARLY_KTS), line(EXEC_LATE_KTS)])
    assert "ptrace_then_exec" not in [a["rule"] for a in db.recent_alerts()]
    assert client.post("/api/rules/nope/toggle").status_code == 404


def test_rules_endpoint_lists_all_fourteen(client):
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    body = client.get("/api/rules").get_json()
    assert len(body["rules"]) == 14
    assert body["errors"] == []
