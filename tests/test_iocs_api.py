import json

from server import auth, db
from server.app import create_app


def make_client(app, username, role):
    auth.create_user(username, "pass-" + username, role)
    client = app.test_client()
    assert client.post("/api/login", json={"username": username, "password": "pass-" + username}).status_code == 200
    return client


def feed_ptrace_then_exec(app):
    pipeline = app.extensions["hids"]["pipeline"]
    base = {"pid": 683409, "ppid": 683400, "uid": 1000, "comm": "victim"}
    pipeline.feed_line(json.dumps({**base, "ts": 8148.519372073, "type": "EXEC", "detail": "/bin/true"}))
    pipeline.feed_line(json.dumps({**base, "ts": 8148.519116233, "type": "PTRACE", "detail": "target_pid=1"}))
    pipeline.drain(flush=True)


def test_viewer_reads_but_cannot_add_or_delete(app):
    viewer = make_client(app, "viewer1", "viewer")
    body = viewer.get("/api/iocs").get_json()
    assert body["iocs"] == []
    assert body["types"] == ["ip", "path", "hash"]
    assert viewer.post("/api/iocs", json={"type": "ip", "value": "10.0.0.5"}).status_code == 403
    assert viewer.delete("/api/iocs/1").status_code == 403


def test_analyst_adds_each_type_and_the_live_store_gets_them(app):
    analyst = make_client(app, "analyst1", "analyst")
    good = [
        {"type": "ip", "value": "10.0.0.5", "description": "lab c2"},
        {"type": "ip", "value": "10.0.0.*"},
        {"type": "path", "value": "/tmp/evil.sh"},
        {"type": "path", "value": "*/payload"},
        {"type": "hash", "value": "D41D8CD98F00B204E9800998ECF8427E"},
    ]
    for payload in good:
        assert analyst.post("/api/iocs", json=payload).status_code == 201, f"{payload} was refused"

    rows = analyst.get("/api/iocs").get_json()["iocs"]
    assert [r["value"] for r in rows] == ["10.0.0.5", "10.0.0.*", "/tmp/evil.sh", "*/payload",
                                          "d41d8cd98f00b204e9800998ecf8427e"]
    assert all(r["added_by"] == "analyst1" for r in rows)

    store = app.extensions["hids"]["pipeline"].iocs
    assert sorted(i["id"] for i in store.all()) == sorted(r["id"] for r in rows)


def test_bad_indicators_are_refused(app):
    analyst = make_client(app, "analyst2", "analyst")
    bad = [
        {},
        {"type": "domain", "value": "evil.example"},
        {"type": "ip", "value": ""},
        {"type": "ip", "value": "not-an-ip"},
        {"type": "ip", "value": "999.1.1.1"},
        {"type": "path", "value": "relative/evil.sh"},
        {"type": "hash", "value": "xyz"},
        {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427"},
        {"type": "path", "value": "/tmp/x", "description": "d" * 201},
        {"type": "path", "value": "/" + "a" * 512},
    ]
    for payload in bad:
        assert analyst.post("/api/iocs", json=payload).status_code == 400, f"{payload} was accepted"
    assert db.list_iocs() == []


def test_duplicate_is_refused(app):
    analyst = make_client(app, "analyst3", "analyst")
    assert analyst.post("/api/iocs", json={"type": "ip", "value": "10.0.0.5"}).status_code == 201
    assert analyst.post("/api/iocs", json={"type": "ip", "value": " 10.0.0.5 "}).status_code == 409


def test_new_indicator_enriches_the_next_alert(app):
    analyst = make_client(app, "analyst4", "analyst")
    created = analyst.post("/api/iocs", json={"type": "path", "value": "/bin/true", "description": "lab marker"})
    ioc_id = created.get_json()["id"]

    feed_ptrace_then_exec(app)

    alert = next(a for a in db.recent_alerts() if a["rule"] == "ptrace_then_exec")
    assert alert["detail"]["ioc"] == [
        {"id": ioc_id, "type": "path", "pattern": "/bin/true", "description": "lab marker"}
    ]


def test_deleted_indicator_stops_matching(app):
    analyst = make_client(app, "analyst5", "analyst")
    ioc_id = analyst.post("/api/iocs", json={"type": "path", "value": "/bin/true"}).get_json()["id"]
    assert analyst.delete(f"/api/iocs/{ioc_id}").get_json() == {"deleted": ioc_id}
    assert analyst.delete(f"/api/iocs/{ioc_id}").status_code == 404

    feed_ptrace_then_exec(app)

    alert = next(a for a in db.recent_alerts() if a["rule"] == "ptrace_then_exec")
    assert "ioc" not in alert["detail"]
    assert app.extensions["hids"]["pipeline"].iocs.all() == []


def test_indicator_survives_a_restart(app):
    analyst = make_client(app, "analyst6", "analyst")
    ioc_id = analyst.post("/api/iocs", json={"type": "ip", "value": "10.0.0.5"}).get_json()["id"]

    restarted = create_app(start_ingest=False)
    store = restarted.extensions["hids"]["pipeline"].iocs
    assert [i["id"] for i in store.all()] == [ioc_id]
