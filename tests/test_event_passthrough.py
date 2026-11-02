import json

import pytest

from server import db


def make_event(ts, etype, detail, comm):
    return {"ts": ts, "pid": 683409, "ppid": 683400, "uid": 1000, "comm": comm, "type": etype, "detail": detail}


def feed(pipeline, events):
    for evt in events:
        pipeline.feed_line(json.dumps(evt) + "\n")
    pipeline.drain(flush=True)


@pytest.fixture
def core(app):
    return app.extensions["hids"]


def test_read_event_is_stored_unchanged(client, core):
    evt = make_event(2000.5, "READ", "/etc/shadow", "cat")
    feed(core["pipeline"], [evt])

    summary = core["pipeline"].summary()
    assert summary["bad_lines"] == 0
    assert summary["engine_errors"] == 0
    assert summary["events"] == 1

    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    stored = client.get("/api/events?limit=1").get_json()["events"][0]
    assert stored["type"] == "READ"
    assert stored["detail"] == "/etc/shadow"
    assert stored["comm"] == "cat"
    assert stored["ts"] == 2000.5


def test_longest_rename_detail_is_stored_in_full(client, core):
    old = "/tmp/" + "a" * 506
    new = "/tmp/" + "b" * 506
    detail = old + " -> " + new
    assert len(old) == 511
    assert len(new) == 511
    assert len(detail) == 1026

    feed(core["pipeline"], [make_event(2001.5, "RENAME", detail, "mv")])

    summary = core["pipeline"].summary()
    assert summary["bad_lines"] == 0
    assert summary["engine_errors"] == 0
    assert summary["events"] == 1

    from_db = db.recent_events(limit=1)[0]
    assert from_db["detail"] == detail

    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    from_api = client.get("/api/events?limit=1").get_json()["events"][0]
    assert from_api["type"] == "RENAME"
    assert from_api["detail"] == detail
    assert len(from_api["detail"]) == 1026
    assert from_api["detail"].split(" -> ", 1) == [old, new]


def test_rename_with_an_empty_old_side_is_stored(client, core):
    new = "/tmp/" + "c" * 100
    detail = " -> " + new

    feed(core["pipeline"], [make_event(2002.5, "RENAME", detail, "mv")])

    assert core["pipeline"].summary()["engine_errors"] == 0
    assert db.recent_events(limit=1)[0]["detail"] == detail
