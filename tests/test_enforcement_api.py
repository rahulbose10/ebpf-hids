import os

import pytest

from server import auth, config, response


def make_client(app, username, role):
    auth.create_user(username, "pass-" + username, role)
    client = app.test_client()
    assert client.post("/api/login", json={"username": username, "password": "pass-" + username}).status_code == 200
    return client


@pytest.fixture(autouse=True)
def safe_defaults(monkeypatch):
    monkeypatch.setattr(config, "RESPONSE_ENABLED", False)
    monkeypatch.setattr(config, "RESPONSE_DRY_RUN", True)
    monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "critical")
    monkeypatch.setattr(response, "_proc_comm", lambda pid: None)
    response.clear_actions()
    yield
    response.clear_actions()


def test_viewer_reads_but_cannot_change_anything(app):
    viewer = make_client(app, "viewer1", "viewer")
    body = viewer.get("/api/enforcement").get_json()
    assert body["enabled"] is False
    assert body["dry_run"] is True
    assert body["min_severity"] == "critical"
    assert body["counts"] == {"executed": 0, "dry_run": 0, "guard_blocked": 0}
    assert body["actions"] == []
    assert "sshd" in body["never_kill"]

    assert viewer.post("/api/enforcement", json={"enabled": True}).status_code == 403
    assert viewer.post("/api/enforcement/action", json={"pid": 1}).status_code == 403
    assert viewer.post("/api/enforcement/clear").status_code == 403
    assert config.RESPONSE_ENABLED is False


def test_analyst_can_request_but_not_arm_or_clear(app):
    analyst = make_client(app, "analyst1", "analyst")
    assert analyst.post("/api/enforcement/action", json={"pid": 1}).status_code == 200
    assert analyst.post("/api/enforcement", json={"enabled": True}).status_code == 403
    assert analyst.post("/api/enforcement/clear").status_code == 403
    assert config.RESPONSE_ENABLED is False


def test_viva_pid1_sshd_and_the_server_are_refused_with_reasons(app):
    admin = make_client(app, "admin1", "admin")
    targets = [{"pid": 1}, {"pid": 987650, "comm": "sshd"}, {"pid": os.getpid()}]
    for body in targets:
        entry = admin.post("/api/enforcement/action", json=body).get_json()
        assert entry["decision"] == "guard_blocked", f"{body} was not blocked"
        assert entry["reason"].startswith("guard:")
        assert entry["rule"] == "manual by admin1"

    state = admin.get("/api/enforcement").get_json()
    assert state["counts"]["guard_blocked"] == 3
    assert [a["pid"] for a in state["actions"]] == [os.getpid(), 987650, 1]


def test_unprotected_target_is_dry_run_until_armed(app):
    admin = make_client(app, "admin2", "admin")
    entry = admin.post("/api/enforcement/action", json={"pid": 987654, "comm": "evil"}).get_json()
    assert entry["decision"] == "dry_run"
    assert "responder is off" in entry["reason"]

    admin.post("/api/enforcement", json={"enabled": True})
    entry = admin.post("/api/enforcement/action", json={"pid": 987654, "comm": "evil"}).get_json()
    assert entry["decision"] == "dry_run"
    assert "dry-run is on" in entry["reason"]


def test_admin_changes_settings_and_bad_input_changes_nothing(app):
    admin = make_client(app, "admin3", "admin")
    body = admin.post("/api/enforcement", json={"enabled": True, "min_severity": "high"}).get_json()
    assert body["enabled"] is True
    assert body["dry_run"] is True
    assert body["min_severity"] == "high"
    assert config.RESPONSE_ENABLED is True

    bad = [
        {},
        {"enabled": "yes"},
        {"dry_run": 0},
        {"min_severity": "extreme"},
        {"enabled": False, "kill_everything": True},
    ]
    for payload in bad:
        assert admin.post("/api/enforcement", json=payload).status_code == 400, f"{payload} was accepted"
    assert config.RESPONSE_ENABLED is True
    assert config.RESPONSE_MIN_SEVERITY == "high"


def test_bad_action_requests_are_refused(app):
    admin = make_client(app, "admin4", "admin")
    for payload in ({}, {"pid": "1"}, {"pid": 0}, {"pid": -5}, {"pid": True}, {"pid": 1.5}, {"pid": 4000, "comm": 7}):
        assert admin.post("/api/enforcement/action", json=payload).status_code == 400, f"{payload} was accepted"
    assert response.recent_actions() == []


def test_clear_empties_the_log(app):
    admin = make_client(app, "admin5", "admin")
    admin.post("/api/enforcement/action", json={"pid": 1})
    admin.post("/api/enforcement/action", json={"pid": 2})
    assert admin.post("/api/enforcement/clear").get_json() == {"cleared": 2}
    assert admin.get("/api/enforcement").get_json()["actions"] == []
