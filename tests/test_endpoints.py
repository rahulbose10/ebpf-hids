import re

import pytest

from server import auth, config

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"

NEEDS = {
    ("POST", "/api/login"): "public",
    ("POST", "/api/logout"): "public",
    ("GET", "/api/health"): "public",
    ("GET", "/api/me"): "viewer",
    ("GET", "/api/events"): "viewer",
    ("GET", "/api/processes"): "viewer",
    ("GET", "/api/alerts"): "viewer",
    ("GET", "/api/anomaly"): "viewer",
    ("GET", "/api/rules"): "viewer",
    ("GET", "/api/incidents"): "viewer",
    ("GET", "/api/incidents/<int:incident_id>"): "viewer",
    ("GET", "/api/evaluation"): "viewer",
    ("GET", "/api/mitre"): "viewer",
    ("GET", "/api/lineage/<int:pid>"): "viewer",
    ("GET", "/api/tree/<int:root>"): "viewer",
    ("GET", "/api/reports/summary"): "viewer",
    ("GET", "/api/reports/alerts.csv"): "viewer",
    ("GET", "/api/reports/incidents.csv"): "viewer",
    ("GET", "/api/reports/incident/<int:incident_id>.html"): "viewer",
    ("GET", "/api/navigator"): "viewer",
    ("GET", "/api/navigator/download"): "viewer",
    ("GET", "/api/iocs"): "viewer",
    ("GET", "/api/enforcement"): "viewer",
    ("POST", "/api/sim/<name>"): "analyst",
    ("POST", "/api/rules/<rule_id>/toggle"): "analyst",
    ("POST", "/api/incidents/<int:incident_id>/status"): "analyst",
    ("POST", "/api/iocs"): "analyst",
    ("DELETE", "/api/iocs/<int:ioc_id>"): "analyst",
    ("POST", "/api/enforcement/action"): "analyst",
    ("GET", "/api/apikeys"): "admin",
    ("POST", "/api/apikeys"): "admin",
    ("DELETE", "/api/apikeys/<int:key_id>"): "admin",
    ("GET", "/api/alerting"): "admin",
    ("POST", "/api/alerting"): "admin",
    ("POST", "/api/alerting/test"): "admin",
    ("GET", "/api/users"): "admin",
    ("POST", "/api/users"): "admin",
    ("DELETE", "/api/users/<username>"): "admin",
    ("POST", "/api/users/<username>/role"): "admin",
    ("POST", "/api/enforcement"): "admin",
    ("POST", "/api/enforcement/clear"): "admin",
}

LEVELS = ("public", "viewer", "analyst", "admin")

FILL = {
    "incident_id": "1", "key_id": "999999", "ioc_id": "999999", "pid": "999999", "root": "999999",
    "rule_id": "ptrace_then_exec", "name": "nope", "username": "nobody",
}


def concrete(rule):
    return re.sub(r"<(?:\w+:)?(\w+)>", lambda m: FILL[m.group(1)], rule)


def call(client, method, rule):
    body = {} if method == "POST" else None
    return client.open(concrete(rule), method=method, json=body)


def ordered():
    return sorted(NEEDS, key=lambda key: key == ("POST", "/api/logout"))


@pytest.fixture
def loaded(app):
    pipeline = app.extensions["hids"]["pipeline"]
    for raw in SAMPLES.read_text(encoding="utf-8").splitlines():
        pipeline.feed_line(raw)
    pipeline.drain(flush=True)
    return app


def client_as(app, role):
    client = app.test_client()
    if role == "admin":
        username, password = "tester", "testpass"
    else:
        username, password = "sweep-" + role, "pass-" + role
        auth.create_user(username, password, role)
    assert client.post("/api/login", json={"username": username, "password": password}).status_code == 200
    return client


def sweep(app, role):
    client = app.test_client() if role == "public" else client_as(app, role)
    return {key: call(client, *key).status_code for key in ordered()}


def test_the_table_lists_every_api_route_and_nothing_else(app):
    live = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api"):
            for method in rule.methods - {"HEAD", "OPTIONS"}:
                live.add((method, rule.rule))
    assert live == set(NEEDS)


@pytest.mark.parametrize("role", LEVELS)
def test_each_role_gets_exactly_what_the_table_says(loaded, role):
    codes = sweep(loaded, role)
    for key, code in codes.items():
        needed = NEEDS[key]
        assert code < 500, f"{role} {key} gave {code}"
        if needed == "public":
            continue
        if role == "public":
            assert code == 401, f"anonymous {key} gave {code}"
        elif LEVELS.index(role) < LEVELS.index(needed):
            assert code == 403, f"{role} {key} gave {code}"
        else:
            assert code not in (401, 403), f"{role} was refused {key} with {code}"
