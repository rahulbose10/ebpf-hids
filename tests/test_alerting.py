import pytest

from server import alerting, auth, config, db

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Recorder:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, *args):
        self.calls.append(args)
        if self.fail:
            raise OSError("connection refused")
        return "HTTP 200"


@pytest.fixture(autouse=True)
def quiet_defaults(monkeypatch):
    monkeypatch.setattr(config, "ALERT_ENABLED", False)
    monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "high")
    monkeypatch.setattr(config, "ALERT_THROTTLE_SECONDS", 300)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    monkeypatch.setattr(config, "ALERT_SYSLOG_ENABLED", False)
    monkeypatch.setattr(config, "ALERT_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setattr(config, "ALERT_SYSLOG_PORT", 514)


@pytest.fixture
def armed(monkeypatch, app):
    monkeypatch.setattr(config, "ALERT_ENABLED", True)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "http://127.0.0.1:9/hook")
    return app


def make_notifier(webhook=None, clock=None):
    return alerting.Notifier(webhook=webhook or Recorder(), syslog=Recorder(),
                             run=lambda job: job(), clock=clock or FakeClock())


def alert(rule="suid_backdoor", severity="high"):
    return {"rule": rule, "technique": "T1548", "severity": severity, "confidence": 0.9,
            "pid": 4321, "comm": "evil", "summary": "s", "ts": 12.5, "incident_id": 7,
            "detail": {"event": {"detail": "/home/user/private"}}}


def make_client(app, username, role):
    auth.create_user(username, "pass-" + username, role)
    client = app.test_client()
    assert client.post("/api/login", json={"username": username, "password": "pass-" + username}).status_code == 200
    return client


def test_off_by_default_sends_nothing(app):
    hook = Recorder()
    notifier = make_notifier(hook)
    assert notifier.notify(alert()) == "off"
    assert hook.calls == []


def test_below_minimum_severity_is_skipped(armed):
    hook = Recorder()
    notifier = make_notifier(hook)
    assert notifier.notify(alert(severity="medium")) == "below_severity"
    assert hook.calls == []


def test_throttle_is_per_rule_and_expires(armed):
    clock = FakeClock()
    hook = Recorder()
    notifier = make_notifier(hook, clock)
    assert notifier.notify(alert("suid_backdoor")) == "queued"
    assert notifier.notify(alert("suid_backdoor")) == "throttled"
    assert notifier.notify(alert("backdoor_listener")) == "queued"
    clock.now += 301
    assert notifier.notify(alert("suid_backdoor")) == "queued"
    assert len(hook.calls) == 3
    assert notifier.stats["throttled"] == 1


def test_failed_delivery_is_logged_not_raised(armed):
    notifier = make_notifier(Recorder(fail=True))
    assert notifier.notify(alert(), alert_id=42) == "queued"
    assert notifier.stats["failed"] == 1
    row = db.recent_deliveries(1)[0]
    assert (row["alert_id"], row["channel"], row["status"]) == (42, "webhook", "failed")
    assert "connection refused" in row["detail"]


def test_webhook_body_leaves_out_the_raw_event():
    body = alerting.payload(alert())
    assert body["source"] == "ebpf-hids"
    assert body["incident_id"] == 7
    assert "detail" not in body


def test_syslog_line_cannot_be_split_by_a_hostile_name():
    hostile = dict(alert(severity="critical"), comm="x\n<34>ebpf-hids: fake alert", summary="a\rb")
    line = alerting.syslog_line(alerting.payload(hostile))
    assert line.startswith("<34>ebpf-hids: severity=critical")
    assert "\n" not in line and "\r" not in line
    assert alerting.syslog_line(alerting.payload(alert(severity="high"))).startswith("<35>")


def test_only_admins_reach_alerting(app):
    for role in ("viewer", "analyst"):
        client = make_client(app, role + "1", role)
        assert client.get("/api/alerting").status_code == 403
        assert client.post("/api/alerting", json={"enabled": True}).status_code == 403
        assert client.post("/api/alerting/test").status_code == 403
    assert config.ALERT_ENABLED is False


def test_bad_settings_change_nothing(app):
    admin = make_client(app, "admin1", "admin")
    bad = [
        {},
        {"enabled": "yes"},
        {"webhook_url": "ftp://x/y"},
        {"webhook_url": "not a url"},
        {"throttle_seconds": -1},
        {"syslog_port": 70000},
        {"syslog_host": "bad host"},
        {"min_severity": "extreme"},
        {"enabled": True, "send_to_everyone": True},
    ]
    for payload in bad:
        assert admin.post("/api/alerting", json=payload).status_code == 400, f"{payload} was accepted"
    assert config.ALERT_ENABLED is False
    assert config.ALERT_WEBHOOK_URL == ""


def test_settings_and_test_endpoint(app):
    admin = make_client(app, "admin2", "admin")
    assert admin.post("/api/alerting/test").status_code == 400

    body = admin.post("/api/alerting", json={"enabled": True, "webhook_url": "http://127.0.0.1:9/hook",
                                             "throttle_seconds": 60}).get_json()
    assert body["enabled"] is True
    assert body["channels"] == ["webhook"]
    assert body["throttle_seconds"] == 60

    hook = Recorder()
    app.extensions["hids"]["notifier"].webhook = hook
    results = admin.post("/api/alerting/test").get_json()["results"]
    assert results["webhook"]["status"] == "sent"
    assert hook.calls[0][1]["rule"] == "alerting_test"
    assert admin.get("/api/alerting").get_json()["deliveries"][0]["status"] == "sent"


def test_stored_alerts_reach_the_webhook_with_their_ids(armed, monkeypatch):
    monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "low")
    monkeypatch.setattr(config, "ALERT_THROTTLE_SECONDS", 0)
    notifier = armed.extensions["hids"]["notifier"]
    hook = Recorder()
    notifier.webhook = hook
    notifier.run = lambda job: job()

    pipeline = armed.extensions["hids"]["pipeline"]
    for raw in SAMPLES.read_text(encoding="utf-8").splitlines():
        pipeline.feed_line(raw)
    pipeline.drain(flush=True)

    assert pipeline.summary()["alerts"] == 3
    assert len(hook.calls) == 3
    assert all(call[1]["incident_id"] is not None for call in hook.calls)
    stored_ids = sorted(a["id"] for a in db.recent_alerts())
    logged_ids = sorted(row["alert_id"] for row in db.recent_deliveries(10))
    assert logged_ids == stored_ids
