import csv
import io

import pytest

from server import config, db, reports

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"
PATHS = [
    "/api/reports/summary",
    "/api/reports/alerts.csv",
    "/api/reports/incidents.csv",
    "/api/reports/incident/1.html",
]


@pytest.fixture
def replayed(client, app):
    pipeline = app.extensions["hids"]["pipeline"]
    for raw in SAMPLES.read_text(encoding="utf-8").splitlines():
        pipeline.feed_line(raw)
    pipeline.drain(flush=True)
    assert client.post("/api/login", json={"username": "tester", "password": "testpass"}).status_code == 200
    return client


def rows_of(reply):
    return list(csv.reader(io.StringIO(reply.get_data(as_text=True))))


def test_every_report_needs_login(client):
    for path in PATHS:
        assert client.get(path).status_code == 401, f"{path} was open"


def test_formula_cells_are_neutralised():
    for bad in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\t=1"):
        assert reports.safe_cell(bad) == "'" + bad
    assert reports.safe_cell("bash") == "bash"
    assert reports.safe_cell("/tmp/x") == "/tmp/x"
    assert reports.safe_cell(-5) == -5
    assert reports.safe_cell(1284.378298) == 1284.378298
    assert reports.safe_cell(None) == ""


def test_alerts_csv_has_every_alert_and_raw_kernel_ts(replayed):
    db.insert_alert(1284.378298, "manual_test", "T1059", "high", 0.9, 4321,
                    "=HYPERLINK(\"http://x\")", "test row", {})
    reply = replayed.get("/api/reports/alerts.csv")
    assert reply.status_code == 200
    assert reply.mimetype == "text/csv"
    assert reply.headers["Content-Disposition"] == 'attachment; filename="alerts.csv"'

    rows = rows_of(reply)
    assert tuple(rows[0]) == reports.ALERT_COLUMNS
    assert len(rows) - 1 == db.counts()["alerts"] == 4
    last = dict(zip(rows[0], rows[-1]))
    assert last["ts"] == "1284.378298"
    assert last["comm"].startswith("'=")


def test_incidents_csv_matches_the_incident_list(replayed):
    rows = rows_of(replayed.get("/api/reports/incidents.csv"))
    assert tuple(rows[0]) == reports.INCIDENT_COLUMNS
    listed = replayed.get("/api/incidents").get_json()["incidents"]
    assert sorted(int(r[0]) for r in rows[1:]) == sorted(i["id"] for i in listed)


def test_summary_numbers_agree_with_each_other(replayed):
    body = replayed.get("/api/reports/summary").get_json()
    assert sum(body["alerts_by_severity"].values()) == body["counts"]["alerts"] == 3
    assert sum(body["incidents_by_status"].values()) == body["counts"]["incidents"]
    assert sum(r["count"] for r in body["top_rules"]) == 3
    assert body["techniques"] == 9
    assert 1 <= body["techniques_with_alerts"] <= 3
    assert set(body["ml"]) == {"scored", "flagged"}


def test_incident_page_escapes_hostile_text_and_blocks_scripts(replayed):
    incident_id = replayed.get("/api/incidents").get_json()["incidents"][-1]["id"]
    db.insert_alert(2000.25, "manual_test", "T1059", "high", 0.9, 4321,
                    "<script>alert(1)</script>", "<img src=x onerror=alert(2)>", {}, incident_id)

    reply = replayed.get(f"/api/reports/incident/{incident_id}.html")
    assert reply.status_code == 200
    assert reply.mimetype == "text/html"
    assert "default-src 'none'" in reply.headers["Content-Security-Policy"]
    assert reply.headers["X-Content-Type-Options"] == "nosniff"

    page = reply.get_data(as_text=True)
    assert "<script>" not in page
    assert "<img" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "2000.25" in page
    assert f"Incident {incident_id}" in page


def test_unknown_incident_page_is_404(replayed):
    assert replayed.get("/api/reports/incident/999999.html").status_code == 404
