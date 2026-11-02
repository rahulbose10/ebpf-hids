import json

from server import config, db, mitre, navigator

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"


def login(client):
    assert client.post("/api/login", json={"username": "tester", "password": "testpass"}).status_code == 200


def test_layer_has_the_fields_navigator_requires():
    layer = navigator.build_layer({})
    assert layer["name"]
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    major, minor, _ = (int(x) for x in layer["versions"]["navigator"].split("."))
    assert (major, minor) >= (4, 9)
    json.dumps(layer)


def test_ml_anom_and_other_non_techniques_are_filtered_out():
    layer = navigator.build_layer({"ML-ANOM": 50, "T1059": 2, "bogus": 3, "": 1, None: 4})
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "ML-ANOM" not in ids
    assert "bogus" not in ids
    assert all(navigator.TECHNIQUE_ID.fullmatch(i) for i in ids)


def test_every_mapped_technique_is_present_with_its_count():
    layer = navigator.build_layer({"T1059": 4, "T1055": 1})
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert set(mitre.TECHNIQUES) <= set(scores)
    assert scores["T1059"] == 4
    assert scores["T1055"] == 1
    assert scores["T1486"] == 0


def test_gradient_is_valid_even_with_no_alerts():
    gradient = navigator.build_layer({})["gradient"]
    assert gradient["maxValue"] > gradient["minValue"]
    assert len(gradient["colors"]) >= 2


def test_a_real_technique_outside_the_map_is_kept():
    layer = navigator.build_layer({"T1105": 2, "T1059.004": 1})
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1105"] == 2
    assert scores["T1059.004"] == 1


def test_endpoint_needs_login_and_matches_the_alerts(client, app):
    assert client.get("/api/navigator").status_code == 401
    assert client.get("/api/navigator/download").status_code == 401

    pipeline = app.extensions["hids"]["pipeline"]
    for raw in SAMPLES.read_text(encoding="utf-8").splitlines():
        pipeline.feed_line(raw)
    pipeline.drain(flush=True)
    db.insert_alert(1.0, "ml_anomaly", "ML-ANOM", "medium", 0.5, 4242, "firefox", "ml", {})

    login(client)
    layer = client.get("/api/navigator").get_json()
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "ML-ANOM" not in ids
    mitre_rows = client.get("/api/mitre").get_json()["techniques"]
    assert sum(t["score"] for t in layer["techniques"]) == sum(r["alert_count"] for r in mitre_rows) == 3


def test_download_is_an_attachment_with_the_same_layer(client):
    login(client)
    reply = client.get("/api/navigator/download")
    assert reply.status_code == 200
    assert reply.mimetype == "application/json"
    assert 'attachment; filename="ebpf-hids-layer.json"' == reply.headers["Content-Disposition"]
    assert json.loads(reply.data) == client.get("/api/navigator").get_json()
