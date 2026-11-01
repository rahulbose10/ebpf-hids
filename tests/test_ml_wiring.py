import sys
import types

import pytest

from server import config, db
from server.app import build_app, create_app, load_anomaly_model

SAMPLES = config.BASE_DIR / "samples" / "events.jsonl"


class FakeModel:
    has_autoencoder = True
    mode = "iforest+autoencoder+limits, test"
    ae_threshold = 0.5

    def __init__(self, alerting):
        self.alerting = alerting

    def score(self, vec):
        return {"iforest_score": 0.1, "recon_error": 0.9, "is_anomaly": True, "confidence": 0.7}


def replay(flask_app):
    pipeline = flask_app.extensions["hids"]["pipeline"]
    for line in SAMPLES.read_text(encoding="utf-8").splitlines():
        pipeline.feed_line(line)
    pipeline.drain(flush=True)
    return pipeline


def login(flask_app):
    client = flask_app.test_client()
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    return client


@pytest.fixture
def fake_loader(monkeypatch):
    calls = []

    def load_model(model_dir=None, alerting=None):
        calls.append({"model_dir": model_dir, "alerting": alerting})
        return FakeModel(alerting)

    monkeypatch.setitem(sys.modules, "server.ml_anomaly", types.SimpleNamespace(load_model=load_model))
    return calls


def test_default_start_loads_the_model_with_alerting_off(app, fake_loader):
    built = build_app(["--no-ingest"])
    assert fake_loader == [{"model_dir": config.MODEL_DIR, "alerting": False}]
    health = login(built).get("/api/health").get_json()
    assert health["ml_ready"] is True
    assert health["ml_alerting"] is False
    assert health["ml_has_autoencoder"] is True
    assert health["ml_mode"] == FakeModel.mode


def test_ml_alerting_flag_turns_alerting_on(app, fake_loader):
    build_app(["--no-ingest", "--ml-alerting"])
    assert fake_loader[0]["alerting"] is True


def test_no_ml_flag_never_touches_the_model(app, fake_loader):
    built = build_app(["--no-ingest", "--no-ml"])
    assert fake_loader == []
    health = built.test_client().get("/api/health").get_json()
    assert health["ml_ready"] is False
    assert health["ml_mode"] == "disabled"


def test_missing_ml_packages_do_not_stop_the_server(app, monkeypatch):
    monkeypatch.setitem(sys.modules, "server.ml_anomaly", None)
    assert load_anomaly_model() is None
    health = build_app(["--no-ingest"]).test_client().get("/api/health").get_json()
    assert health["status"] == "ok"
    assert health["ml_ready"] is False
    assert health["ml_mode"] == "not loaded"


def test_gauge_only_model_scores_every_event_and_raises_nothing(app):
    built = create_app(start_ingest=False, anomaly_model=FakeModel(alerting=False))
    pipeline = replay(built)
    assert pipeline.stats["ml_scored"] == 160
    assert pipeline.stats["ml_flagged"] == 160

    client = login(built)
    assert all(a["technique"] != "ML-ANOM" for a in client.get("/api/alerts").get_json()["alerts"])

    anomaly = client.get("/api/anomaly").get_json()
    assert anomaly["ml_ready"] is True and anomaly["ml_alerting"] is False
    assert anomaly["ae_threshold"] == 0.5
    assert anomaly["latest"]["recon_error"] == 0.9

    evaluation = client.get("/api/evaluation").get_json()
    assert evaluation["anomaly_scores"] == 160
    assert evaluation["anomalies_flagged"] == 160
    assert evaluation["ml_alerts"] == 0
    assert client.get("/api/health").get_json()["counts"]["anomalies"] == 160


def test_alerting_model_raises_ml_anom_and_it_stays_off_the_attack_map(app):
    built = create_app(start_ingest=False, anomaly_model=FakeModel(alerting=True))
    replay(built)
    client = login(built)
    evaluation = client.get("/api/evaluation").get_json()
    assert evaluation["ml_alerts"] > 0
    assert "ML-ANOM" not in evaluation["by_technique"]
    techniques = {t["technique"] for t in client.get("/api/mitre").get_json()["techniques"]}
    assert "ML-ANOM" not in techniques


def test_no_model_reports_no_threshold(client):
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    assert client.get("/api/anomaly").get_json()["ae_threshold"] is None


def test_real_model_trained_on_a_baseline_still_loads_with_alerting_off(app, monkeypatch, tmp_path):
    pytest.importorskip("numpy")
    pytest.importorskip("sklearn")
    from scripts.gen_baseline import generate_baseline_matrix
    from server import ml_anomaly

    model = ml_anomaly.fit(generate_baseline_matrix(400, seed=1), {"data_source": "baseline"},
                           n_estimators=60, autoencoders=0)
    ml_anomaly.save_model(model, tmp_path / "ml")
    monkeypatch.setattr(config, "MODEL_DIR", tmp_path / "ml")

    assert ml_anomaly.load_model(tmp_path / "ml").alerting is True
    loaded = load_anomaly_model()
    assert loaded.alerting is False

    built = create_app(start_ingest=False, anomaly_model=loaded)
    pipeline = replay(built)
    assert pipeline.stats["ml_scored"] == 160
    assert pipeline.summary()["engine_errors"] == 0
    assert all(a["technique"] != "ML-ANOM" for a in db.recent_alerts())
