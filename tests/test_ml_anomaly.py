import json
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from scripts.capture_baseline import replay_vectors
from scripts.gen_baseline import generate_baseline_matrix
from server import ml_anomaly
from server.features import FEATURE_NAMES, N_FEATURES

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "events.jsonl"


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    X = generate_baseline_matrix(400, seed=1)
    scaler = ml_anomaly.fit_scaler(X)
    forest = ml_anomaly.train_iforest(scaler.transform(X), n_estimators=60)
    folder = tmp_path_factory.mktemp("model")
    ml_anomaly.save_model(scaler, forest, {"data_source": "synthetic"}, None, folder)
    return X, folder


def far_point(X):
    return X.max(axis=0) + 1.0


def test_baseline_is_reproducible_and_16_wide():
    a = generate_baseline_matrix(50, seed=3)
    b = generate_baseline_matrix(50, seed=3)
    assert a.shape == (50, N_FEATURES)
    assert np.array_equal(a, b)


def test_sign_convention_negative_means_anomalous(trained):
    X, folder = trained
    model = ml_anomaly.load(folder)
    normal = model.score(np.median(X, axis=0))
    odd = model.score(far_point(X))
    assert normal["iforest_score"] > 0 and normal["is_anomaly"] is False
    assert odd["iforest_score"] < 0 and odd["is_anomaly"] is True
    assert odd["confidence"] > normal["confidence"]


def test_fast_single_row_matches_sklearn(trained):
    X, folder = trained
    model = ml_anomaly.load(folder)
    rows = np.vstack([X[:40], far_point(X)])
    single = [model.score(r)["iforest_score"] for r in rows]
    expected = model.iforest.decision_function(model.scaler.transform(rows))
    assert np.allclose(single, expected, atol=1e-9)


def test_scaler_is_fitted_once_not_at_scoring_time(trained):
    X, folder = trained
    model = ml_anomaly.load(folder)
    before = model.scaler.mean_.copy()
    model.score_many(np.tile(far_point(X), (20, 1)))
    assert np.array_equal(before, model.scaler.mean_)


def test_synthetic_model_defaults_to_gauge_only(trained):
    _, folder = trained
    model = ml_anomaly.load(folder)
    assert model.alerting is False
    assert model.has_autoencoder is False
    assert model.mode == "iforest, synthetic baseline"
    assert ml_anomaly.load(folder, alerting=True).alerting is True


def test_refuses_a_reordered_feature_list(trained, tmp_path):
    _, folder = trained
    for name in (ml_anomaly.SCALER_FILE, ml_anomaly.IFOREST_FILE):
        (tmp_path / name).write_bytes((folder / name).read_bytes())
    info = json.loads((folder / ml_anomaly.INFO_FILE).read_text())
    info["feature_names"] = list(reversed(info["feature_names"]))
    (tmp_path / ml_anomaly.INFO_FILE).write_text(json.dumps(info))
    with pytest.raises(ml_anomaly.ModelFileError):
        ml_anomaly.load(tmp_path)
    assert ml_anomaly.load_model(tmp_path) is None


def test_refuses_a_different_feature_count(trained, tmp_path):
    _, folder = trained
    info = json.loads((folder / ml_anomaly.INFO_FILE).read_text())
    info["n_features"] = 15
    (tmp_path / ml_anomaly.INFO_FILE).write_text(json.dumps(info))
    with pytest.raises(ml_anomaly.ModelFileError):
        ml_anomaly.read_info(tmp_path)


def test_missing_model_gives_none_not_a_crash(tmp_path):
    assert ml_anomaly.load_model(tmp_path / "nothing") is None


def test_capture_skips_single_event_processes():
    X, stats = replay_vectors(SAMPLES)
    assert X.shape[1] == N_FEATURES
    assert stats["bad_lines"] == 0
    assert stats["events"] == 160
    assert 0 < stats["processes_kept"] < stats["processes"]


def test_autoencoder_path_when_tensorflow_is_there(tmp_path):
    pytest.importorskip("tensorflow")
    X = generate_baseline_matrix(200, seed=2)
    scaler = ml_anomaly.fit_scaler(X)
    Xs = scaler.transform(X)
    forest = ml_anomaly.train_iforest(Xs, n_estimators=30)
    ae = ml_anomaly.train_autoencoder(Xs, epochs=2)
    layers = ml_anomaly.dense_layers(ae)
    assert layers[-1][2] is False
    assert all(relu for _, _, relu in layers[:-1])
    threshold = ml_anomaly.percentile_threshold(ml_anomaly.reconstruction_errors(layers, Xs))
    ml_anomaly.save_model(scaler, forest, {"data_source": "synthetic", "ae_threshold": threshold}, ae, tmp_path)
    model = ml_anomaly.load(tmp_path)
    assert model.has_autoencoder is True
    row = model.score(X[0])
    assert row["recon_error"] is not None
    assert row["is_anomaly"] == (row["iforest_anomaly"] or row["ae_anomaly"])
