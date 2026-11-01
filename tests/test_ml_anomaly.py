import json
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from scripts.capture_baseline import replay_rows, replay_vectors
from scripts.gen_baseline import generate_baseline_matrix
from server import ml_anomaly
from server.features import N_FEATURES

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "events.jsonl"
COL = ml_anomaly.COL


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    X = generate_baseline_matrix(400, seed=1)
    model = ml_anomaly.fit(X, {"data_source": "synthetic"}, n_estimators=60, autoencoders=0)
    folder = tmp_path_factory.mktemp("model")
    ml_anomaly.save_model(model, folder)
    return X, folder


@pytest.fixture(scope="module")
def one_hour(tmp_path_factory):
    X = generate_baseline_matrix(400, seed=4)
    X[:, COL["hour_of_day"]] = 3
    return X, ml_anomaly.fit(X, {"data_source": "baseline"}, n_estimators=60, autoencoders=0)


def far_point(X):
    return X.max(axis=0) + 1.0


def median_row(X):
    return np.median(X, axis=0)


def test_baseline_is_reproducible_and_16_wide():
    a = generate_baseline_matrix(50, seed=3)
    b = generate_baseline_matrix(50, seed=3)
    assert a.shape == (50, N_FEATURES)
    assert np.array_equal(a, b)


def test_sign_convention_negative_means_anomalous(trained):
    X, folder = trained
    model = ml_anomaly.load(folder)
    normal = model.score(median_row(X))
    odd = model.score(far_point(X))
    assert normal["iforest_score"] > 0 and normal["is_anomaly"] is False
    assert odd["iforest_score"] < 0 and odd["is_anomaly"] is True
    assert odd["confidence"] > normal["confidence"]


def test_fast_single_row_matches_sklearn(trained):
    X, folder = trained
    model = ml_anomaly.load(folder)
    rows = np.vstack([X[:40], far_point(X)])
    single = [model.score(r)["iforest_score"] for r in rows]
    expected = model.iforest.decision_function(model.model_input(rows))
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
    assert model.mode == "iforest+limits, synthetic baseline"
    assert ml_anomaly.load(folder, alerting=True).alerting is True


def test_the_clock_cannot_raise_alarms(one_hour, trained):
    X, model = one_hour
    _, folder = trained
    for X_used, m in ((X, model), (generate_baseline_matrix(400, seed=1), ml_anomaly.load(folder))):
        assert "hour_of_day" in m.prep.ignored_names()
        at_3 = median_row(X_used)
        at_3[COL["hour_of_day"]] = 3
        at_14 = at_3.copy()
        at_14[COL["hour_of_day"]] = 14
        assert m.score(at_3) == m.score(at_14)


def test_never_seen_ptrace_trips_the_limit(one_hour):
    X, model = one_hour
    assert X[:, COL["ptrace_count"]].max() == 0
    row = median_row(X)
    row[COL["ptrace_count"]] = 1
    result = model.score(row)
    assert result["limit_anomaly"] is True
    assert result["over_limit"] == ["ptrace_count"]
    assert result["is_anomaly"] is True


def test_limit_is_margin_past_the_largest_value_seen(one_hour):
    X, model = one_hour
    limits = dict(zip(ml_anomaly.LIMIT_FEATURES, model.prep.limits))
    assert limits["ptrace_count"] == pytest.approx(ml_anomaly.LIMIT_MARGIN - 1.0)
    biggest = X[:, COL["burst_rate"]].max()
    assert limits["burst_rate"] == pytest.approx(ml_anomaly.LIMIT_MARGIN * (biggest + 1.0) - 1.0)


def test_an_old_process_is_not_suspicious_for_being_old(one_hour):
    X, model = one_hour
    row = median_row(X)
    row[COL["lifetime_sec"]] = X[:, COL["lifetime_sec"]].max()
    older = row.copy()
    older[COL["lifetime_sec"]] *= 100
    assert model.score(row)["iforest_score"] == model.score(older)["iforest_score"]
    assert model.score(older)["over_limit"] == []


def test_destinations_count_per_second_not_in_total(one_hour):
    X, model = one_hour
    browser = median_row(X)
    browser[COL["distinct_dst"]] = 40
    browser[COL["lifetime_sec"]] = 3600
    scanner = median_row(X)
    scanner[COL["distinct_dst"]] = 100
    scanner[COL["lifetime_sec"]] = 1.0
    assert "dst_per_sec" not in model.score(browser)["over_limit"]
    assert "dst_per_sec" in model.score(scanner)["over_limit"]


def test_uid_flip_inside_sudo_does_not_change_the_score(one_hour):
    X, model = one_hour
    assert "uid" not in model.prep.kept_names()
    as_user = median_row(X)
    as_user[COL["uid"]] = 1000
    as_root = as_user.copy()
    as_root[COL["uid"]] = 0
    assert model.score(as_user) == model.score(as_root)


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


def test_refuses_a_model_from_the_old_format(trained, tmp_path):
    _, folder = trained
    info = json.loads((folder / ml_anomaly.INFO_FILE).read_text())
    del info["format"]
    (tmp_path / ml_anomaly.INFO_FILE).write_text(json.dumps(info))
    with pytest.raises(ml_anomaly.ModelFileError, match="older version"):
        ml_anomaly.read_info(tmp_path)


def test_missing_model_gives_none_not_a_crash(tmp_path):
    assert ml_anomaly.load_model(tmp_path / "nothing") is None


def test_autoencoder_weights_round_trip_without_tensorflow(tmp_path):
    rng = np.random.default_rng(0)
    nets = [[(rng.normal(size=(4, 3)).astype(np.float32), rng.normal(size=3).astype(np.float32), True),
             (rng.normal(size=(3, 4)).astype(np.float32), rng.normal(size=4).astype(np.float32), False)]
            for _ in range(2)]
    ml_anomaly.save_nets(nets, tmp_path / ml_anomaly.AE_FILE)
    back = ml_anomaly.load_nets(tmp_path / ml_anomaly.AE_FILE)
    Z = rng.normal(size=(5, 4))
    assert len(back) == 2
    assert np.array_equal(ml_anomaly.reconstruction_errors(nets, Z), ml_anomaly.reconstruction_errors(back, Z))


def test_capture_skips_single_event_processes():
    X, stats = replay_vectors(SAMPLES)
    assert X.shape[1] == N_FEATURES
    assert stats["bad_lines"] == 0
    assert stats["events"] == 160
    assert 0 < stats["processes_kept"] < stats["processes"]


def test_replay_rows_keeps_event_order_and_names():
    X, meta = replay_rows(SAMPLES)
    first = json.loads(SAMPLES.read_text(encoding="utf-8").splitlines()[0])
    assert X.shape == (160, N_FEATURES)
    assert len(meta) == 160
    assert meta[0] == {"pid": first["pid"], "comm": first["comm"], "type": first["type"]}


def test_autoencoder_path_when_tensorflow_is_there(tmp_path, monkeypatch):
    pytest.importorskip("tensorflow")
    X = generate_baseline_matrix(200, seed=2)
    model = ml_anomaly.fit(X, {"data_source": "synthetic"}, n_estimators=30, autoencoders=2, epochs=2)
    assert model.has_autoencoder is True and len(model.nets) == 2
    layers = model.nets[0]
    assert layers[-1][2] is False
    assert all(relu for _, _, relu in layers[:-1])
    ml_anomaly.save_model(model, tmp_path)
    monkeypatch.setattr(ml_anomaly, "import_keras", lambda: (None, "hidden for this test"))
    loaded = ml_anomaly.load(tmp_path)
    assert loaded.has_autoencoder is True
    row = loaded.score(X[0])
    assert row["recon_error"] == pytest.approx(model.score(X[0])["recon_error"])
    assert row["is_anomaly"] == (row["iforest_anomaly"] or row["ae_anomaly"] or row["limit_anomaly"])
