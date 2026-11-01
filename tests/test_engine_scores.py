from server.engine import Engine


def ev(ts, pid, etype, detail):
    return {"ts": ts, "pid": pid, "ppid": 1, "uid": 1000, "comm": "x", "type": etype, "detail": detail}


def featurize(state, depth):
    return [0.0] * 16


class LimitModel:
    alerting = False

    def score(self, vec):
        return {"iforest_score": 0.02, "recon_error": 0.4, "is_anomaly": True, "iforest_anomaly": False,
                "ae_anomaly": False, "limit_anomaly": True, "over_limit": ["exec_count", "burst_rate"],
                "confidence": 0.41}


class OldShapeModel:
    alerting = False

    def score(self, vec):
        return {"iforest_score": 0.1, "recon_error": None, "is_anomaly": False}


def test_score_row_keeps_which_check_flagged_it():
    eng = Engine(anomaly_model=LimitModel(), featurize=featurize)
    eng.process_event(ev(1.0, 300, "EXEC", "/bin/a"))
    row = eng.anomaly_scores[-1]
    assert row["is_anomaly"] is True
    assert row["ae_anomaly"] is False
    assert row["limit_anomaly"] is True
    assert row["over_limit"] == ["exec_count", "burst_rate"]


def test_score_row_keeps_the_old_keys_unchanged():
    eng = Engine(anomaly_model=LimitModel(), featurize=featurize)
    eng.process_event(ev(1.0, 301, "OPEN", "/tmp/a"))
    row = eng.anomaly_scores[-1]
    assert {k: row[k] for k in ("pid", "comm", "ts", "iforest_score", "recon_error", "is_anomaly")} == {
        "pid": 301, "comm": "x", "ts": 1.0, "iforest_score": 0.02, "recon_error": 0.4, "is_anomaly": True}


def test_model_without_the_new_keys_gets_safe_defaults():
    eng = Engine(anomaly_model=OldShapeModel(), featurize=featurize)
    eng.process_event(ev(1.0, 302, "EXEC", "/bin/a"))
    row = eng.anomaly_scores[-1]
    assert row["ae_anomaly"] is False
    assert row["limit_anomaly"] is False
    assert row["over_limit"] == []


def test_row_does_not_share_the_models_list():
    model = LimitModel()
    eng = Engine(anomaly_model=model, featurize=featurize)
    eng.process_event(ev(1.0, 303, "EXEC", "/bin/a"))
    eng.anomaly_scores[-1]["over_limit"].append("changed")
    assert model.score(None)["over_limit"] == ["exec_count", "burst_rate"]
