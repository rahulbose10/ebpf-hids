from server.engine import Engine
from server.features import (
    FEATURE_NAMES,
    MIN_LIFETIME,
    N_FEATURES,
    ProcessState,
    burst_rate,
    extract_features,
)

CONTRACT_ORDER = [
    "distinct_syscall_types", "exec_count", "exec_depth", "file_write_count",
    "file_write_rate", "connect_count", "connect_rate", "ran_as_root",
    "lifetime_sec", "burst_rate", "hour_of_day", "uid",
    "distinct_files_written", "distinct_dst", "ptrace_count", "setuid_count",
]


def ev(ts, typ, detail, pid=1, ppid=0, uid=1000):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": uid, "comm": "x", "type": typ, "detail": detail}


def state_from(events, uid=1000):
    state = ProcessState(pid=1, ppid=0, comm="x", uid=uid)
    for e in events:
        state.update(e)
    return state


def test_feature_names_match_the_frozen_contract():
    assert FEATURE_NAMES == CONTRACT_ORDER
    assert N_FEATURES == 16


def test_each_feature_lands_in_its_slot():
    state = state_from([
        ev(10.0, "EXEC", "/bin/sh"),
        ev(10.5, "OPEN", "/tmp/a"),
        ev(11.0, "OPEN", "/tmp/a"),
        ev(11.5, "CONNECT", "5.6.7.8:4444"),
        ev(12.0, "CONNECT", "9.9.9.9:443"),
        ev(13.0, "PTRACE", "target_pid=5"),
        ev(14.0, "SETUID", "old_uid=1000 new_uid=0"),
    ])
    vec = dict(zip(FEATURE_NAMES, extract_features(state, depth=3, hour=21)))
    assert vec["distinct_syscall_types"] == 5
    assert vec["exec_count"] == 1
    assert vec["exec_depth"] == 3
    assert vec["file_write_count"] == 2
    assert vec["file_write_rate"] == 2 / 4.0
    assert vec["connect_count"] == 2
    assert vec["connect_rate"] == 2 / 4.0
    assert vec["ran_as_root"] == 1.0
    assert vec["lifetime_sec"] == 4.0
    assert vec["burst_rate"] == 3
    assert vec["hour_of_day"] == 21
    assert vec["uid"] == 1000
    assert vec["distinct_files_written"] == 1
    assert vec["distinct_dst"] == 2
    assert vec["ptrace_count"] == 1
    assert vec["setuid_count"] == 1


def test_all_values_are_floats():
    vec = extract_features(state_from([ev(1.0, "EXEC", "/bin/ls")]), depth=0, hour=3)
    assert len(vec) == N_FEATURES
    assert all(isinstance(v, float) for v in vec)


def test_new_process_rate_uses_the_floor_not_a_million():
    vec = extract_features(state_from([ev(5.0, "CONNECT", "1.2.3.4:80")]), depth=0, hour=0)
    rate = vec[FEATURE_NAMES.index("connect_rate")]
    assert rate == 1 / MIN_LIFETIME
    assert rate < 100


def test_burst_rate_counts_the_busiest_second():
    assert burst_rate([]) == 0
    assert burst_rate([1.0]) == 1
    assert burst_rate([1.0, 1.2, 1.9, 2.05, 5.0]) == 3
    assert burst_rate([2.05, 1.0, 5.0, 1.9, 1.2]) == 3


def test_hour_defaults_to_the_local_clock():
    hour = extract_features(state_from([ev(1.0, "EXEC", "/bin/ls")]), depth=0)[FEATURE_NAMES.index("hour_of_day")]
    assert 0 <= hour <= 23


def test_kernel_ts_never_becomes_the_hour():
    early = extract_features(state_from([ev(5.0, "EXEC", "/bin/ls")]), depth=0, hour=14)
    late = extract_features(state_from([ev(80000.0, "EXEC", "/bin/ls")]), depth=0, hour=14)
    assert early[FEATURE_NAMES.index("hour_of_day")] == late[FEATURE_NAMES.index("hour_of_day")] == 14


class FakeModel:
    has_autoencoder = False
    mode = "fake"

    def __init__(self, alerting, flag=True):
        self.alerting = alerting
        self.flag = flag
        self.vectors = []

    def score(self, vec):
        self.vectors.append(vec)
        return {"iforest_score": -0.2 if self.flag else 0.2, "recon_error": None,
                "is_anomaly": self.flag, "confidence": 0.7}


def test_engine_hands_extract_features_the_engine_depth():
    model = FakeModel(alerting=False)
    engine = Engine(anomaly_model=model)
    engine.process_event(ev(1.0, "EXEC", "/bin/bash", pid=10, ppid=1))
    engine.process_event(ev(2.0, "EXEC", "/bin/sh", pid=11, ppid=10))
    assert len(model.vectors[-1]) == N_FEATURES
    assert model.vectors[-1][FEATURE_NAMES.index("exec_depth")] == 1


def test_gauge_only_model_scores_but_never_alerts():
    engine = Engine(anomaly_model=FakeModel(alerting=False))
    alerts = engine.process_event(ev(1.0, "OPEN", "/tmp/x"))
    assert [a for a in alerts if a["rule"] == "ml_anomaly"] == []
    assert engine.recent_anomaly_scores()[0]["is_anomaly"] is True
    assert engine.ml_alert_count == 0


def test_alerting_model_raises_ml_anom():
    engine = Engine(anomaly_model=FakeModel(alerting=True))
    alerts = engine.process_event(ev(1.0, "OPEN", "/tmp/x"))
    ml = [a for a in alerts if a["rule"] == "ml_anomaly"]
    assert len(ml) == 1
    assert ml[0]["technique"] == "ML-ANOM"
    assert ml[0]["confidence"] == 0.7


def test_score_row_has_the_api_contract_keys():
    engine = Engine(anomaly_model=FakeModel(alerting=False, flag=False))
    engine.process_event(ev(1.0, "OPEN", "/tmp/x"))
    row = engine.recent_anomaly_scores()[0]
    assert set(row) == {"pid", "comm", "ts", "iforest_score", "recon_error", "is_anomaly",
                        "iforest_anomaly", "ae_anomaly", "limit_anomaly", "over_limit"}
