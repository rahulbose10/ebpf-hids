import json
import sys
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from server.features import FEATURE_NAMES, N_FEATURES

MODEL_DIR = Path(__file__).resolve().parent / "ml"
SCALER_FILE = "scaler.joblib"
IFOREST_FILE = "iforest.joblib"
AE_FILE = "autoencoder.npz"
INFO_FILE = "threshold.json"
MODEL_FORMAT = 2

N_TREES = 200
CONTAMINATION = 0.01
AE_PERCENTILE = 99.5
AE_COUNT = 5
AE_EPOCHS = 150
AE_BATCH = 32
SEED = 42
LIMIT_MARGIN = 1.5

COL = {name: i for i, name in enumerate(FEATURE_NAMES)}
LOG_FEATURES = ("exec_count", "file_write_count", "file_write_rate", "connect_count", "connect_rate",
                "lifetime_sec", "burst_rate", "distinct_files_written", "distinct_dst", "ptrace_count",
                "setuid_count")
MODEL_SKIP = ("uid", "hour_of_day")
AGE_FEATURES = ("lifetime_sec", "file_write_count", "connect_count", "distinct_files_written", "distinct_dst")
LIMIT_FEATURES = ("exec_count", "ptrace_count", "setuid_count", "file_write_rate", "connect_rate",
                  "burst_rate", "dst_per_sec")
LOG_COLS = [COL[n] for n in LOG_FEATURES]
AGE_COLS = [COL[n] for n in AGE_FEATURES]


class ModelFileError(Exception):
    pass


def log(message):
    print(f"ml: {message}", file=sys.stderr)


def import_keras():
    try:
        from tensorflow import keras
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return keras, None


def as_rows(X):
    X = np.array(X, dtype=float)
    if X.ndim != 2 or X.shape[1] != N_FEATURES:
        raise ValueError(f"expected rows of {N_FEATURES} features, got shape {X.shape}")
    return X


def limit_values(X):
    life = np.maximum(X[:, COL["lifetime_sec"]], 1.0)
    derived = {"dst_per_sec": X[:, COL["distinct_dst"]] / life}
    return np.column_stack([derived[n] if n in derived else X[:, COL[n]] for n in LIMIT_FEATURES])


class FeaturePrep:
    def __init__(self, age_max, keep, limits):
        self.age_max = np.asarray(age_max, dtype=float)
        self.keep = np.asarray(keep, dtype=bool)
        self.limits = np.asarray(limits, dtype=float)

    @classmethod
    def fit(cls, X_train, margin=LIMIT_MARGIN):
        X = as_rows(X_train)
        age_max = X[:, AGE_COLS].max(axis=0)
        prepared = cls(age_max, np.ones(N_FEATURES, dtype=bool), []).prepare(X)
        keep = (prepared.std(axis=0) > 1e-9) & ~np.isin(FEATURE_NAMES, MODEL_SKIP)
        limits = margin * (limit_values(X).max(axis=0) + 1.0) - 1.0
        return cls(age_max, keep, limits)

    def prepare(self, X):
        X = as_rows(X)
        X[:, AGE_COLS] = np.minimum(X[:, AGE_COLS], self.age_max)
        X[:, LOG_COLS] = np.log1p(np.maximum(X[:, LOG_COLS], 0.0))
        return X

    def model_input(self, X):
        return self.prepare(X)[:, self.keep]

    def over_limits(self, X):
        return limit_values(as_rows(X)) > self.limits

    def kept_names(self):
        return [n for n, k in zip(FEATURE_NAMES, self.keep) if k]

    def ignored_names(self):
        return [n for n, k in zip(FEATURE_NAMES, self.keep) if not k]

    def to_info(self):
        return {"age_max": self.age_max.tolist(), "keep": self.keep.tolist(),
                "limits": dict(zip(LIMIT_FEATURES, self.limits.tolist()))}

    @classmethod
    def from_info(cls, info):
        limits = info["limits"]
        if list(limits) != list(LIMIT_FEATURES):
            raise ModelFileError("limit features in threshold.json differ from the code, retrain it")
        return cls(info["age_max"], info["keep"], list(limits.values()))


def train_iforest(Z, contamination=CONTAMINATION, n_estimators=N_TREES, seed=SEED):
    model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=seed)
    model.fit(np.asarray(Z, dtype=float))
    return model


def build_autoencoder(keras, n_inputs):
    model = keras.Sequential([
        keras.layers.Input(shape=(n_inputs,)),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(3, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(n_inputs, activation="linear"),
    ])
    model.compile(optimizer="adam", loss="mse")
    return model


def dense_layers(ae):
    layers = []
    for layer in ae.layers:
        weights = layer.get_weights()
        if len(weights) != 2:
            continue
        activation = layer.get_config().get("activation", "linear")
        if activation not in ("relu", "linear"):
            raise ValueError(f"unsupported activation {activation}")
        layers.append((np.asarray(weights[0], dtype=np.float32),
                       np.asarray(weights[1], dtype=np.float32),
                       activation == "relu"))
    return layers


def train_autoencoders(Z, count=AE_COUNT, epochs=AE_EPOCHS, batch_size=AE_BATCH, seed=SEED):
    keras, problem = import_keras()
    if keras is None:
        log(f"TensorFlow not available, training without the autoencoder ({problem})")
        return []
    Z = np.asarray(Z, dtype="float32")
    nets = []
    try:
        for k in range(count):
            keras.utils.set_random_seed(seed * 100 + k)
            ae = build_autoencoder(keras, Z.shape[1])
            ae.fit(Z, Z, epochs=epochs, batch_size=batch_size, shuffle=True, verbose=0)
            nets.append(dense_layers(ae))
    except Exception as exc:
        log(f"autoencoder training failed, continuing without it ({type(exc).__name__}: {exc})")
        return []
    return nets


def reconstruct(layers, Z):
    out = np.asarray(Z, dtype=np.float32)
    for weights, bias, relu in layers:
        out = out @ weights + bias
        if relu:
            out = np.maximum(out, 0.0)
    return out


def reconstruction_errors(nets, Z):
    Z = np.asarray(Z, dtype=np.float32)
    return np.mean([np.mean((Z - reconstruct(layers, Z)) ** 2, axis=1) for layers in nets], axis=0)


def percentile_threshold(errors, percentile=AE_PERCENTILE):
    return float(np.percentile(errors, percentile))


def average_path_length(n):
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    out[n == 2] = 1.0
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    return out


class ForestArrays:
    def __init__(self, iforest):
        trees = iforest.estimators_
        n_features = iforest.n_features_in_
        subsample = getattr(iforest, "_max_features", n_features) != n_features
        size = max(t.tree_.node_count for t in trees)
        count = len(trees)
        self.left = np.full((count, size), -1, dtype=np.intp)
        self.right = np.full((count, size), -1, dtype=np.intp)
        self.feature = np.zeros((count, size), dtype=np.intp)
        self.threshold = np.zeros((count, size))
        self.leaf_length = np.zeros((count, size))
        for i, (est, features) in enumerate(zip(trees, iforest.estimators_features_)):
            tree = est.tree_
            n = tree.node_count
            local = np.clip(tree.feature, 0, None)
            self.left[i, :n] = tree.children_left
            self.right[i, :n] = tree.children_right
            self.feature[i, :n] = np.asarray(features)[local] if subsample else local
            self.threshold[i, :n] = tree.threshold
            depth = np.zeros(n)
            for node in range(n):
                if tree.children_left[node] != -1:
                    depth[tree.children_left[node]] = depth[node] + 1
                    depth[tree.children_right[node]] = depth[node] + 1
            self.leaf_length[i, :n] = depth + average_path_length(tree.n_node_samples)
        self.rows = np.arange(count)
        self.steps = max(t.tree_.max_depth for t in trees) + 1
        self.denominator = count * float(average_path_length([iforest.max_samples_])[0])

    def anomaly_score(self, x):
        x = np.asarray(x, dtype=np.float32)
        node = np.zeros(len(self.rows), dtype=np.intp)
        for _ in range(self.steps):
            left = self.left[self.rows, node]
            inner = left != -1
            if not inner.any():
                break
            go_left = x[self.feature[self.rows, node]] <= self.threshold[self.rows, node]
            step = np.where(go_left, left, self.right[self.rows, node])
            node = np.where(inner, step, node)
        return float(2.0 ** (-self.leaf_length[self.rows, node].sum() / self.denominator))


class AnomalyModel:
    def __init__(self, prep, scaler, iforest, info, nets=None, alerting=None):
        self.prep = prep
        self.scaler = scaler
        self.iforest = iforest
        self.info = dict(info)
        self.ae_threshold = self.info.get("ae_threshold") if nets else None
        self.nets = list(nets) if self.ae_threshold is not None else []
        self.has_autoencoder = bool(self.nets)
        self.forest = ForestArrays(iforest)
        self.data_source = self.info.get("data_source", "unknown")
        if alerting is None:
            alerting = self.data_source == "baseline"
        self.alerting = bool(alerting)
        parts = ["iforest"] + (["autoencoder"] if self.has_autoencoder else []) + ["limits"]
        source = {"baseline": "real host baseline"}.get(self.data_source, f"{self.data_source} baseline")
        self.mode = f"{'+'.join(parts)}, {source}"

    def model_input(self, X_raw):
        return self.scaler.transform(self.prep.model_input(X_raw))

    def score_many(self, X_raw):
        X = as_rows(X_raw)
        Z = self.model_input(X)
        if len(Z) == 1:
            paper = np.array([self.forest.anomaly_score(Z[0])])
        else:
            paper = -self.iforest.score_samples(Z)
        forest = -paper - self.iforest.offset_
        recon = reconstruction_errors(self.nets, Z) if self.has_autoencoder else None
        over = self.prep.over_limits(X)

        rows = []
        for i in range(len(Z)):
            forest_flag = bool(forest[i] < 0)
            ae_flag = bool(recon is not None and recon[i] > self.ae_threshold)
            limit_flag = bool(over[i].any())
            rows.append({
                "iforest_score": float(forest[i]),
                "recon_error": None if recon is None else float(recon[i]),
                "is_anomaly": forest_flag or ae_flag or limit_flag,
                "iforest_anomaly": forest_flag,
                "ae_anomaly": ae_flag,
                "limit_anomaly": limit_flag,
                "over_limit": [n for n, hit in zip(LIMIT_FEATURES, over[i]) if hit],
                "confidence": round(float(paper[i]), 4),
            })
        return rows

    def score(self, vec):
        return self.score_many([vec])[0]


def fit(X_train, info, contamination=CONTAMINATION, n_estimators=N_TREES, autoencoders=AE_COUNT,
        epochs=AE_EPOCHS, percentile=AE_PERCENTILE, seed=SEED):
    prep = FeaturePrep.fit(X_train)
    scaler = StandardScaler().fit(prep.model_input(X_train))
    Z = scaler.transform(prep.model_input(X_train))
    iforest = train_iforest(Z, contamination, n_estimators, seed)
    nets = train_autoencoders(Z, autoencoders, epochs, seed=seed) if autoencoders else []
    info = dict(info)
    info.update({"contamination": contamination, "trees": n_estimators,
                 "autoencoders": len(nets), "ae_epochs": epochs if nets else None,
                 "ae_percentile": percentile if nets else None,
                 "ae_threshold": percentile_threshold(reconstruction_errors(nets, Z), percentile) if nets else None})
    return AnomalyModel(prep, scaler, iforest, info, nets)


def save_nets(nets, path):
    arrays = {}
    for k, layers in enumerate(nets):
        for j, (weights, bias, relu) in enumerate(layers):
            arrays[f"n{k}_w{j}"] = weights
            arrays[f"n{k}_b{j}"] = bias
        arrays[f"n{k}_relu"] = np.array([relu for _, _, relu in layers])
    np.savez(path, **arrays)


def load_nets(path):
    nets = []
    with np.load(path) as data:
        k = 0
        while f"n{k}_relu" in data:
            relu = data[f"n{k}_relu"]
            nets.append([(data[f"n{k}_w{j}"], data[f"n{k}_b{j}"], bool(relu[j])) for j in range(len(relu))])
            k += 1
    return nets


def save_model(model, model_dir=None):
    model_dir = Path(model_dir or MODEL_DIR)
    model_dir.mkdir(parents=True, exist_ok=True)
    info = dict(model.info)
    info.update({"format": MODEL_FORMAT, "n_features": N_FEATURES, "feature_names": list(FEATURE_NAMES),
                 "has_autoencoder": model.has_autoencoder, "sklearn_version": sklearn.__version__,
                 "prep": model.prep.to_info()})
    joblib.dump(model.scaler, model_dir / SCALER_FILE)
    joblib.dump(model.iforest, model_dir / IFOREST_FILE)
    ae_path = model_dir / AE_FILE
    if model.has_autoencoder:
        save_nets(model.nets, ae_path)
    elif ae_path.exists():
        ae_path.unlink()
    (model_dir / INFO_FILE).write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return model_dir


def read_info(model_dir=None):
    path = Path(model_dir or MODEL_DIR) / INFO_FILE
    if not path.is_file():
        raise ModelFileError(f"{path} not found, run python -m scripts.train_ml first")
    info = json.loads(path.read_text(encoding="utf-8"))
    if info.get("format") != MODEL_FORMAT:
        raise ModelFileError("model was saved by an older version of ml_anomaly.py, retrain it")
    if info.get("n_features") != N_FEATURES:
        raise ModelFileError(
            f"model was trained on {info.get('n_features')} features but the code has {N_FEATURES}, retrain it"
        )
    if info.get("feature_names") != list(FEATURE_NAMES):
        raise ModelFileError("feature order in threshold.json differs from FEATURE_NAMES, retrain it")
    return info


def load(model_dir=None, alerting=None):
    model_dir = Path(model_dir or MODEL_DIR)
    info = read_info(model_dir)
    if info.get("sklearn_version") not in (None, sklearn.__version__):
        log(f"model saved with scikit-learn {info['sklearn_version']}, running {sklearn.__version__}")
    prep = FeaturePrep.from_info(info["prep"])
    scaler = joblib.load(model_dir / SCALER_FILE)
    iforest = joblib.load(model_dir / IFOREST_FILE)
    if getattr(scaler, "n_features_in_", None) != int(prep.keep.sum()):
        raise ModelFileError(f"{SCALER_FILE} does not match the feature list in {INFO_FILE}, retrain it")
    nets = load_nets(model_dir / AE_FILE) if info.get("has_autoencoder") else []
    return AnomalyModel(prep, scaler, iforest, info, nets, alerting)


def load_model(model_dir=None, alerting=None):
    try:
        model = load(model_dir, alerting)
    except ModelFileError as exc:
        log(f"not loaded: {exc}")
        return None
    except Exception as exc:
        log(f"not loaded: {type(exc).__name__}: {exc}")
        return None
    log(f"loaded {model.mode}, alerting {'on' if model.alerting else 'off'}")
    return model
