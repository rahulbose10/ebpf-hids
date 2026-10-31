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
AE_FILE = "autoencoder.keras"
INFO_FILE = "threshold.json"

N_TREES = 200
CONTAMINATION = 0.02
AE_PERCENTILE = 99.0
AE_EPOCHS = 50
AE_BATCH = 32
SEED = 42


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


def fit_scaler(X_train):
    scaler = StandardScaler()
    scaler.fit(np.asarray(X_train, dtype=float))
    return scaler


def train_iforest(X_train_scaled, contamination=CONTAMINATION, n_estimators=N_TREES, seed=SEED):
    model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=seed)
    model.fit(np.asarray(X_train_scaled, dtype=float))
    return model


def build_autoencoder(keras, n_features=N_FEATURES):
    model = keras.Sequential([
        keras.layers.Input(shape=(n_features,)),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(3, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(n_features, activation="linear"),
    ])
    model.compile(optimizer="adam", loss="mse")
    return model


def train_autoencoder(X_train_scaled, epochs=AE_EPOCHS, batch_size=AE_BATCH, seed=SEED, verbose=0):
    keras, problem = import_keras()
    if keras is None:
        log(f"TensorFlow not available, training the Isolation Forest only ({problem})")
        return None
    try:
        keras.utils.set_random_seed(seed)
        X = np.asarray(X_train_scaled, dtype="float32")
        ae = build_autoencoder(keras, X.shape[1])
        ae.fit(X, X, epochs=epochs, batch_size=batch_size, shuffle=True, verbose=verbose)
    except Exception as exc:
        log(f"autoencoder training failed, continuing with the forest only ({type(exc).__name__}: {exc})")
        return None
    return ae


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


def reconstruct(layers, X_scaled):
    out = np.asarray(X_scaled, dtype=np.float32)
    for weights, bias, relu in layers:
        out = out @ weights + bias
        if relu:
            out = np.maximum(out, 0.0)
    return out


def reconstruction_errors(layers, X_scaled):
    X = np.asarray(X_scaled, dtype=np.float32)
    return np.mean((X - reconstruct(layers, X)) ** 2, axis=1)


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


def percentile_threshold(errors, percentile=AE_PERCENTILE):
    return float(np.percentile(errors, percentile))


class AnomalyModel:
    def __init__(self, scaler, iforest, info, autoencoder=None, alerting=None):
        self.scaler = scaler
        self.iforest = iforest
        self.info = dict(info)
        self.ae_threshold = self.info.get("ae_threshold") if autoencoder is not None else None
        self.autoencoder = autoencoder if self.ae_threshold is not None else None
        self.has_autoencoder = self.autoencoder is not None
        self.ae_layers = dense_layers(self.autoencoder) if self.has_autoencoder else None
        self.forest = ForestArrays(iforest)
        self.data_source = self.info.get("data_source", "unknown")
        if alerting is None:
            alerting = self.data_source == "baseline"
        self.alerting = bool(alerting)
        models = "iforest+autoencoder" if self.has_autoencoder else "iforest"
        self.mode = f"{models}, {self.data_source} baseline"

    def score_many(self, X_raw):
        X = np.asarray(X_raw, dtype=float)
        if X.ndim != 2 or X.shape[1] != N_FEATURES:
            raise ValueError(f"expected rows of {N_FEATURES} features, got shape {X.shape}")
        Xs = self.scaler.transform(X)
        if len(Xs) == 1:
            paper = np.array([self.forest.anomaly_score(Xs[0])])
        else:
            paper = -self.iforest.score_samples(Xs)
        forest = -paper - self.iforest.offset_
        recon = reconstruction_errors(self.ae_layers, Xs) if self.has_autoencoder else None

        rows = []
        for i in range(len(Xs)):
            forest_flag = bool(forest[i] < 0)
            ae_flag = bool(recon is not None and recon[i] > self.ae_threshold)
            rows.append({
                "iforest_score": float(forest[i]),
                "recon_error": None if recon is None else float(recon[i]),
                "is_anomaly": forest_flag or ae_flag,
                "iforest_anomaly": forest_flag,
                "ae_anomaly": ae_flag,
                "confidence": round(float(paper[i]), 4),
            })
        return rows

    def score(self, vec):
        return self.score_many([vec])[0]


def save_model(scaler, iforest, info, autoencoder=None, model_dir=None):
    model_dir = Path(model_dir or MODEL_DIR)
    model_dir.mkdir(parents=True, exist_ok=True)
    info = dict(info)
    info["n_features"] = N_FEATURES
    info["feature_names"] = list(FEATURE_NAMES)
    info["has_autoencoder"] = autoencoder is not None
    info["sklearn_version"] = sklearn.__version__

    joblib.dump(scaler, model_dir / SCALER_FILE)
    joblib.dump(iforest, model_dir / IFOREST_FILE)
    ae_path = model_dir / AE_FILE
    if autoencoder is not None:
        autoencoder.save(ae_path)
    elif ae_path.exists():
        ae_path.unlink()
    (model_dir / INFO_FILE).write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return model_dir


def read_info(model_dir=None):
    path = Path(model_dir or MODEL_DIR) / INFO_FILE
    if not path.is_file():
        raise ModelFileError(f"{path} not found, run python -m scripts.train_ml first")
    info = json.loads(path.read_text(encoding="utf-8"))
    if info.get("n_features") != N_FEATURES:
        raise ModelFileError(
            f"model was trained on {info.get('n_features')} features but the code has {N_FEATURES}, retrain it"
        )
    if info.get("feature_names") != list(FEATURE_NAMES):
        raise ModelFileError("feature order in threshold.json differs from FEATURE_NAMES, retrain it")
    return info


def load_autoencoder(path):
    keras, problem = import_keras()
    if keras is None:
        log(f"{path.name} is there but TensorFlow is not, scoring with the forest only ({problem})")
        return None
    try:
        return keras.models.load_model(path)
    except Exception as exc:
        log(f"could not load {path.name}, scoring with the forest only ({type(exc).__name__}: {exc})")
        return None


def load(model_dir=None, alerting=None):
    model_dir = Path(model_dir or MODEL_DIR)
    info = read_info(model_dir)
    if info.get("sklearn_version") not in (None, sklearn.__version__):
        log(f"model saved with scikit-learn {info['sklearn_version']}, running {sklearn.__version__}")
    scaler = joblib.load(model_dir / SCALER_FILE)
    iforest = joblib.load(model_dir / IFOREST_FILE)
    if getattr(scaler, "n_features_in_", N_FEATURES) != N_FEATURES:
        raise ModelFileError(f"{SCALER_FILE} expects {scaler.n_features_in_} features, retrain it")
    autoencoder = load_autoencoder(model_dir / AE_FILE) if info.get("has_autoencoder") else None
    return AnomalyModel(scaler, iforest, info, autoencoder, alerting)


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
