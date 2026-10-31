import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import json
from server.features import N_FEATURES
try:
    from tensorflow import keras
    from tensorflow.keras import layers
    HAS_TF = True
except ImportError:
    keras = None
    layers = None
    HAS_TF = False

def fit_scaler(X_train):
    X_train = np.array(X_train)
    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, "scaler.joblib")
    return scaler


def train_iforest(X_train_scaled, contamination=0.02):
    X_train_scaled = np.array(X_train_scaled)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(X_train_scaled)
    joblib.dump(model, "iforest.joblib")
    return model


def load():
    with open("threshold.json", "r") as f:
        threshold_info = json.load(f)

    saved_n_features = threshold_info["n_features"]

    if saved_n_features != N_FEATURES:
        raise ValueError(
            f"Feature count mismatch! Model was trained with "
            f"{saved_n_features} features, but current code has "
            f"{N_FEATURES} features. Retrain the model before using it."
        )

    scaler = joblib.load("scaler.joblib")
    model = joblib.load("iforest.joblib")

    return scaler, model


def build_autoencoder(n_features=16):
    model = keras.Sequential([
        layers.Input(shape=(n_features,)),
        layers.Dense(12, activation="relu"),
        layers.Dense(6, activation="relu"),
        layers.Dense(3, activation="relu"),
        layers.Dense(6, activation="relu"),
        layers.Dense(12, activation="relu"),
        layers.Dense(n_features, activation="linear"),
    ])

    model.compile(optimizer="adam", loss="mse")

    return model

def train_autoencoder(X_train_scaled, epochs=50, batch_size=32):
    n_features = X_train_scaled.shape[1]
    ae = build_autoencoder(n_features)

    ae.fit(
        X_train_scaled, X_train_scaled,
        epochs=epochs,
        batch_size=batch_size,
        shuffle=True,
        verbose=1,
    )

    ae.save("autoencoder.keras")

    return ae

def reconstruction_errors(ae, X_scaled):
    reconstructed = ae.predict(X_scaled, verbose=0)
    errors = np.mean((X_scaled - reconstructed) ** 2, axis=1)
    return errors


def compute_ae_threshold(ae, X_train_scaled, percentile=99):
    errors = reconstruction_errors(ae, X_train_scaled)
    threshold = float(np.percentile(errors, percentile))
    return threshold

def try_train_autoencoder(X_train_scaled, epochs=50):
    if not HAS_TF:
        print("TensorFlow not available - training Isolation Forest only.")
        return None
    try:
        return train_autoencoder(X_train_scaled, epochs=epochs)
    except Exception as e:
        print("Autoencoder training failed:", e)
        return None


def load_autoencoder(path="autoencoder.keras"):
    if not HAS_TF:
        print("TensorFlow not available - autoencoder not loaded.")
        return None
    try:
        return keras.models.load_model(path)
    except Exception as e:
        print("Could not load autoencoder:", e)
        return None

def combined_verdict(scaler, iforest, ae, ae_threshold, X_raw):
    X_scaled = scaler.transform(np.array(X_raw))

    iforest_scores = iforest.decision_function(X_scaled)
    iforest_flags = iforest_scores < 0

    if ae is not None and ae_threshold is not None:
        recon = reconstruction_errors(ae, X_scaled)
        ae_flags = recon > ae_threshold
    else:
        recon = [None] * len(X_scaled)
        ae_flags = np.zeros(len(X_scaled), dtype=bool)

    results = []
    for i in range(len(X_scaled)):
        results.append({
            "iforest_score": float(iforest_scores[i]),
            "recon_error": None if recon[i] is None else float(recon[i]),
            "is_anomaly": bool(iforest_flags[i] or ae_flags[i]),
        })

    return results
