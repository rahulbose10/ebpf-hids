import numpy as np
from scripts.gen_baseline import generate_baseline_matrix
from server.ml_anomaly import fit_scaler, train_iforest
import random
from server.features import extract_features
import json


def split_train_test(X, train_fraction=0.85, seed=42):
    rng = np.random.default_rng(seed)
    n = len(X)
    indices = rng.permutation(n)

    split_point = int(n * train_fraction)
    train_idx = indices[:split_point]
    test_idx = indices[split_point:]

    return X[train_idx], X[test_idx]

def gen_synthetic_attack():
    return {
        "exec_count": 5,
        "connect_count": 50,
        "file_write_count": 20,
        "distinct_files_written": 15,
        "distinct_dst": 10,
        "lifetime_s": 2.0,
        "ran_as_root": True,
        "uid": 0,
        "ptrace_count": 3,
        "setuid_count": 2,
        "distinct_syscall_types": 25,
        "event_timestamps": [1.0, 1.05, 1.1, 1.15, 1.2, 1.25],
        "ts": 1_720_000_000.0,
    }


def run_training(n_samples=2500, contamination=0.02):
    print(f"Generating {n_samples} synthetic baseline processes...")
    X = generate_baseline_matrix(n_samples)

    X_train, X_holdout = split_train_test(X)
    print(f"Train shape: {X_train.shape}, Holdout shape: {X_holdout.shape}")

    scaler = fit_scaler(X_train)
    X_train_scaled = scaler.transform(X_train)

    model = train_iforest(X_train_scaled, contamination=contamination)

    X_holdout_scaled = scaler.transform(X_holdout)
    holdout_predictions = model.predict(X_holdout_scaled)
    holdout_scores = model.decision_function(X_holdout_scaled)

    false_positive_count = np.sum(holdout_predictions == -1)
    false_positive_rate = false_positive_count / len(holdout_predictions)

    print(f"Held-out normal data:")
    print(f"  False positive rate: {false_positive_rate:.2%}")
    print(f"  Mean score: {holdout_scores.mean():.4f}")
    attack_procs = [gen_synthetic_attack() for _ in range(100)]
    attack_features = [extract_features(proc, random.randint(0, 3)) for proc in attack_procs]
    X_attack = np.array(attack_features)
    X_attack_scaled = scaler.transform(X_attack)

    attack_predictions = model.predict(X_attack_scaled)
    attack_scores = model.decision_function(X_attack_scaled)

    detected_count = np.sum(attack_predictions == -1)
    detection_rate = detected_count / len(attack_predictions)

    print(f"Synthetic attack data:")
    print(f"  Detection rate: {detection_rate:.2%}")
    print(f"  Mean score: {attack_scores.mean():.4f}")

    threshold_info = {
        "n_features": X.shape[1],
        "data_source": "synthetic",
        "contamination": contamination,
        "false_positive_rate": false_positive_rate,
        "detection_rate": detection_rate,
        "train_samples": len(X_train),
        "holdout_samples": len(X_holdout),
    }

    with open("threshold.json", "w") as f:
        json.dump(threshold_info, f, indent=2)

    print("Saved threshold.json")

    return model, scaler


if __name__ == "__main__":
    run_training()
