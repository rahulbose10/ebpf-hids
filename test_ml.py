import random
import numpy as np
from scripts.gen_baseline import generate_baseline_matrix
from scripts.train_ml import split_train_test, gen_synthetic_attack
from server.features import extract_features
from server.ml_anomaly import fit_scaler, train_iforest, train_autoencoder, compute_ae_threshold, combined_verdict

X = generate_baseline_matrix(2500)
X_train, X_holdout = split_train_test(X)

scaler = fit_scaler(X_train)
X_train_scaled = scaler.transform(X_train)

iforest = train_iforest(X_train_scaled, contamination=0.02)
ae = train_autoencoder(X_train_scaled, epochs=50)
ae_threshold = compute_ae_threshold(ae, X_train_scaled, percentile=99)

attack_X = np.array([extract_features(gen_synthetic_attack(), random.randint(0, 3)) for _ in range(100)])

for name, data in [("Holdout normal", X_holdout), ("Synthetic attack", attack_X)]:
    results = combined_verdict(scaler, iforest, ae, ae_threshold, data)
    forest_rate = np.mean([r["iforest_score"] < 0 for r in results])
    ae_rate = np.mean([r["recon_error"] > ae_threshold for r in results])
    combined_rate = np.mean([r["is_anomaly"] for r in results])
    print(f"{name}: forest {forest_rate:.2%} | autoencoder {ae_rate:.2%} | combined (OR) {combined_rate:.2%}")

print("Sample result:", results[0])
