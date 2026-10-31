import argparse
import time
from pathlib import Path

import numpy as np

from scripts.gen_baseline import DEFAULT_N, HOUR_P, SEED, generate_baseline_matrix, run_process, spread
from server import ml_anomaly
from server.features import FEATURE_NAMES, N_FEATURES

TRAIN_FRACTION = 0.85
ATTACKS_PER_KIND = 20
SWEEP = (0.02, 0.05, 0.10)


def split_train_test(X, train_fraction=TRAIN_FRACTION, seed=42):
    order = np.random.default_rng(seed).permutation(len(X))
    cut = int(len(X) * train_fraction)
    return X[order[:cut]], X[order[cut:]]


def reverse_shell(rng, start):
    lifetime = rng.uniform(1.0, 30.0)
    dst = f"10.0.{rng.integers(0, 255)}.{rng.integers(1, 255)}:{rng.choice([4444, 1337, 9001])}"
    events = [(start, "EXEC", "/bin/sh")]
    for ts in spread(rng, rng.integers(3, 15), start, lifetime):
        events.append((ts, "CONNECT", dst))
    for ts in spread(rng, rng.integers(0, 5), start, lifetime):
        events.append((ts, "EXEC", str(rng.choice(["/usr/bin/id", "/usr/bin/whoami", "/usr/bin/uname"]))))
    return events


def privesc(rng, start):
    lifetime = rng.uniform(0.5, 10.0)
    events = [(start, "EXEC", "/tmp/.x/run"), (start + 0.05, "SETUID", "old_uid=1000 new_uid=0"),
              (start + 0.1, "EXEC", "/bin/sh")]
    targets = ["/etc/sudoers.d/x", "/root/.ssh/authorized_keys", "/etc/passwd", "/etc/cron.d/x"]
    for ts in spread(rng, rng.integers(1, 5), start + 0.1, lifetime):
        events.append((ts, "OPEN", str(rng.choice(targets))))
    return events


def mass_write(rng, start):
    lifetime = rng.uniform(1.0, 8.0)
    events = [(start, "EXEC", "/tmp/enc")]
    for k, ts in enumerate(spread(rng, rng.integers(60, 300), start, lifetime)):
        events.append((ts, "OPEN", f"/home/user/Documents/f{k}.locked"))
    return events


def injection(rng, start):
    lifetime = rng.uniform(0.2, 5.0)
    events = [(start, "EXEC", "/tmp/inj")]
    for ts in spread(rng, rng.integers(1, 6), start, lifetime):
        events.append((ts, "PTRACE", f"target_pid={rng.integers(300, 5000)}"))
    events.append((start + lifetime, "EXEC", "/bin/sh"))
    return events


def scanner(rng, start):
    lifetime = rng.uniform(0.5, 4.0)
    events = [(start, "EXEC", "/tmp/scan")]
    for ts in spread(rng, rng.integers(30, 200), start, lifetime):
        events.append((ts, "CONNECT", f"192.168.1.{rng.integers(1, 255)}:{rng.integers(1, 1024)}"))
    return events


ATTACKS = (reverse_shell, privesc, mass_write, injection, scanner)


def generate_attack_matrix(per_kind=ATTACKS_PER_KIND, seed=99):
    rng = np.random.default_rng(seed)
    rows = []
    for make in ATTACKS:
        for _ in range(per_kind):
            start = rng.uniform(100.0, 50000.0)
            hour = int(rng.choice(24, p=HOUR_P))
            rows.append(run_process(make(rng, start), 1000, int(rng.integers(1, 5)), hour))
    return np.asarray(rows, dtype=float)


def rates(rows):
    n = len(rows)
    return (
        sum(r["iforest_anomaly"] for r in rows) / n,
        sum(r["ae_anomaly"] for r in rows) / n,
        sum(r["is_anomaly"] for r in rows) / n,
    )


def split_counts(iforest):
    counts = np.zeros(N_FEATURES, dtype=int)
    subsample = getattr(iforest, "_max_features", N_FEATURES) != N_FEATURES
    for tree, features in zip(iforest.estimators_, iforest.estimators_features_):
        local = tree.tree_.feature
        used = local[local >= 0]
        np.add.at(counts, np.asarray(features)[used] if subsample else used, 1)
    return counts


def pct(x):
    return f"{x * 100:.2f}%"


def edge_probe(model, X_train):
    row = np.median(X_train, axis=0)
    row[FEATURE_NAMES.index("connect_count")] = 500
    return model.score(row)


def score_timing(model, row, rounds=200):
    start = time.perf_counter()
    for _ in range(rounds):
        model.score(row)
    fast = (time.perf_counter() - start) / rounds * 1000
    scaled = model.scaler.transform([row])
    start = time.perf_counter()
    for _ in range(20):
        model.iforest.decision_function(scaled)
    slow = (time.perf_counter() - start) / 20 * 1000
    return fast, slow


def train(X, contamination, use_ae, epochs, seed):
    X_train, X_holdout = split_train_test(X, seed=seed)
    scaler = ml_anomaly.fit_scaler(X_train)
    X_train_scaled = scaler.transform(X_train)
    iforest = ml_anomaly.train_iforest(X_train_scaled, contamination=contamination, seed=seed)
    ae, ae_threshold = None, None
    if use_ae:
        ae = ml_anomaly.train_autoencoder(X_train_scaled, epochs=epochs, seed=seed)
        if ae is not None:
            errors = ml_anomaly.reconstruction_errors(ml_anomaly.dense_layers(ae), X_train_scaled)
            ae_threshold = ml_anomaly.percentile_threshold(errors)
    return X_train, X_holdout, scaler, iforest, ae, ae_threshold


REPORT_FILE = "last_report.txt"
report = []


def say(line):
    print(line)
    report.append(line)


def check_file(model, path):
    from scripts.capture_baseline import replay_vectors

    X, stats = replay_vectors(path, min_events=1, per_pid_cap=None)
    if len(X) == 0:
        say(f"  check {Path(path).as_posix()}: no events scored")
        return
    rows = model.score_many(X)
    forest_rate, ae_rate, combined = rates(rows)
    z = np.abs((X - model.scaler.mean_) / model.scaler.scale_)
    worst = np.argsort(-z.max(axis=0))[:3]
    say(f"  replay {Path(path).as_posix()}: {stats['events']} events from {stats['processes']} processes scored through the engine")
    say(f"    flagged            forest {pct(forest_rate)} | autoencoder {pct(ae_rate)} | combined {pct(combined)}")
    say(f"    mean iforest score {np.mean([r['iforest_score'] for r in rows]):.4f}")
    say("    furthest from training (max z): "
          + ", ".join(f"{FEATURE_NAMES[i]} {z[:, i].max():.1f}" for i in worst))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m scripts.train_ml",
                                     description="Train the L3 models and print what was measured.")
    parser.add_argument("--baseline", help=".npy matrix from scripts.capture_baseline, instead of synthetic data")
    parser.add_argument("-n", type=int, default=DEFAULT_N, help="synthetic rows when no --baseline")
    parser.add_argument("--contamination", type=float, default=ml_anomaly.CONTAMINATION)
    parser.add_argument("--epochs", type=int, default=ml_anomaly.AE_EPOCHS)
    parser.add_argument("--no-autoencoder", action="store_true")
    parser.add_argument("--sweep", action="store_true", help="also measure holdout false positives at 0.02, 0.05, 0.10")
    parser.add_argument("--check", metavar="FILE", help="replay a sensor JSON lines file through the engine and score it")
    parser.add_argument("--model-dir", default=None)
    parser.add_argument("--seed", type=int, default=ml_anomaly.SEED)
    args = parser.parse_args(argv)

    if args.baseline:
        X = np.load(args.baseline)
        if X.ndim != 2 or X.shape[1] != N_FEATURES:
            parser.error(f"{args.baseline} has shape {X.shape}, expected (rows, {N_FEATURES})")
        source, source_note = "baseline", f"{Path(args.baseline).name}, captured on a real host"
    else:
        X = generate_baseline_matrix(args.n, SEED)
        source, source_note = "synthetic", f"scripts/gen_baseline.py, seed {SEED}"

    X_train, X_holdout, scaler, iforest, ae, ae_threshold = train(
        X, args.contamination, not args.no_autoencoder, args.epochs, args.seed)
    info = {"data_source": source, "source_note": source_note, "contamination": args.contamination,
            "trees": ml_anomaly.N_TREES, "train_samples": len(X_train), "holdout_samples": len(X_holdout),
            "ae_threshold": ae_threshold, "ae_percentile": ml_anomaly.AE_PERCENTILE,
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    model = ml_anomaly.AnomalyModel(scaler, iforest, info, ae)

    holdout = model.score_many(X_holdout)
    X_attack = generate_attack_matrix()
    attack = model.score_many(X_attack)
    h_forest, h_ae, h_comb = rates(holdout)
    a_forest, a_ae, a_comb = rates(attack)
    counts = split_counts(iforest)
    std = X_train.std(axis=0)
    dead = [FEATURE_NAMES[i] for i in range(N_FEATURES) if counts[i] == 0]
    info.update({"holdout_fp_forest": h_forest, "holdout_fp_combined": h_comb,
                 "synthetic_attack_detect_forest": a_forest, "synthetic_attack_detect_combined": a_comb,
                 "features_never_split": dead})
    saved = ml_anomaly.save_model(scaler, iforest, info, ae, args.model_dir)

    say("L3 training report")
    say(f"  data source        {source} ({len(X)} rows, {source_note})")
    say(f"  train / holdout    {len(X_train)} / {len(X_holdout)}")
    say(f"  contamination      {args.contamination}")
    if ae is not None:
        say(f"  autoencoder        yes, threshold {ae_threshold:.4f} (99th percentile of training error)")
    else:
        say("  autoencoder        no, forest only")
    say(f"  holdout normal     forest {pct(h_forest)} | autoencoder {pct(h_ae)} | combined {pct(h_comb)} flagged")
    say(f"  synthetic attacks  forest {pct(a_forest)} | autoencoder {pct(a_ae)} | combined {pct(a_comb)} flagged "
          f"({len(X_attack)} rows, {len(ATTACKS)} kinds)")
    say(f"  mean iforest score normal {np.mean([r['iforest_score'] for r in holdout]):.4f}"
          f" | attack {np.mean([r['iforest_score'] for r in attack]):.4f}")
    say(f"  lifetime_sec       training max {X_train[:, FEATURE_NAMES.index('lifetime_sec')].max():.2f} s")
    say("  features never split on: " + (", ".join(
        f"{name} (training std {std[FEATURE_NAMES.index(name)]:.3f})" for name in dead) or "none"))
    probe = edge_probe(model, X_train)
    verdict = "anomaly" if probe["iforest_anomaly"] else "normal"
    line = f"  edge probe         500 connects on a median process: forest {probe['iforest_score']:.3f} ({verdict})"
    if probe["recon_error"] is not None:
        line += f", autoencoder error {probe['recon_error']:.1f} vs threshold {model.ae_threshold:.2f}"
    say(line)
    fast, slow = score_timing(model, X_holdout[0])
    say(f"  score time         {fast:.2f} ms per event (sklearn decision_function on one row {slow:.2f} ms)")

    if args.sweep:
        say("  contamination sweep, forest only, same holdout:")
        X_train_scaled = scaler.transform(X_train)
        X_holdout_scaled = scaler.transform(X_holdout)
        for c in SWEEP:
            forest = ml_anomaly.train_iforest(X_train_scaled, contamination=c, seed=args.seed)
            fp = float(np.mean(forest.predict(X_holdout_scaled) == -1))
            say(f"    contamination {c:.2f} -> holdout false positives {pct(fp)}")

    if args.check:
        check_file(model, args.check)

    (saved / REPORT_FILE).write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"  saved              {saved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
