import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from scripts.gen_baseline import DEFAULT_N, HOUR_P, SEED, generate_baseline_matrix, run_process, spread
from server import ml_anomaly
from server.features import FEATURE_NAMES, N_FEATURES

TRAIN_FRACTION = 0.85
ATTACKS_PER_KIND = 20
SWEEP = (0.01, 0.02, 0.05, 0.10)
REPORT_FILE = "last_report.txt"
DETECTORS = ("iforest_anomaly", "ae_anomaly", "limit_anomaly", "is_anomaly")


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
    rows, kinds = [], []
    for make in ATTACKS:
        for _ in range(per_kind):
            start = rng.uniform(100.0, 50000.0)
            hour = int(rng.choice(24, p=HOUR_P))
            rows.append(run_process(make(rng, start), 1000, int(rng.integers(1, 5)), hour))
            kinds.append(make.__name__)
    return np.asarray(rows, dtype=float), kinds


def rates(rows):
    n = len(rows)
    return [sum(r[k] for r in rows) / n for k in DETECTORS]


def pct(x):
    return f"{x * 100:.2f}%"


def rate_line(rows):
    forest, ae, limits, combined = rates(rows)
    return f"forest {pct(forest)} | autoencoder {pct(ae)} | limits {pct(limits)} | combined {pct(combined)}"


def by_kind(rows, kinds):
    return {k: [r for r, kind in zip(rows, kinds) if kind == k] for k in dict.fromkeys(kinds)}


def reasons(row):
    out = []
    if row["iforest_anomaly"]:
        out.append("forest")
    if row["ae_anomaly"]:
        out.append("autoencoder")
    out.extend(f"limit {name}" for name in row["over_limit"])
    return out


def split_counts(model):
    iforest = model.iforest
    n_inputs = iforest.n_features_in_
    counts = np.zeros(n_inputs, dtype=int)
    subsample = getattr(iforest, "_max_features", n_inputs) != n_inputs
    for tree, features in zip(iforest.estimators_, iforest.estimators_features_):
        local = tree.tree_.feature
        used = local[local >= 0]
        np.add.at(counts, np.asarray(features)[used] if subsample else used, 1)
    return dict(zip(model.prep.kept_names(), counts))


def edge_probe(model, X_train):
    row = np.median(X_train, axis=0)
    row[FEATURE_NAMES.index("connect_count")] = 500
    return model.score(row)


def score_timing(model, row, rounds=200):
    start = time.perf_counter()
    for _ in range(rounds):
        model.score(row)
    fast = (time.perf_counter() - start) / rounds * 1000
    Z = model.model_input([row])
    start = time.perf_counter()
    for _ in range(20):
        model.iforest.decision_function(Z)
    slow = (time.perf_counter() - start) / 20 * 1000
    return fast, slow


def train_and_score(X, args, seed, source, source_note):
    X_train, X_holdout = split_train_test(X, seed=seed)
    info = {"data_source": source, "source_note": source_note, "seed": seed,
            "train_samples": len(X_train), "holdout_samples": len(X_holdout),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    model = ml_anomaly.fit(X_train, info, contamination=args.contamination,
                           autoencoders=0 if args.no_autoencoder else args.autoencoders,
                           epochs=args.epochs, seed=seed)
    X_attack, kinds = generate_attack_matrix()
    return X_train, X_holdout, model, model.score_many(X_holdout), model.score_many(X_attack), kinds


report = []


def say(line):
    print(line)
    report.append(line)


def alert_count(model, path, boot_epoch=None):
    from scripts.capture_baseline import featurizer, read_lines
    from server.engine import Engine

    was = model.alerting
    model.alerting = True
    engine = Engine(anomaly_model=model, featurize=featurizer(boot_epoch))
    stamps = []
    for line in read_lines(path):
        try:
            evt = json.loads(line)
            engine.process_event(evt)
        except (ValueError, TypeError):
            continue
        stamps.append(float(evt["ts"]))
    model.alerting = was
    minutes = (max(stamps) - min(stamps)) / 60.0 if len(stamps) > 1 else 0.0
    return engine.ml_alert_count, minutes


def check_file(model, path, boot_epoch=None):
    from scripts.capture_baseline import replay_rows

    X, meta = replay_rows(path, boot_epoch)
    if len(X) == 0:
        say(f"  check {Path(path).as_posix()}: no events scored")
        return
    rows = model.score_many(X)
    say(f"  replay {Path(path).as_posix()}: {len(X)} events from {len({m['pid'] for m in meta})} processes "
        "scored through the engine")
    say(f"    flagged            {rate_line(rows)}")
    flagged = defaultdict(Counter)
    for row, m in zip(rows, meta):
        if row["is_anomaly"]:
            flagged[(m["comm"], m["pid"])].update(reasons(row))
    if flagged:
        say("    flagged processes:")
        for (comm, pid), why in sorted(flagged.items(), key=lambda kv: -sum(kv[1].values()))[:15]:
            say(f"      {comm} (pid {pid}): " + ", ".join(f"{w} x{c}" for w, c in why.items()))
    alerts, minutes = alert_count(model, path, boot_epoch)
    say(f"    ML alerts it would raise (engine dedupe, 60 s per process): {alerts} over {minutes:.1f} min of capture"
        + (f", {alerts / minutes * 60:.0f} per hour" if minutes >= 1 else ""))
    Z = np.abs(model.model_input(X))
    names = model.prep.kept_names()
    worst = np.argsort(-Z.max(axis=0))[:3]
    say("    furthest from training (max z): " + ", ".join(f"{names[i]} {Z[:, i].max():.1f}" for i in worst))


def repeat_runs(X, args, source, source_note):
    seeds = [args.seed + 1000 * k for k in range(1, args.repeat + 1)]
    holdout, attack, kinds_seen = [], [], {}
    for seed in seeds:
        _, _, _, h_rows, a_rows, kinds = train_and_score(X, args, seed, source, source_note)
        holdout.append(rates(h_rows)[3])
        attack.append(rates(a_rows)[3])
        for kind, rows in by_kind(a_rows, kinds).items():
            kinds_seen.setdefault(kind, []).append(rates(rows)[3])

    def spread_text(values):
        return f"mean {pct(np.mean(values))} (min {pct(min(values))}, max {pct(max(values))})"

    say(f"  repeated over {len(seeds)} more seeds (split, forest and autoencoders all reseeded), combined verdict:")
    say(f"    holdout normal     {spread_text(holdout)}")
    say(f"    synthetic attacks  {spread_text(attack)}")
    for kind, values in kinds_seen.items():
        say(f"      {kind:16s} {spread_text(values)}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m scripts.train_ml",
                                     description="Train the L3 models and print what was measured.")
    parser.add_argument("--baseline", help=".npy matrix from scripts.capture_baseline, instead of synthetic data")
    parser.add_argument("-n", type=int, default=DEFAULT_N, help="synthetic rows when no --baseline")
    parser.add_argument("--contamination", type=float, default=ml_anomaly.CONTAMINATION)
    parser.add_argument("--autoencoders", type=int, default=ml_anomaly.AE_COUNT)
    parser.add_argument("--epochs", type=int, default=ml_anomaly.AE_EPOCHS)
    parser.add_argument("--no-autoencoder", action="store_true")
    parser.add_argument("--sweep", action="store_true", help="also measure holdout false positives per contamination")
    parser.add_argument("--repeat", type=int, default=0, metavar="N",
                        help="retrain N more times with other seeds and report the spread")
    parser.add_argument("--check", metavar="FILE", help="replay a sensor JSON lines file through the engine and score it")
    parser.add_argument("--boot-epoch", type=float, default=None, help="boot time of the machine that captured --check")
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

    X_train, X_holdout, model, holdout, attack, kinds = train_and_score(X, args, args.seed, source, source_note)
    h = rates(holdout)
    a = rates(attack)
    counts = split_counts(model)
    dead = [name for name, c in counts.items() if c == 0]
    model.info.update({"holdout_fp_combined": h[3], "synthetic_attack_detect_combined": a[3],
                       "features_ignored": model.prep.ignored_names(), "features_never_split": dead})
    saved = ml_anomaly.save_model(model, args.model_dir)

    say("L3 training report")
    say(f"  data source        {source} ({len(X)} rows, {source_note})")
    say(f"  train / holdout    {len(X_train)} / {len(X_holdout)}")
    say(f"  contamination      {args.contamination}")
    if model.has_autoencoder:
        say(f"  autoencoder        {len(model.nets)} networks averaged, {args.epochs} epochs, threshold "
            f"{model.ae_threshold:.4f} ({ml_anomaly.AE_PERCENTILE}th percentile of training error)")
    else:
        say("  autoencoder        no, forest and limits only")
    ignored = model.prep.ignored_names()
    say("  ignored            " + (", ".join(ignored) + " (no spread in training, so the forest and autoencoder "
                                  "cannot learn them)" if ignored else "none"))
    say(f"  limits             {ml_anomaly.LIMIT_MARGIN} x past the baseline max: " + ", ".join(
        f"{name} > {value:.3g}" for name, value in zip(ml_anomaly.LIMIT_FEATURES, model.prep.limits)))
    say(f"  holdout normal     {rate_line(holdout)} flagged")
    say(f"  synthetic attacks  {rate_line(attack)} flagged ({len(attack)} rows, {len(ATTACKS)} kinds)")
    for kind, rows in by_kind(attack, kinds).items():
        say(f"    {kind:16s} {rate_line(rows)}")
    say(f"  mean iforest score normal {np.mean([r['iforest_score'] for r in holdout]):.4f}"
        f" | attack {np.mean([r['iforest_score'] for r in attack]):.4f}")
    say(f"  lifetime_sec       training max {X_train[:, FEATURE_NAMES.index('lifetime_sec')].max():.2f} s")
    say("  features never split on: " + (", ".join(dead) if dead else "none"))
    probe = edge_probe(model, X_train)
    line = (f"  edge probe         500 connects on a median process: forest {probe['iforest_score']:.3f} "
            f"({'anomaly' if probe['iforest_anomaly'] else 'normal'})")
    if probe["recon_error"] is not None:
        line += f", autoencoder error {probe['recon_error']:.2f} vs threshold {model.ae_threshold:.2f}"
    line += f", limits {', '.join(probe['over_limit']) or 'none'}"
    say(line)
    fast, slow = score_timing(model, X_holdout[0])
    say(f"  score time         {fast:.2f} ms per event (sklearn decision_function on one row {slow:.2f} ms)")

    if args.sweep:
        say("  contamination sweep, forest only, same holdout:")
        Z_train = model.model_input(X_train)
        Z_holdout = model.model_input(X_holdout)
        for c in SWEEP:
            forest = ml_anomaly.train_iforest(Z_train, contamination=c, seed=args.seed)
            fp = float(np.mean(forest.predict(Z_holdout) == -1))
            say(f"    contamination {c:.2f} -> holdout false positives {pct(fp)}")

    if args.repeat:
        repeat_runs(X, args, source, source_note)

    if args.check:
        check_file(model, args.check, args.boot_epoch)

    (saved / REPORT_FILE).write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"  saved              {saved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
