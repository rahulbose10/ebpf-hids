import argparse
import json
import sys
import time
from collections import Counter, defaultdict

import numpy as np

from server.engine import Engine
from server.features import FEATURE_NAMES, N_FEATURES, extract_features

MIN_EVENTS = 2
PER_PID_CAP = 50


class Recorder:
    has_autoencoder = False
    alerting = False
    mode = "recorder"

    def __init__(self):
        self.last = None

    def score(self, vec):
        self.last = list(vec)
        return {"iforest_score": None, "recon_error": None, "is_anomaly": False}


def featurizer(boot_epoch):
    if boot_epoch is None:
        return extract_features

    def with_capture_hour(state, depth):
        hour = time.localtime(boot_epoch + state.last_ts).tm_hour
        return extract_features(state, depth, hour=hour)

    return with_capture_hour


def read_lines(path):
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                yield line


def replay_rows(path, boot_epoch=None):
    recorder = Recorder()
    engine = Engine(anomaly_model=recorder, featurize=featurizer(boot_epoch))
    rows, meta = [], []
    for line in read_lines(path):
        recorder.last = None
        try:
            evt = json.loads(line)
            engine.process_event(evt)
        except (ValueError, TypeError):
            continue
        if recorder.last is not None:
            rows.append(recorder.last)
            meta.append({"pid": int(evt["pid"]), "comm": str(evt["comm"]), "type": str(evt["type"])})
    return np.asarray(rows, dtype=float).reshape(-1, N_FEATURES), meta


def replay_vectors(path, boot_epoch=None, min_events=MIN_EVENTS, per_pid_cap=PER_PID_CAP):
    recorder = Recorder()
    engine = Engine(anomaly_model=recorder, featurize=featurizer(boot_epoch))
    per_pid = defaultdict(list)
    seen = Counter()
    stats = {"lines": 0, "events": 0, "bad_lines": 0}

    for line in read_lines(path):
        stats["lines"] += 1
        recorder.last = None
        try:
            evt = json.loads(line)
            engine.process_event(evt)
        except (ValueError, TypeError):
            stats["bad_lines"] += 1
            continue
        if recorder.last is None:
            continue
        stats["events"] += 1
        pid = int(evt["pid"])
        seen[pid] += 1
        per_pid[pid].append(recorder.last)

    rows = []
    kept = 0
    for pid, vectors in per_pid.items():
        if seen[pid] < min_events:
            continue
        kept += 1
        if per_pid_cap and len(vectors) > per_pid_cap:
            picks = np.linspace(0, len(vectors) - 1, per_pid_cap).round().astype(int)
            vectors = [vectors[i] for i in picks]
        rows.extend(vectors)

    stats["processes"] = len(per_pid)
    stats["processes_kept"] = kept
    stats["rows"] = len(rows)
    X = np.asarray(rows, dtype=float).reshape(-1, N_FEATURES)
    return X, stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m scripts.capture_baseline",
        description="Turn a captured sensor JSON lines file into a training matrix, through the same Engine path as live scoring.",
    )
    parser.add_argument("file", help="loader output saved as JSON lines")
    parser.add_argument("-o", "--out", default="server/ml/baseline.npy")
    parser.add_argument("--boot-epoch", type=float, default=None,
                        help="wall clock time of boot on the capture machine, so hour_of_day is the capture hour")
    parser.add_argument("--per-pid", type=int, default=PER_PID_CAP)
    args = parser.parse_args(argv)

    if args.boot_epoch is None:
        print("capture: no --boot-epoch, hour_of_day uses this machine's clock now", file=sys.stderr)

    X, stats = replay_vectors(args.file, boot_epoch=args.boot_epoch, per_pid_cap=args.per_pid)
    if len(X) == 0:
        print("capture: no usable rows, nothing written", file=sys.stderr)
        return 1
    np.save(args.out, X)
    life = X[:, FEATURE_NAMES.index("lifetime_sec")]
    print(
        "capture: {lines} lines, {events} events, {bad_lines} bad lines, {processes} processes, "
        "{processes_kept} with 2+ events, {rows} rows".format(**stats)
    )
    print(f"capture: lifetime_sec max {life.max():.1f} s, wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
