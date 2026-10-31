import random
import numpy as np
from server.features import extract_features


def gen_short_cli_process():
    lifetime = random.uniform(0.1, 4.4)
    return {
        "exec_count": random.randint(1, 2),
        "connect_count": 0,
        "file_write_count": random.randint(0, 3),
        "distinct_files_written": random.randint(0, 2),
        "distinct_dst": 0,
        "lifetime_s": lifetime,
        "ran_as_root": random.random() < 0.05,
        "uid": random.choice([0, 1000, 1001]),
        "ptrace_count": 0,
        "setuid_count": 0,
        "distinct_syscall_types": random.randint(3, 8),
        "event_timestamps": [],
        "ts": random.uniform(1_700_000_000, 1_750_000_000),
    }


def gen_network_client_process():
    lifetime = random.uniform(0.5, 4.4)
    return {
        "exec_count": random.randint(1, 3),
        "connect_count": random.randint(1, 5),
        "file_write_count": random.randint(0, 1),
        "distinct_files_written": random.randint(0, 1),
        "distinct_dst": random.randint(1, 3),
        "lifetime_s": lifetime,
        "ran_as_root": random.random() < 0.05,
        "uid": random.choice([0, 1000, 1001]),
        "ptrace_count": 0,
        "setuid_count": 0,
        "distinct_syscall_types": random.randint(5, 10),
        "event_timestamps": [],
        "ts": random.uniform(1_700_000_000, 1_750_000_000),
    }


def gen_mixed_process():
    if random.random() < 0.5:
        return gen_short_cli_process()
    else:
        return gen_network_client_process()


def generate_baseline_matrix(n=2500):
    rows = []
    for _ in range(n):
        proc = gen_mixed_process()
        depth = random.randint(0, 3)
        features = extract_features(proc, depth)
        rows.append(features)
    return np.array(rows)
