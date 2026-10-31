import argparse

import numpy as np

from server.features import N_FEATURES, ProcessState, extract_features

DEFAULT_N = 2500
SEED = 7
MAX_LIFETIME = 4.4

CLI_TOOLS = ["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/git", "/usr/bin/cp",
             "/usr/bin/python3", "/usr/bin/vim", "/usr/bin/sed", "/usr/bin/tar", "/usr/bin/make"]
NET_TOOLS = ["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/ssh", "/usr/bin/apt", "/usr/bin/git"]
SERVERS = ["93.184.216.34:443", "140.82.112.3:443", "91.189.91.39:80", "151.101.1.69:443",
           "185.125.190.36:443", "142.250.72.14:443"]
DNS = "127.0.0.53:53"
HOUR_WEIGHTS = np.array([1, 1, 1, 1, 1, 1, 2, 4, 8, 10, 10, 10, 9, 10, 10, 10, 10, 9, 8, 8, 7, 6, 4, 2], dtype=float)
HOUR_P = HOUR_WEIGHTS / HOUR_WEIGHTS.sum()


def run_process(events, uid, depth, hour, pid=1000):
    state = ProcessState(pid=pid, ppid=1, comm="bash", uid=uid)
    for ts, etype, detail in sorted(events, key=lambda e: e[0]):
        state.update({"ts": ts, "pid": pid, "ppid": 1, "uid": uid, "comm": state.comm,
                      "type": etype, "detail": detail})
    return extract_features(state, depth, hour=hour)


def spread(rng, count, start, lifetime):
    return sorted(start + rng.uniform(0.0, lifetime, size=count))


def user_uid(rng):
    return 0 if rng.random() < 0.08 else 1000


def short_cli(rng, start):
    lifetime = rng.uniform(0.05, MAX_LIFETIME)
    events = [(start, "EXEC", str(rng.choice(CLI_TOOLS)))]
    files = [f"/home/user/work/file{n}.txt" for n in range(rng.integers(1, 4))]
    for ts in spread(rng, rng.integers(0, 4), start, lifetime):
        events.append((ts, "OPEN", str(rng.choice(files))))
    if rng.random() < 0.03:
        events.append((start + lifetime * 0.1, "SETUID", "old_uid=1000 new_uid=0"))
    events.append((start + lifetime, "OPEN", "/dev/null"))
    return events


def network_client(rng, start):
    lifetime = rng.uniform(0.5, MAX_LIFETIME)
    events = [(start, "EXEC", str(rng.choice(NET_TOOLS)))]
    servers = list(rng.choice(SERVERS, size=rng.integers(1, 4), replace=False))
    times = spread(rng, rng.integers(1, 6), start, lifetime)
    events.append((times[0], "CONNECT", DNS))
    for ts in times[1:]:
        events.append((ts, "CONNECT", str(rng.choice(servers))))
    if len(times) == 1:
        events.append((start + lifetime, "CONNECT", str(servers[0])))
    if rng.random() < 0.5:
        events.append((start + lifetime * 0.9, "OPEN", "/home/user/Downloads/page.html"))
    return events


def mixed(rng, start):
    lifetime = rng.uniform(0.2, MAX_LIFETIME)
    events = [(start, "EXEC", str(rng.choice(CLI_TOOLS + NET_TOOLS)))]
    for ts in spread(rng, rng.integers(0, 5), start, lifetime):
        events.append((ts, "OPEN", f"/tmp/build{rng.integers(0, 6)}.o"))
    for ts in spread(rng, rng.integers(0, 4), start, lifetime):
        events.append((ts, "CONNECT", str(rng.choice(SERVERS + [DNS]))))
    events.append((start + lifetime, "OPEN", "/home/user/.bash_history"))
    return events


ARCHETYPES = (short_cli, network_client, mixed)
ARCHETYPE_P = (0.45, 0.30, 0.25)


def generate_baseline_matrix(n=DEFAULT_N, seed=SEED):
    rng = np.random.default_rng(seed)
    rows = np.empty((n, N_FEATURES), dtype=float)
    for i in range(n):
        make = ARCHETYPES[rng.choice(len(ARCHETYPES), p=ARCHETYPE_P)]
        start = rng.uniform(100.0, 50000.0)
        hour = int(rng.choice(24, p=HOUR_P))
        rows[i] = run_process(make(rng, start), user_uid(rng), int(rng.integers(0, 4)), hour)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m scripts.gen_baseline",
                                     description="Write a synthetic normal matrix built through ProcessState.")
    parser.add_argument("-n", type=int, default=DEFAULT_N)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("-o", "--out", default="synthetic_baseline.npy")
    args = parser.parse_args(argv)
    X = generate_baseline_matrix(args.n, args.seed)
    np.save(args.out, X)
    print(f"wrote {args.out}: {X.shape[0]} rows, lifetime_sec max {X[:, 8].max():.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
