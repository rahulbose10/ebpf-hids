import argparse
import json
import sys

from server.engine import Engine

MAX_WARNINGS = 20


def run(stream, engine, out=sys.stdout, err=sys.stderr, echo_events=False):
    stats = {"lines": 0, "events": 0, "bad_lines": 0, "errors": 0, "alerts": 0}

    def warn(msg):
        if stats["bad_lines"] + stats["errors"] <= MAX_WARNINGS:
            print(f"ingest: {msg}", file=err)

    def handle_line(lineno, line):
        line = line.strip()
        if not line:
            return
        stats["lines"] += 1
        try:
            evt = json.loads(line)
            alerts = engine.process_event(evt)
        except ValueError as exc:
            stats["bad_lines"] += 1
            warn(f"line {lineno} skipped: {exc}")
            return
        except Exception as exc:
            stats["errors"] += 1
            warn(f"line {lineno} engine error: {type(exc).__name__}: {exc}")
            return

        stats["events"] += 1
        if echo_events:
            print(json.dumps({"event": evt}), file=out, flush=True)
        for alert in alerts:
            stats["alerts"] += 1
            print(json.dumps(alert), file=out, flush=True)

    try:
        for lineno, line in enumerate(stream, start=1):
            handle_line(lineno, line)
    except KeyboardInterrupt:
        print("ingest: stopped", file=err)
    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m server.ingest",
        description="Read sensor JSON lines (stdin or a file), run the L2 engine, print alerts as JSON lines.",
    )
    parser.add_argument("file", nargs="?", help="JSON lines file; reads stdin when omitted")
    parser.add_argument("--events", action="store_true", help="also print every parsed event")
    args = parser.parse_args(argv)

    engine = Engine(anomaly_model=None)
    for problem in engine.rule_errors:
        print(f"ingest: rule problem: {problem}", file=sys.stderr)
    print(f"ingest: {len(engine.rules)} rules loaded", file=sys.stderr)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as stream:
            stats = run(stream, engine, echo_events=args.events)
    else:
        stats = run(sys.stdin, engine, echo_events=args.events)

    print(
        "ingest: {events} events, {alerts} alerts, {bad_lines} bad lines, {errors} engine errors".format(**stats),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
