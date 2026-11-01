import heapq
import json
import os
import queue
import sys
import threading
import time

from server import config, db, response
from server.engine import normalise


class ReorderBuffer:
    def __init__(self, hold=None, max_events=None, clock=time.monotonic):
        self.hold = config.REORDER_HOLD_SECONDS if hold is None else hold
        self.max_events = config.REORDER_MAX_EVENTS if max_events is None else max_events
        self.clock = clock
        self.heap = []
        self.seq = 0
        self.last_seq = -1
        self.last_ts = None
        self.reordered = 0
        self.late = 0

    def __len__(self):
        return len(self.heap)

    def push(self, evt):
        heapq.heappush(self.heap, (evt["ts"], self.seq, self.clock(), evt))
        self.seq += 1

    def pop_ready(self, flush=False):
        ready = []
        now = self.clock()
        while self.heap:
            ts, seq, arrived, evt = self.heap[0]
            over_cap = len(self.heap) > self.max_events
            if not flush and not over_cap and now - arrived < self.hold:
                break
            heapq.heappop(self.heap)
            if seq < self.last_seq:
                self.reordered += 1
            self.last_seq = max(self.last_seq, seq)
            if self.last_ts is not None and ts < self.last_ts:
                self.late += 1
            else:
                self.last_ts = ts
            ready.append(evt)
        return ready


class Pipeline:
    def __init__(self, engine, incidents, iocs, own_pid=None):
        self.engine = engine
        self.incidents = incidents
        self.iocs = iocs
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self.buffer = ReorderBuffer()
        self.queue = queue.Queue(maxsize=config.INGEST_QUEUE_MAX)
        self.pending = []
        self.last_flush = time.monotonic()
        self.mode = None
        self.reader = None
        self.worker = None
        self.last_event_at = None
        self.last_score = None
        self.stats = {
            "lines": 0, "events": 0, "bad_lines": 0, "engine_errors": 0,
            "self_events": 0, "alerts": 0, "fanout_errors": 0,
            "ml_scored": 0, "ml_flagged": 0,
        }

    def start(self, mode, source):
        self.mode = mode
        self.reader = threading.Thread(target=self._read, args=(source,), daemon=True, name="hids-reader")
        self.worker = threading.Thread(target=self._work, daemon=True, name="hids-worker")
        self.reader.start()
        self.worker.start()

    def stop(self, timeout=2.0):
        if self.worker is None or not self.worker.is_alive():
            return
        try:
            self.queue.put(None, timeout=timeout)
        except queue.Full:
            return
        self.worker.join(timeout)

    def sensor_live(self):
        if self.mode != "sensor" or self.reader is None or not self.reader.is_alive():
            return False
        if self.last_event_at is None:
            return False
        return time.monotonic() - self.last_event_at < config.SENSOR_STALE_SECONDS

    def _read(self, source):
        try:
            if isinstance(source, (str, os.PathLike)):
                with open(source, "r", encoding="utf-8") as stream:
                    for line in stream:
                        self.queue.put(line)
            else:
                for line in source:
                    self.queue.put(line)
        except Exception as exc:
            self._warn(f"reader stopped: {type(exc).__name__}: {exc}")
        finally:
            self.queue.put(None)

    def _work(self):
        while True:
            try:
                line = self.queue.get(timeout=0.05)
            except queue.Empty:
                self.drain()
                continue
            if line is None:
                self.drain(flush=True)
                self._report()
                return
            self.feed_line(line)
            self.drain()

    def feed_line(self, line):
        line = line.strip()
        if not line:
            return
        self.stats["lines"] += 1
        try:
            evt = normalise(json.loads(line))
        except ValueError as exc:
            self.stats["bad_lines"] += 1
            self._warn(f"line {self.stats['lines']} skipped: {exc}")
            return
        if evt["pid"] == self.own_pid:
            self.stats["self_events"] += 1
            return
        self.last_event_at = time.monotonic()
        self.buffer.push(evt)

    def drain(self, flush=False):
        for evt in self.buffer.pop_ready(flush=flush):
            self._handle(evt)
        due = time.monotonic() - self.last_flush >= config.EVENT_FLUSH_SECONDS
        if self.pending and (flush or due or len(self.pending) >= config.EVENT_BATCH_SIZE):
            batch, self.pending = self.pending, []
            try:
                db.insert_events(batch)
            except Exception as exc:
                self._warn(f"could not store {len(batch)} events: {type(exc).__name__}: {exc}")
            self.last_flush = time.monotonic()

    def _handle(self, evt):
        self.pending.append(evt)
        try:
            alerts = self.engine.process_event(evt)
        except Exception as exc:
            self.stats["engine_errors"] += 1
            self._warn(f"engine error: {type(exc).__name__}: {exc}")
            return
        self.stats["events"] += 1
        self._count_score()
        for alert in alerts:
            self._fan_out(alert)

    def _count_score(self):
        scores = self.engine.anomaly_scores
        row = scores[-1] if scores else None
        if row is None or row is self.last_score:
            return
        self.last_score = row
        self.stats["ml_scored"] += 1
        if row["is_anomaly"]:
            self.stats["ml_flagged"] += 1

    def _fan_out(self, alert):
        with self.engine.lock:
            self._step("ioc", self.iocs.enrich, alert)
            incident = self._step("incidents", self.incidents.correlate, self.engine, alert)
            incident_row = incident.to_dict() if incident is not None else None
        self._step("response", response.respond, alert)
        try:
            db.insert_alert(
                alert["ts"], alert["rule"], alert["technique"], alert["severity"],
                alert["confidence"], alert["pid"], alert["comm"], alert["summary"],
                alert["detail"], alert.get("incident_id"),
            )
            if incident_row is not None:
                db.upsert_incident(incident_row)
        except Exception as exc:
            self.stats["fanout_errors"] += 1
            self._warn(f"could not store alert {alert.get('rule')}: {type(exc).__name__}: {exc}")
            return
        self.stats["alerts"] += 1

    def _step(self, name, func, *args):
        try:
            return func(*args)
        except Exception as exc:
            self.stats["fanout_errors"] += 1
            self._warn(f"{name} failed: {type(exc).__name__}: {exc}")
            return None

    def summary(self):
        s = dict(self.stats)
        s["reordered"] = self.buffer.reordered
        s["late"] = self.buffer.late
        return s

    def _report(self):
        s = self.summary()
        print(
            "ingest: {events} events, {alerts} alerts, {bad_lines} bad lines, {engine_errors} engine errors, "
            "{self_events} own events dropped, {reordered} reordered, {late} late, "
            "{fanout_errors} fan-out errors, {ml_scored} scored by ML, {ml_flagged} flagged".format(**s),
            file=sys.stderr,
        )

    def _warn(self, message):
        if self.stats["bad_lines"] + self.stats["engine_errors"] + self.stats["fanout_errors"] <= 20:
            print(f"ingest: {message}", file=sys.stderr)
