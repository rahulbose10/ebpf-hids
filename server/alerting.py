import json
import re
import socket
import sys
import threading
import time
import urllib.request

from server import config, db

SEVERITY_ORDER = ("low", "medium", "high", "critical")
SYSLOG_LEVEL = {"critical": 2, "high": 3, "medium": 4, "low": 5}
SYSLOG_FACILITY_AUTH = 4
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def severity_at_least(severity, minimum):
    if severity not in SEVERITY_ORDER or minimum not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)


def payload(alert):
    return {
        "source": "ebpf-hids",
        "rule": alert.get("rule"),
        "technique": alert.get("technique"),
        "severity": alert.get("severity"),
        "confidence": alert.get("confidence"),
        "pid": alert.get("pid"),
        "comm": alert.get("comm"),
        "summary": alert.get("summary"),
        "ts": alert.get("ts"),
        "incident_id": alert.get("incident_id"),
    }


def _clean(value):
    return CONTROL_CHARS.sub(" ", "" if value is None else str(value))


def syslog_line(body):
    pri = SYSLOG_FACILITY_AUTH * 8 + SYSLOG_LEVEL.get(body.get("severity"), 5)
    fields = ("severity", "rule", "technique", "pid", "comm", "summary")
    text = " ".join(f"{name}={_clean(body.get(name))}" for name in fields)
    return f"<{pri}>ebpf-hids: {text}"


def post_webhook(url, body, timeout):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as reply:
        return f"HTTP {reply.status}"


def send_syslog(host, port, line):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(line.encode("utf-8", "replace")[:2048], (host, port))
    return f"udp {host}:{port}"


def run_in_background(job):
    threading.Thread(target=job, daemon=True, name="hids-alerting").start()


class Notifier:
    def __init__(self, webhook=post_webhook, syslog=send_syslog, run=run_in_background, clock=time.monotonic):
        self.webhook = webhook
        self.syslog = syslog
        self.run = run
        self.clock = clock
        self.last_sent = {}
        self.lock = threading.Lock()
        self.stats = {"sent": 0, "failed": 0, "throttled": 0, "below_severity": 0}

    def channels(self):
        chosen = []
        if config.ALERT_WEBHOOK_URL:
            chosen.append("webhook")
        if config.ALERT_SYSLOG_ENABLED:
            chosen.append("syslog")
        return chosen

    def notify(self, alert, alert_id=None):
        if not config.ALERT_ENABLED or not self.channels():
            return "off"
        if not severity_at_least(alert.get("severity"), config.ALERT_MIN_SEVERITY):
            with self.lock:
                self.stats["below_severity"] += 1
            return "below_severity"
        rule = alert.get("rule")
        now = self.clock()
        with self.lock:
            last = self.last_sent.get(rule)
            if last is not None and now - last < config.ALERT_THROTTLE_SECONDS:
                self.stats["throttled"] += 1
                return "throttled"
            self.last_sent[rule] = now
        body = payload(alert)
        self.run(lambda: self.deliver(body, alert_id))
        return "queued"

    def deliver(self, body, alert_id=None, channels=None):
        results = {}
        for channel in channels or self.channels():
            try:
                if channel == "webhook":
                    outcome = self.webhook(config.ALERT_WEBHOOK_URL, body, config.ALERT_WEBHOOK_TIMEOUT)
                else:
                    outcome = self.syslog(config.ALERT_SYSLOG_HOST, config.ALERT_SYSLOG_PORT, syslog_line(body))
                status = "sent"
            except Exception as exc:
                outcome = f"{type(exc).__name__}: {exc}"
                status = "failed"
            with self.lock:
                self.stats[status] += 1
            try:
                db.insert_delivery(alert_id, channel, status, str(outcome)[:500])
            except Exception as exc:
                print(f"alerting: could not log a {channel} delivery: {type(exc).__name__}: {exc}", file=sys.stderr)
            results[channel] = {"status": status, "detail": str(outcome)}
        return results
