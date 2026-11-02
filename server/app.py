import argparse
import atexit
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import threading
from datetime import timedelta

from flask import Flask, request, send_from_directory
from werkzeug.security import safe_join

from server import auth, config, db, mitre, response
from server.engine import Engine
from server.incidents import TRANSITIONS, IncidentManager
from server.ioc import IOC_TYPES, IOCStore
from server.pipeline import Pipeline


def _run_simulation(command):
    try:
        subprocess.run(command, timeout=config.SIM_TIMEOUT_SECONDS, capture_output=True)
    except Exception as error:
        print("simulation failed:", error, file=sys.stderr)


def _seed_admin():
    if db.count_users() > 0:
        return
    password = config.SEED_PASS or secrets.token_urlsafe(12)
    auth.create_user(config.SEED_USER, password, role="admin")
    if config.SEED_PASS:
        print(f"created admin user '{config.SEED_USER}' with the password from HIDS_ADMIN_PASS", file=sys.stderr)
    else:
        print(f"created admin user '{config.SEED_USER}' with password {password} "
              "(shown once, set HIDS_ADMIN_PASS to choose your own)", file=sys.stderr)


def _limit(default):
    value = request.args.get("limit", default, type=int)
    return max(1, min(value, config.MAX_LIMIT))


ENFORCEMENT_SETTINGS = ("enabled", "dry_run", "min_severity")

HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")


def _check_ioc(ioc_type, value):
    if ioc_type not in IOC_TYPES:
        return None, "type must be one of: " + ", ".join(IOC_TYPES)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 512:
        return None, "value is required (1 to 512 characters)"
    value = value.strip()
    wildcard = any(ch in value for ch in "*?[")
    if ioc_type == "ip" and not wildcard:
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            return None, "value is not an IP address (use * for a pattern, like 10.0.0.*)"
    if ioc_type == "path" and not value.startswith(("/", "*")):
        return None, "a path must start with / or with * for a pattern"
    if ioc_type == "hash":
        value = value.lower()
        if not HASH_RE.fullmatch(value):
            return None, "a hash must be md5, sha1 or sha256 in hex"
    return value, None


def _enforcement_state():
    actions = response.recent_actions(config.RESPONSE_LOG_MAX)
    counts = {decision: 0 for decision in response.DECISIONS}
    for item in actions:
        counts[item["decision"]] += 1
    return {
        "enabled": config.RESPONSE_ENABLED,
        "dry_run": config.RESPONSE_DRY_RUN,
        "min_severity": config.RESPONSE_MIN_SEVERITY,
        "severities": list(response.SEVERITY_ORDER),
        "grace_seconds": config.RESPONSE_GRACE_SECONDS,
        "min_safe_pid": config.MIN_SAFE_PID,
        "never_kill": sorted(config.NEVER_KILL),
        "note": "changes made here last until the server restarts, then it is off and in dry-run again",
        "counts": counts,
        "actions": actions[:_limit(100)],
    }


def _load_iocs():
    store = IOCStore()
    for row in db.list_iocs():
        try:
            store.add(row["type"], row["value"], row["description"] or "", ioc_id=row["id"])
        except ValueError as exc:
            print(f"ioc {row['id']} skipped: {exc}", file=sys.stderr)
    return store


def load_anomaly_model(alerting=False):
    try:
        from server.ml_anomaly import load_model
    except ImportError as exc:
        print(f"ml: not loaded: {exc}, install requirements-ml.txt", file=sys.stderr)
        return None
    return load_model(config.MODEL_DIR, alerting=bool(alerting))


def _ml_status(model, off_mode):
    if model is None:
        return {"ml_ready": False, "ml_has_autoencoder": False, "ml_alerting": False, "ml_mode": off_mode}
    return {
        "ml_ready": True,
        "ml_has_autoencoder": bool(getattr(model, "has_autoencoder", False)),
        "ml_alerting": bool(getattr(model, "alerting", False)),
        "ml_mode": str(getattr(model, "mode", "unknown")),
    }


def create_app(start_ingest=True, source=None, mode="sensor", anomaly_model=None, ml_off_mode="disabled"):
    if os.environ.get("HIDS_NO_INGEST"):
        start_ingest = False

    app = Flask(__name__)
    app.secret_key = config.load_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS),
    )

    db.init_db()
    _seed_admin()

    engine = Engine(anomaly_model=anomaly_model, rules_dir=config.RULES_DIR)
    for problem in engine.rule_errors:
        print(f"rule problem: {problem}", file=sys.stderr)
    incidents = IncidentManager(next_id=db.max_incident_id() + 1)
    pipeline = Pipeline(engine, incidents, _load_iocs())
    app.extensions["hids"] = {"engine": engine, "incidents": incidents, "pipeline": pipeline}

    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        user = auth.check_login(data.get("username"), data.get("password"))
        if user is None:
            return {"error": "invalid username or password"}, 401
        auth.do_login(user)
        return {"user": user["username"]}

    @app.route("/api/logout", methods=["POST"])
    def logout():
        auth.do_logout()
        return {"status": "logged out"}

    @app.route("/api/me")
    @auth.login_required
    def me():
        user = auth.current_user()
        return {"user": user["username"], "role": user["role"], "kind": user["kind"]}

    @app.route("/api/health")
    def health():
        counts = db.counts()
        with engine.lock:
            counts["processes"] = len(engine.processes)
        counts["anomalies"] = pipeline.stats["ml_flagged"]
        return {"status": "ok", "sensor_ready": pipeline.sensor_live(),
                **_ml_status(anomaly_model, ml_off_mode), "counts": counts}

    @app.route("/api/events")
    @auth.login_required
    def events():
        pid = request.args.get("pid", type=int)
        return {"events": db.recent_events(limit=_limit(100), pid=pid)}

    @app.route("/api/processes")
    @auth.login_required
    def processes():
        return {"processes": engine.process_rows(limit=_limit(100))}

    @app.route("/api/alerts")
    @auth.login_required
    def alerts():
        return {"alerts": db.recent_alerts(limit=300)}

    @app.route("/api/anomaly")
    @auth.login_required
    def anomaly():
        scores = engine.recent_anomaly_scores(limit=300)
        status = _ml_status(anomaly_model, ml_off_mode)
        return {
            "ml_ready": status["ml_ready"],
            "ml_alerting": status["ml_alerting"],
            "latest": scores[0] if scores else None,
            "scores": scores,
            "anomaly_count": sum(1 for s in scores if s["is_anomaly"]),
            "ae_threshold": getattr(anomaly_model, "ae_threshold", None),
        }

    @app.route("/api/sim/<name>", methods=["POST"])
    @auth.require_role("analyst")
    def sim(name):
        command = config.SIM_WHITELIST.get(name)
        if command is None:
            return {"error": "unknown simulation"}, 400
        thread = threading.Thread(target=_run_simulation, args=(command,), daemon=True)
        thread.start()
        return {
            "started": name,
            "note": f"running in the background, stops after {config.SIM_TIMEOUT_SECONDS} seconds at most",
        }, 202

    @app.route("/api/rules")
    @auth.login_required
    def rules():
        return engine.rules_info()

    @app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
    @auth.require_role("analyst")
    def toggle_rule(rule_id):
        with engine.lock:
            current = next((r for r in engine.rules if r.id == rule_id), None)
            if current is None:
                return {"error": "unknown rule"}, 404
            row = engine.set_rule_enabled(rule_id, not current.enabled)
        return {"id": row["id"], "enabled": row["enabled"]}

    @app.route("/api/incidents")
    @auth.login_required
    def incidents_list():
        return {"incidents": db.list_incidents()}

    @app.route("/api/incidents/<int:incident_id>")
    @auth.login_required
    def incident_detail(incident_id):
        incident = db.get_incident(incident_id)
        if incident is None:
            return {"error": "unknown incident"}, 404
        return incident

    @app.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
    @auth.require_role("analyst")
    def incident_status(incident_id):
        data = request.get_json(silent=True) or {}
        new_status = data.get("status")
        note = data.get("note") if isinstance(data.get("note"), str) else ""
        if new_status not in TRANSITIONS:
            return {"error": "status must be one of: " + ", ".join(TRANSITIONS)}, 400
        current = db.get_incident(incident_id)
        if current is None:
            return {"error": "unknown incident"}, 404
        if current["status"] != new_status and new_status not in TRANSITIONS[current["status"]]:
            return {"error": f"cannot move incident {incident_id} from '{current['status']}' to '{new_status}'"}, 409
        who = auth.current_user()["username"]
        with engine.lock:
            live = incidents.get(incident_id)
            if live is not None and live.status != new_status:
                live.set_status(new_status, who, note)
        db.set_incident_status(incident_id, new_status, who, note[:500])
        return db.get_incident(incident_id)

    @app.route("/api/evaluation")
    @auth.login_required
    def evaluation():
        numbers = db.evaluation_numbers()
        status = _ml_status(anomaly_model, ml_off_mode)
        numbers["anomaly_scores"] = pipeline.stats["ml_scored"]
        numbers["anomalies_flagged"] = pipeline.stats["ml_flagged"]
        numbers["ml_ready"] = status["ml_ready"]
        numbers["ml_alerting"] = status["ml_alerting"]
        return numbers

    @app.route("/api/mitre")
    @auth.login_required
    def mitre_coverage():
        return {"techniques": mitre.coverage(db.technique_counts())}

    @app.route("/api/apikeys")
    @auth.require_role("admin")
    def apikeys_list():
        return {"apikeys": db.list_api_keys()}

    @app.route("/api/apikeys", methods=["POST"])
    @auth.require_role("admin")
    def apikeys_create():
        data = request.get_json(silent=True) or {}
        name = data.get("name")
        role = data.get("role", "viewer")
        if not isinstance(name, str) or not name.strip() or len(name) > 64:
            return {"error": "name is required (1 to 64 characters)"}, 400
        if role not in auth.ROLES:
            return {"error": "role must be one of: " + ", ".join(auth.ROLES)}, 400
        token, key_id = auth.create_api_key(name.strip(), role)
        return {
            "id": key_id,
            "name": name.strip(),
            "role": role,
            "key": token,
            "note": "Copy this key now. It is shown only once and cannot be shown again.",
        }, 201

    @app.route("/api/apikeys/<int:key_id>", methods=["DELETE"])
    @auth.require_role("admin")
    def apikeys_delete(key_id):
        if not db.delete_api_key(key_id):
            return {"error": "unknown api key"}, 404
        return {"deleted": key_id}

    @app.route("/api/iocs")
    @auth.login_required
    def iocs_list():
        return {
            "iocs": db.list_iocs(),
            "types": list(IOC_TYPES),
            "note": "an indicator enriches alerts that rules raise after it was added, it does not raise an alert on its own",
        }

    @app.route("/api/iocs", methods=["POST"])
    @auth.require_role("analyst")
    def iocs_add():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        ioc_type = data.get("type")
        value, problem = _check_ioc(ioc_type, data.get("value"))
        if problem:
            return {"error": problem}, 400
        description = data.get("description") or ""
        if not isinstance(description, str) or len(description) > 200:
            return {"error": "description must be text of at most 200 characters"}, 400
        if any(row["type"] == ioc_type and row["value"] == value for row in db.list_iocs()):
            return {"error": "that indicator already exists"}, 409
        who = auth.current_user()["username"]
        ioc_id = db.insert_ioc(ioc_type, value, description.strip(), who)
        with engine.lock:
            pipeline.iocs.add(ioc_type, value, description.strip(), ioc_id=ioc_id)
        return {"id": ioc_id, "type": ioc_type, "value": value,
                "description": description.strip(), "added_by": who}, 201

    @app.route("/api/iocs/<int:ioc_id>", methods=["DELETE"])
    @auth.require_role("analyst")
    def iocs_delete(ioc_id):
        if not db.delete_ioc(ioc_id):
            return {"error": "unknown indicator"}, 404
        with engine.lock:
            pipeline.iocs.remove(ioc_id)
        return {"deleted": ioc_id}

    @app.route("/api/enforcement")
    @auth.login_required
    def enforcement():
        return _enforcement_state()

    @app.route("/api/enforcement", methods=["POST"])
    @auth.require_role("admin")
    def enforcement_settings():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not data:
            return {"error": "send at least one of: " + ", ".join(ENFORCEMENT_SETTINGS)}, 400
        unknown = sorted(set(data) - set(ENFORCEMENT_SETTINGS))
        if unknown:
            return {"error": "unknown setting: " + ", ".join(unknown)}, 400
        for key in ("enabled", "dry_run"):
            if key in data and not isinstance(data[key], bool):
                return {"error": key + " must be true or false"}, 400
        if "min_severity" in data and data["min_severity"] not in response.SEVERITY_ORDER:
            return {"error": "min_severity must be one of: " + ", ".join(response.SEVERITY_ORDER)}, 400
        if "enabled" in data:
            config.RESPONSE_ENABLED = data["enabled"]
        if "dry_run" in data:
            config.RESPONSE_DRY_RUN = data["dry_run"]
        if "min_severity" in data:
            config.RESPONSE_MIN_SEVERITY = data["min_severity"]
        changes = ", ".join(f"{key}={data[key]}" for key in sorted(data))
        print(f"enforcement: {auth.current_user()['username']} set {changes}", file=sys.stderr)
        return _enforcement_state()

    @app.route("/api/enforcement/action", methods=["POST"])
    @auth.require_role("analyst")
    def enforcement_action():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        pid = data.get("pid")
        comm = data.get("comm")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return {"error": "pid must be a positive whole number"}, 400
        if comm is not None and (not isinstance(comm, str) or len(comm) > 64):
            return {"error": "comm must be text of at most 64 characters"}, 400
        return response.manual_request(pid, comm, auth.current_user()["username"])

    @app.route("/api/enforcement/clear", methods=["POST"])
    @auth.require_role("admin")
    def enforcement_clear():
        cleared = response.clear_actions()
        print(f"enforcement: {auth.current_user()['username']} cleared {cleared} log entries", file=sys.stderr)
        return {"cleared": cleared}

    if config.CONSOLE_DIST.is_dir():
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def console(path):
            if path.startswith("api/"):
                return {"error": "not found"}, 404
            target = safe_join(str(config.CONSOLE_DIST), path) if path else None
            if target and os.path.isfile(target):
                return send_from_directory(config.CONSOLE_DIST, path)
            return send_from_directory(config.CONSOLE_DIST, "index.html")

    if start_ingest and source is not None:
        pipeline.start(mode, source)

    return app


def build_app(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m server.app",
        description="eBPF-HIDS backend. Pipe the loader into it, or replay a captured file.",
    )
    parser.add_argument("--replay", metavar="FILE", help="read events from a JSON lines file instead of stdin")
    parser.add_argument("--no-ingest", action="store_true", help="serve the API only, read no events")
    parser.add_argument("--no-ml", action="store_true", help="do not load the anomaly model")
    parser.add_argument("--ml-alerting", action="store_true",
                        help="let the anomaly model raise ML-ANOM alerts (off by default, the score is a gauge)")
    args = parser.parse_args(argv)

    if args.no_ingest:
        source, mode = None, None
    elif args.replay:
        source, mode = args.replay, "replay"
    elif not sys.stdin.isatty():
        source, mode = sys.stdin, "sensor"
    else:
        source, mode = None, None
        print("no events: stdin is a terminal. Pipe the loader in, or use --replay FILE", file=sys.stderr)

    if args.no_ml:
        model, off_mode = None, "disabled"
    else:
        model, off_mode = load_anomaly_model(alerting=args.ml_alerting), "not loaded"

    return create_app(start_ingest=source is not None, source=source, mode=mode,
                      anomaly_model=model, ml_off_mode=off_mode)


def main(argv=None):
    app = build_app(argv)
    atexit.register(app.extensions["hids"]["pipeline"].stop)
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
