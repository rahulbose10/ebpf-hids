import subprocess
import threading

from flask import Flask, request

import auth
import config
import db
import rules_registry


def _start_ingest_thread():
    def worker():
        pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def _run_simulation(command):
    try:
        subprocess.run(command, timeout=config.SIM_TIMEOUT_SECONDS, capture_output=True)
    except Exception as error:
        print("simulation failed:", error)


def create_app(start_ingest=True):
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY

    db.init_db()


    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username")
        password = data.get("password")

        user = auth.check_login(username, password)
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
        return {
            "status": "ok",
            "sensor_ready": False,
            "ml_ready": False,
            "ml_has_autoencoder": False,
            "ml_alerting": False,
            "ml_mode": "disabled",
            "counts": db.counts()
        }


    @app.route("/api/events")
    @auth.login_required
    def events():
        limit = min(int(request.args.get("limit", 100)), 1000)
        pid = request.args.get("pid", type=int)
        return {"events": db.recent_events(limit=limit, pid=pid)}

    @app.route("/api/processes")
    @auth.login_required
    def processes():
        limit = min(int(request.args.get("limit", 100)), 1000)
        return {"processes": db.all_processes(limit=limit)}

    @app.route("/api/alerts")
    @auth.login_required
    def alerts():
        return {"alerts": db.recent_alerts(limit=300)}

    @app.route("/api/anomaly")
    @auth.login_required
    def anomaly():
        scores = db.recent_anomaly_scores(limit=300)
        return {
            "ml_ready": False,
            "ml_alerting": False,
            "latest": scores[0] if scores else None,
            "scores": scores,
            "anomaly_count": sum(1 for s in scores if s.get("is_anomaly"))
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
            "note": "running in the background, stops after " + str(config.SIM_TIMEOUT_SECONDS) + " seconds at most"
        }, 202


    @app.route("/api/rules")
    @auth.login_required
    def rules():
        return {"rules": rules_registry.list_rules(), "errors": []}

    @app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
    @auth.require_role("analyst")
    def toggle_rule(rule_id):
        rule = rules_registry.toggle_rule(rule_id)
        if rule is None:
            return {"error": "unknown rule"}, 404
        return {"id": rule["id"], "enabled": rule["enabled"]}


    @app.route("/api/incidents")
    @auth.login_required
    def incidents():
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

        if new_status not in config.INCIDENT_STATUSES:
            return {"error": "status must be one of: " + ", ".join(config.INCIDENT_STATUSES)}, 400

        who = auth.current_user()["username"]
        if not db.set_incident_status(incident_id, new_status, who):
            return {"error": "unknown incident"}, 404
        return db.get_incident(incident_id)


    @app.route("/api/evaluation")
    @auth.login_required
    def evaluation():
        numbers = db.evaluation_numbers()
        numbers["ml_ready"] = False
        numbers["ml_alerting"] = False
        return numbers


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
            "note": "Copy this key now. It is shown only once and cannot be shown again."
        }, 201

    @app.route("/api/apikeys/<int:key_id>", methods=["DELETE"])
    @auth.require_role("admin")
    def apikeys_delete(key_id):
        if not db.delete_api_key(key_id):
            return {"error": "unknown api key"}, 404
        return {"deleted": key_id}

    if start_ingest:
        _start_ingest_thread()

    return app


if __name__ == "__main__":
    app = create_app(start_ingest=True)
    app.run(debug=True, port=config.PORT)
