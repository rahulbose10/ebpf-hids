from server import auth, config, db
from server.app import create_app


def login(client, username, password):
    return client.post("/api/login", json={"username": username, "password": password})


def test_fresh_database_seeds_one_admin(client):
    assert login(client, "admin", "seedpass").status_code == 200
    assert client.get("/api/me").get_json()["role"] == "admin"


def test_seed_does_not_run_twice(app):
    before = db.count_users()
    create_app(start_ingest=False)
    assert db.count_users() == before


def test_secret_key_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "env.db"))
    monkeypatch.setattr(config, "SEED_PASS", "x")
    monkeypatch.setenv("HIDS_SECRET_KEY", "from-the-env")
    assert create_app(start_ingest=False).secret_key == "from-the-env"


def test_secret_key_file_is_created_once_and_reused(app):
    first = config.SECRET_KEY_FILE.read_text().strip()
    assert len(first) == 64
    assert create_app(start_ingest=False).secret_key == first


def test_unknown_user_still_pays_for_a_hash(client, monkeypatch):
    calls = []
    real = auth.verify_password

    def counting(password, stored_hash, salt):
        calls.append(password)
        return real(password, stored_hash, salt)

    monkeypatch.setattr(auth, "verify_password", counting)
    assert login(client, "nobody-here", "guess").status_code == 401
    assert calls == ["guess"]


def test_limit_has_a_floor_a_ceiling_and_survives_junk(client):
    for i in range(1005):
        db.insert_event(float(i), 5000 + i, 1, 1000, "bash", "OPEN", "/tmp/x")
    login(client, "tester", "testpass")

    def count(query):
        response = client.get("/api/events" + query)
        assert response.status_code == 200, query
        return len(response.get_json()["events"])

    assert count("?limit=-1") == 1
    assert count("?limit=0") == 1
    assert count("?limit=5000") == 1000
    assert count("?limit=abc") == 100
    assert count("") == 100


def test_events_come_back_in_arrival_order_not_kernel_time(client):
    db.insert_event(9000.0, 7001, 1, 0, "before-reboot", "EXEC", "/bin/a")
    db.insert_event(12.0, 7002, 1, 0, "after-reboot", "EXEC", "/bin/b")
    login(client, "tester", "testpass")
    events = client.get("/api/events?limit=2").get_json()["events"]
    assert [e["comm"] for e in events] == ["after-reboot", "before-reboot"]


def test_role_change_applies_to_a_live_session(app):
    auth.create_user("promoted", "pw", "viewer")
    client = app.test_client()
    login(client, "promoted", "pw")
    toggle = "/api/rules/ptrace_then_exec/toggle"
    assert client.post(toggle).status_code == 403
    db.set_user_role("promoted", "analyst")
    assert client.post(toggle).status_code == 200
    assert client.post(toggle).status_code == 200


def test_deleted_user_loses_a_live_session(app):
    auth.create_user("leaving", "pw", "admin")
    client = app.test_client()
    login(client, "leaving", "pw")
    assert client.get("/api/me").status_code == 200
    db.delete_user("leaving")
    assert client.get("/api/me").status_code == 401


def test_session_cookie_is_httponly_lax_and_expires(client):
    response = login(client, "tester", "testpass")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Expires=" in cookie
