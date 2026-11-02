from server import auth, db


def login(app, username, password):
    client = app.test_client()
    assert client.post("/api/login", json={"username": username, "password": password}).status_code == 200
    return client


def make_client(app, username, role):
    auth.create_user(username, "pass-" + username, role)
    return login(app, username, "pass-" + username)


def test_only_admins_reach_user_management(app):
    for role in ("viewer", "analyst"):
        client = make_client(app, role + "1", role)
        assert client.get("/api/users").status_code == 403
        assert client.post("/api/users", json={"username": "x", "password": "longenough", "role": "admin"}).status_code == 403
        assert client.delete("/api/users/tester").status_code == 403
        assert client.post("/api/users/tester/role", json={"role": "viewer"}).status_code == 403
    assert db.get_user("tester")["role"] == "admin"


def test_list_never_shows_password_material(app):
    admin = login(app, "tester", "testpass")
    body = admin.get("/api/users").get_json()
    assert body["roles"] == ["viewer", "analyst", "admin"]
    names = [u["username"] for u in body["users"]]
    assert "tester" in names
    for row in body["users"]:
        assert set(row) == {"username", "role", "created_at"}


def test_admin_creates_a_user_who_can_log_in(app):
    admin = login(app, "tester", "testpass")
    created = admin.post("/api/users", json={"username": "new.analyst", "password": "a-long-password", "role": "analyst"})
    assert created.status_code == 201
    assert created.get_json() == {"username": "new.analyst", "role": "analyst"}
    me = login(app, "new.analyst", "a-long-password").get("/api/me").get_json()
    assert me["role"] == "analyst"


def test_bad_new_users_are_refused(app):
    admin = login(app, "tester", "testpass")
    bad = [
        {},
        {"username": "", "password": "a-long-password"},
        {"username": "has space", "password": "a-long-password"},
        {"username": "key:bot", "password": "a-long-password"},
        {"username": "a" * 33, "password": "a-long-password"},
        {"username": "shortpass", "password": "short"},
        {"username": "nopass"},
        {"username": "badrole", "password": "a-long-password", "role": "root"},
    ]
    for payload in bad:
        assert admin.post("/api/users", json=payload).status_code == 400, f"{payload} was accepted"
    assert admin.post("/api/users", json={"username": "tester", "password": "a-long-password"}).status_code == 409


def test_role_change_applies_on_the_next_request(app):
    admin = login(app, "tester", "testpass")
    user = make_client(app, "rising", "viewer")
    assert user.post("/api/rules/ptrace_then_exec/toggle").status_code == 403
    assert admin.post("/api/users/rising/role", json={"role": "analyst"}).get_json() == {"username": "rising", "role": "analyst"}
    assert user.post("/api/rules/ptrace_then_exec/toggle").status_code == 200


def test_deleting_a_user_ends_their_session(app):
    admin = login(app, "tester", "testpass")
    user = make_client(app, "leaving", "viewer")
    assert user.get("/api/me").status_code == 200
    assert admin.delete("/api/users/leaving").get_json() == {"deleted": "leaving"}
    assert user.get("/api/me").status_code == 401
    assert admin.delete("/api/users/leaving").status_code == 404


def test_admin_cannot_delete_or_demote_themselves(app):
    admin = login(app, "tester", "testpass")
    assert admin.delete("/api/users/tester").status_code == 409
    assert admin.post("/api/users/tester/role", json={"role": "viewer"}).status_code == 409
    assert db.get_user("tester")["role"] == "admin"


def test_the_last_admin_cannot_be_removed_even_by_an_admin_key(app):
    admin = login(app, "tester", "testpass")
    for row in db.list_users():
        if row["role"] == "admin" and row["username"] != "tester":
            assert admin.delete("/api/users/" + row["username"]).status_code == 200
    assert [u["username"] for u in db.list_users() if u["role"] == "admin"] == ["tester"]

    key = admin.post("/api/apikeys", json={"name": "ops-bot", "role": "admin"}).get_json()["key"]
    bot = app.test_client()
    headers = {"X-API-Key": key}
    assert bot.delete("/api/users/tester", headers=headers).status_code == 409
    assert bot.post("/api/users/tester/role", json={"role": "viewer"}, headers=headers).status_code == 409
    assert db.get_user("tester")["role"] == "admin"

    assert db.delete_user("tester") is False
    assert db.set_user_role("tester", "viewer") is False
