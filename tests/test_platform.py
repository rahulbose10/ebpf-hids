import auth
import db

ANALYST_ENDPOINTS = [
    ("post", "/api/rules/ptrace_then_exec/toggle", None),
    ("post", "/api/sim/demo", None),
    ("post", "/api/incidents/1/status", {"status": "resolved"}),
]


def make_client(app, username, password, role):
    auth.create_user(username, password, role)
    client = app.test_client()
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return client


def call(client, method, path, body):
    if method == "post":
        return client.post(path, json=body)
    return client.get(path)


def create_key(admin_client, name="ci-bot", role="viewer"):
    response = admin_client.post("/api/apikeys", json={"name": name, "role": role})
    assert response.status_code == 201
    return response.get_json()


def test_viewer_gets_403_on_analyst_endpoints(app):
    viewer = make_client(app, "viewer1", "viewerpass", "viewer")
    for method, path, body in ANALYST_ENDPOINTS:
        response = call(viewer, method, path, body)
        assert response.status_code == 403, f"{path} let a viewer in"


def test_anonymous_gets_401_not_403(client):
    for method, path, body in ANALYST_ENDPOINTS:
        response = call(client, method, path, body)
        assert response.status_code == 401, f"{path} should answer 401 to a stranger"


def test_analyst_and_admin_pass_the_guard(app):
    analyst = make_client(app, "analyst1", "analystpass", "analyst")
    admin = make_client(app, "admin2", "adminpass", "admin")
    for person in (analyst, admin):
        first = person.post("/api/rules/ptrace_then_exec/toggle")
        assert first.status_code == 200
        second = person.post("/api/rules/ptrace_then_exec/toggle")
        assert second.status_code == 200


def test_viewer_can_still_read(app):
    viewer = make_client(app, "viewer2", "viewerpass", "viewer")
    for path in ("/api/events", "/api/alerts", "/api/rules", "/api/incidents"):
        assert viewer.get(path).status_code == 200, f"{path} blocked a viewer"


def test_key_is_shown_once_and_stored_hashed(app):
    admin = make_client(app, "keyadmin", "adminpass", "admin")
    created = create_key(admin)
    assert created["key"].startswith("hids.")

    listing = admin.get("/api/apikeys").get_json()["apikeys"]
    assert len(listing) == 1
    assert "key" not in listing[0]
    assert "key_hash" not in listing[0]

    secret = created["key"].split(".")[2]
    stored = db.get_api_key(created["id"])["key_hash"]
    assert "$" in stored
    assert secret not in stored


def test_key_works_as_a_credential(app):
    admin = make_client(app, "keyadmin", "adminpass", "admin")
    created = create_key(admin, "analyst-bot", "analyst")

    bot = app.test_client()
    response = bot.get("/api/me", headers={"X-API-Key": created["key"]})
    assert response.status_code == 200
    body = response.get_json()
    assert body["kind"] == "apikey"
    assert body["role"] == "analyst"


def test_key_role_is_enforced(app):
    admin = make_client(app, "keyadmin", "adminpass", "admin")
    viewer_key = create_key(admin, "viewer-bot", "viewer")["key"]
    analyst_key = create_key(admin, "analyst-bot", "analyst")["key"]

    bot = app.test_client()
    toggle = "/api/rules/ptrace_then_exec/toggle"
    assert bot.post(toggle, headers={"X-API-Key": viewer_key}).status_code == 403
    assert bot.post(toggle, headers={"X-API-Key": analyst_key}).status_code == 200
    assert bot.post(toggle, headers={"X-API-Key": analyst_key}).status_code == 200


def test_bad_and_deleted_keys_are_rejected(app):
    admin = make_client(app, "keyadmin", "adminpass", "admin")
    created = create_key(admin)

    bot = app.test_client()
    for bad in ("garbage", "hids.1.wrongsecret", "hids.999.abc", ""):
        response = bot.get("/api/me", headers={"X-API-Key": bad})
        assert response.status_code == 401, f"{bad!r} was accepted"

    assert bot.get("/api/me", headers={"X-API-Key": created["key"]}).status_code == 200
    assert admin.delete("/api/apikeys/" + str(created["id"])).status_code == 200
    assert bot.get("/api/me", headers={"X-API-Key": created["key"]}).status_code == 401


def test_only_admins_can_manage_keys(app):
    analyst = make_client(app, "analyst1", "analystpass", "analyst")
    assert analyst.get("/api/apikeys").status_code == 403
    assert analyst.post("/api/apikeys", json={"name": "x", "role": "viewer"}).status_code == 403
