PROTECTED = [
    "/api/me",
    "/api/events",
    "/api/processes",
    "/api/alerts",
    "/api/anomaly",
    "/api/rules",
    "/api/incidents",
    "/api/evaluation",
    "/api/apikeys",
]
def login(client, username="tester", password="testpass"):
    return client.post("/api/login", json={"username": username, "password": password})


def test_health_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_protected_endpoints_reject_without_login(client):
    for path in PROTECTED:
        response = client.get(path)
        assert response.status_code == 401, f"{path} was not locked"


def test_protected_endpoints_open_after_login(client):
    assert login(client).status_code == 200
    for path in PROTECTED:
        response = client.get(path)
        assert response.status_code == 200, f"{path} did not open after login"


def test_wrong_password_is_rejected(client):
    response = login(client, password="wrong-password")
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid username or password"}


def test_unknown_user_gets_same_error_as_wrong_password(client):
    wrong_password = login(client, password="wrong-password")
    unknown_user = login(client, username="nobody-here", password="whatever")
    assert wrong_password.status_code == unknown_user.status_code
    assert wrong_password.get_json() == unknown_user.get_json()


def test_logout_locks_the_doors_again(client):
    login(client)
    assert client.get("/api/me").status_code == 200
    client.post("/api/logout")
    assert client.get("/api/me").status_code == 401
