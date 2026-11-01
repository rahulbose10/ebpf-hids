import pytest

from server import auth, config
from server.app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(config, "SECRET_KEY_FILE", tmp_path / "secret.key")
    monkeypatch.setattr(config, "SEED_PASS", "seedpass")
    monkeypatch.delenv("HIDS_SECRET_KEY", raising=False)

    app = create_app(start_ingest=False)
    app.config["TESTING"] = True

    auth.create_user("tester", "testpass", role="admin")
    return app


@pytest.fixture
def client(app):
    return app.test_client()
