import os
import sys

import pytest

SERVER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server")
sys.path.insert(0, SERVER_DIR)

import config
import auth
from app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "test.db"))

    app = create_app(start_ingest=False)
    app.config["TESTING"] = True

    auth.create_user("tester", "testpass", role="admin")
    return app


@pytest.fixture
def client(app):
    return app.test_client()
