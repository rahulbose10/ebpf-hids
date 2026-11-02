import re
import sys
from pathlib import Path

from server import app as app_module
from server import auth, config

PAGE = config.BASE_DIR / "console" / "src" / "pages" / "AttackRange.jsx"
SIM_DIR = config.BASE_DIR / "server" / "simulations"


def analyst(app):
    auth.create_user("sim-analyst", "pass-sim-analyst", "analyst")
    client = app.test_client()
    assert client.post("/api/login", json={"username": "sim-analyst", "password": "pass-sim-analyst"}).status_code == 200
    return client


def test_every_attack_range_id_is_whitelisted_and_nothing_else():
    ids = set(re.findall(r'\bid:\s*"([a-z0-9-]+)"', PAGE.read_text(encoding="utf-8")))
    assert len(ids) == 8
    assert set(config.SIM_WHITELIST) - {"demo"} == ids


def test_each_entry_runs_python_on_its_own_script_in_the_simulations_folder():
    for name, command in config.SIM_WHITELIST.items():
        assert len(command) == 2, name
        assert command[0] == sys.executable, name
        script = Path(command[1])
        assert script.parent == SIM_DIR, name
        assert script.name == "sim_" + name.replace("-", "_") + ".py", name


def test_missing_script_is_503_not_202(app, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "SIM_WHITELIST", {"ghost": [sys.executable, str(tmp_path / "sim_ghost.py")]})
    reply = analyst(app).post("/api/sim/ghost")
    assert reply.status_code == 503
    assert "not on this server" in reply.get_json()["error"]


def test_unknown_name_is_400(app):
    assert analyst(app).post("/api/sim/not-a-sim").status_code == 400


def test_present_script_is_202_and_its_exit_code_is_logged(app, monkeypatch, tmp_path, capsys):
    script = tmp_path / "sim_probe.py"
    script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    command = [sys.executable, str(script)]
    monkeypatch.setattr(config, "SIM_WHITELIST", {"probe": command})
    monkeypatch.setattr(app_module.threading, "Thread", lambda target, args, daemon: type(
        "Now", (), {"start": lambda self: target(*args)})())

    reply = analyst(app).post("/api/sim/probe")
    assert reply.status_code == 202
    assert reply.get_json()["started"] == "probe"
    assert "simulation probe exited with code 3" in capsys.readouterr().err
