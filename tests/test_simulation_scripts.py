import importlib.util
import os
from pathlib import Path

from server import config

SCRIPTS = {name: Path(command[-1]) for name, command in config.SIM_WHITELIST.items()}


def load(name):
    spec = importlib.util.spec_from_file_location("sim_under_test_" + name.replace("-", "_"), SCRIPTS[name])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_whitelisted_script_exists():
    missing = [name for name, script in SCRIPTS.items() if not script.is_file()]
    assert missing == []


def test_every_attack_range_script_refuses_to_run_as_root(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    ran_anyway = []
    for name in sorted(set(SCRIPTS) - {"demo"}):
        code = load(name).main()
        said = capsys.readouterr().out
        if code != 1 or "refusing to run as root" not in said:
            ran_anyway.append(name)
    assert ran_anyway == []
