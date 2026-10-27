import pytest

from server import mitre
from server.engine import Engine
from server.ioc import IOCStore


def alert_for(typ, detail):
    return {"detail": {"event": {"type": typ, "detail": detail}, "tactic": None, "technique": "T1071"}}


def test_ipv4_wildcard_match():
    store = IOCStore()
    store.add("ip", "5.6.7.*", "lab c2 range")
    assert store.enrich(alert_for("CONNECT", "5.6.7.8:4444"))["detail"]["ioc"][0]["pattern"] == "5.6.7.*"
    assert "ioc" not in store.enrich(alert_for("CONNECT", "1.1.1.1:443"))["detail"]


def test_ipv6_address_is_split_correctly():
    store = IOCStore()
    store.add("ip", "2001:db8:*")
    assert store.match_event({"type": "CONNECT", "detail": "[2001:db8:0:0:0:0:0:1]:4444"})


def test_path_patterns_cover_rename_chmod_and_correlated():
    store = IOCStore()
    store.add("path", "/tmp/*.sh")
    assert store.match_event({"type": "RENAME", "detail": "/tmp/a -> /tmp/evil.sh"})
    assert store.match_event({"type": "CHMOD", "detail": "/tmp/evil.sh mode=4755"})
    assert store.match_event({"type": "CORRELATED", "detail": "dst=1.2.3.4:4444 exec=/tmp/x.sh"})
    assert not store.match_event({"type": "OPEN", "detail": "/home/u/x.sh"})


def test_matching_is_case_sensitive_on_every_os():
    store = IOCStore()
    store.add("path", "/tmp/*.sh")
    assert not store.match_event({"type": "OPEN", "detail": "/TMP/EVIL.SH"})


def test_new_indicator_works_without_restart_and_can_be_removed():
    store = IOCStore()
    evt = {"type": "CONNECT", "detail": "9.9.9.9:53"}
    assert store.match_event(evt) == []
    ioc = store.add("ip", "9.9.9.9")
    assert len(store.match_event(evt)) == 1
    assert store.remove(ioc["id"]) is True
    assert store.match_event(evt) == []


def test_load_rows_from_database_shape():
    store = IOCStore()
    store.load([{"id": 7, "type": "path", "pattern": "/dev/shm/*", "description": ""}])
    assert store.match_event({"type": "EXEC", "detail": "/dev/shm/x"})[0]["id"] == 7
    assert store.add("ip", "1.2.3.4")["id"] == 8


def test_bad_ioc_type_is_rejected():
    with pytest.raises(ValueError):
        IOCStore().add("domain", "evil.example")


def test_mitre_coverage_counts_and_ignores_ml_anom():
    eng = Engine()
    eng.process_event({"ts": 1.0, "pid": 1, "ppid": 0, "uid": 0, "comm": "insmod", "type": "MODULE", "detail": "x.ko"})
    eng.technique_counts["ML-ANOM"] += 3
    summary = mitre.summary(eng.technique_counts)
    assert summary["total_techniques"] == 9
    assert summary["covered_techniques"] == 1
    assert {r["technique"] for r in summary["rows"]} == set(mitre.TECHNIQUES)
