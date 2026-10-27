import pytest

from server.engine import Engine
from server.incidents import IncidentManager, find_root_pid


def ev(ts, pid, ppid, comm, typ, detail, uid=1000):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": uid, "comm": comm, "type": typ, "detail": detail}


def build_two_sessions():
    eng = Engine()
    eng.process_event(ev(1.0, 1, 0, "systemd", "OPEN", "/run/systemd/x", uid=0))
    eng.process_event(ev(2.0, 1500, 1, "systemd", "EXEC", "/usr/libexec/gnome-terminal-server"))
    eng.process_event(ev(3.0, 1600, 1500, "gnome-terminal-", "EXEC", "/bin/bash"))
    eng.process_event(ev(3.5, 1700, 1500, "gnome-terminal-", "EXEC", "/bin/bash"))
    return eng


def test_root_stops_at_the_session_shell_not_systemd():
    eng = build_two_sessions()
    eng.process_event(ev(4.0, 1601, 1600, "bash", "EXEC", "/usr/bin/python3"))
    eng.process_event(ev(4.1, 1602, 1601, "python3", "EXEC", "/bin/sh"))
    assert find_root_pid(eng, 1602) == 1600
    assert find_root_pid(eng, 1700) == 1700


def test_unknown_parent_makes_the_process_its_own_root():
    eng = Engine()
    eng.process_event(ev(1.0, 900, 899, "x", "EXEC", "/bin/x"))
    assert find_root_pid(eng, 900) == 900


def test_same_tree_one_incident_other_tree_another():
    eng = build_two_sessions()
    im = IncidentManager()
    for a in eng.process_event(ev(5.0, 1601, 1600, "bash", "MODULE", "evil.ko", uid=0)):
        im.correlate(eng, a)
    for a in eng.process_event(ev(6.0, 1602, 1600, "bash", "CHMOD", "/tmp/y mode=4755", uid=0)):
        im.correlate(eng, a)
    for a in eng.process_event(ev(8.0, 1702, 1700, "bash", "CHMOD", "/tmp/z mode=4755", uid=0)):
        im.correlate(eng, a)

    incidents = {i.root_pid: i for i in im.all_incidents()}
    assert set(incidents) == {1600, 1700}
    assert incidents[1600].alert_count == 2
    assert incidents[1600].severity == "critical"
    assert incidents[1700].severity == "high"
    assert all(a["incident_id"] == incidents[1600].id for a in incidents[1600].alerts)


def test_severity_is_the_max_not_the_average():
    eng = Engine()
    im = IncidentManager()
    alerts = []
    alerts += eng.process_event(ev(1.0, 3000, 1, "chmod", "CHMOD", "/etc/hosts mode=0666", uid=0))
    alerts += eng.process_event(ev(2.0, 3000, 1, "chmod", "CHMOD", "/etc/motd mode=0666", uid=0))
    alerts += eng.process_event(ev(3.0, 3000, 1, "insmod", "MODULE", "x.ko", uid=0))
    for a in alerts:
        im.correlate(eng, a)
    (incident,) = im.all_incidents()
    assert incident.severity == "critical"
    assert incident.to_dict()["alert_count"] == len(alerts)
    assert "alerts" not in incident.to_dict()
    assert len(incident.to_dict(include_alerts=True)["alerts"]) == len(alerts)


def test_status_workflow_records_actor_note_and_time():
    eng = Engine()
    im = IncidentManager()
    (alert,) = eng.process_event(ev(1.0, 4000, 1, "insmod", "MODULE", "x.ko", uid=0))
    inc = im.correlate(eng, alert)
    inc.set_status("investigating", "rahul", "looking at the module", when=100.0)
    inc.set_status("resolved", "rahul", "lab module, unloaded", when=200.0)
    assert inc.status == "resolved"
    assert [(e["from_status"], e["to_status"], e["actor"], e["ts"]) for e in inc.audit_log] == [
        ("open", "investigating", "rahul", 100.0),
        ("investigating", "resolved", "rahul", 200.0),
    ]


def test_invalid_status_and_invalid_transition_raise():
    eng = Engine()
    im = IncidentManager()
    (alert,) = eng.process_event(ev(1.0, 4100, 1, "insmod", "MODULE", "x.ko", uid=0))
    inc = im.correlate(eng, alert)
    with pytest.raises(ValueError):
        inc.set_status("banana", "rahul")
    with pytest.raises(ValueError):
        inc.set_status("open", "rahul")
    inc.set_status("false_positive", "rahul", "my own test")
    with pytest.raises(ValueError):
        inc.set_status("resolved", "rahul")
    with pytest.raises(ValueError):
        inc.set_status("open", "")
    assert len(inc.audit_log) == 1


def test_new_alert_after_resolve_opens_a_new_incident():
    eng = Engine(dedupe_window=0.0)
    im = IncidentManager(next_id=41)
    (a1,) = eng.process_event(ev(1.0, 4200, 1, "insmod", "MODULE", "x.ko", uid=0))
    first = im.correlate(eng, a1)
    first.set_status("resolved", "rahul")
    (a2,) = eng.process_event(ev(2.0, 4200, 1, "insmod", "MODULE", "y.ko", uid=0))
    second = im.correlate(eng, a2)
    assert (first.id, second.id) == (41, 42)
    assert second.status == "open"
