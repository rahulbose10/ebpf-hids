import json

import pytest

from server import config

PROCESS_KEYS = {
    "pid", "ppid", "comm", "uid", "exec_count", "connect_count", "file_write_count",
    "ptrace_count", "setuid_count", "destruction_count", "module_count", "bind_count",
    "mprotect_exec_count", "ran_as_root", "depth", "lifetime_s",
}


def feed(app, family):
    pipeline = app.extensions["hids"]["pipeline"]
    ts = 500.0
    for pid, ppid, comm in family:
        ts += 0.01
        pipeline.feed_line(json.dumps({"ts": ts, "pid": pid, "ppid": ppid, "uid": 1000,
                                       "comm": comm, "type": "OPEN", "detail": f"/tmp/lineage/{pid}"}))
    pipeline.drain(flush=True)


@pytest.fixture
def family(client, app):
    feed(app, [(5000, 1, "bash"), (5001, 5000, "python3"), (5002, 5001, "sh"), (5003, 5000, "curl")])
    assert client.post("/api/login", json={"username": "tester", "password": "testpass"}).status_code == 200
    return client


def test_both_need_login(client):
    assert client.get("/api/lineage/1").status_code == 401
    assert client.get("/api/tree/1").status_code == 401


def test_lineage_walks_up_to_the_oldest_known_parent(family):
    body = family.get("/api/lineage/5002").get_json()
    assert body["pid"] == 5002
    assert [p["pid"] for p in body["chain"]] == [5002, 5001, 5000]
    assert [p["comm"] for p in body["chain"]] == ["sh", "python3", "bash"]
    assert all(set(p) == PROCESS_KEYS for p in body["chain"])


def test_tree_holds_every_descendant(family):
    body = family.get("/api/tree/5000").get_json()
    assert body["root"] == 5000
    assert body["nodes"] == 4
    assert body["truncated"] is False
    tree = body["tree"]
    assert tree["process"]["comm"] == "bash"
    assert [c["process"]["pid"] for c in tree["children"]] == [5001, 5003]
    assert [c["process"]["pid"] for c in tree["children"][0]["children"]] == [5002]
    assert tree["children"][1]["children"] == []


def test_unknown_pid_is_404(family):
    assert family.get("/api/lineage/999999").status_code == 404
    assert family.get("/api/tree/999999").status_code == 404


def test_a_parent_loop_from_pid_reuse_still_ends(client, app):
    feed(app, [(6000, 6001, "a"), (6001, 6000, "b")])
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    chain = client.get("/api/lineage/6000").get_json()["chain"]
    assert [p["pid"] for p in chain] == [6000, 6001]
    body = client.get("/api/tree/6000").get_json()
    assert body["nodes"] == 2
    assert body["tree"]["children"][0]["children"] == []


def test_a_huge_tree_is_cut_and_says_so(client, app, monkeypatch):
    monkeypatch.setattr(config, "TREE_MAX_NODES", 3)
    feed(app, [(7000, 1, "parent")] + [(7001 + i, 7000, "child") for i in range(5)])
    client.post("/api/login", json={"username": "tester", "password": "testpass"})
    body = client.get("/api/tree/7000").get_json()
    assert body["nodes"] == 3
    assert body["truncated"] is True
    assert len(body["tree"]["children"]) == 2
