import sqlite3

import pytest

from server import config, db


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "pool.db"))
    db.init_db()
    return tmp_path


def test_a_closed_connection_is_handed_out_again(fresh_db):
    first = db.get_connection()
    first.close()
    second = db.get_connection()
    assert second is first
    second.close()


def test_uncommitted_work_is_rolled_back_when_returned(fresh_db):
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO events (ts, pid, ppid, uid, comm, type, detail) VALUES (1.0, 1, 0, 0, 'x', 'OPEN', '/tmp/x')"
    )
    assert conn.in_transaction
    conn.close()
    assert not conn.in_transaction
    assert db.counts()["events"] == 0


def test_a_new_database_path_never_gets_an_old_connection(fresh_db, monkeypatch):
    old = db.get_connection()
    old.close()
    monkeypatch.setattr(config, "DATABASE_PATH", str(fresh_db / "other.db"))
    new = db.get_connection()
    assert new is not old
    with pytest.raises(sqlite3.ProgrammingError):
        old.execute("SELECT 1")
    new.close()


def test_the_pool_keeps_at_most_pool_size_connections(fresh_db):
    conns = [db.get_connection() for _ in range(db.POOL_SIZE + 3)]
    for conn in conns:
        conn.close()
    assert len(db._idle) == db.POOL_SIZE


def test_closing_twice_does_not_break_the_pool(fresh_db):
    conn = db.get_connection()
    conn.close()
    conn.close()
    again = db.get_connection()
    assert again.execute("SELECT 1").fetchone()[0] == 1
    again.close()
