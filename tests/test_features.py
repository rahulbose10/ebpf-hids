import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from features import ProcessState


def test_exec_count_increments():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    p.update({"ts": 1.0, "type": "EXEC", "detail": "/bin/bash"})
    assert p.exec_count == 1


def test_files_written_is_a_set():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    p.update({"ts": 1.0, "type": "OPEN", "detail": "/tmp/a"})
    p.update({"ts": 2.0, "type": "OPEN", "detail": "/tmp/a"})
    assert p.file_write_count == 2
    assert len(p.files_written) == 1


def test_bounded_memory_caps_at_256():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    for i in range(300):
        p.update({"ts": float(i), "type": "CONNECT", "detail": f"1.2.3.{i}"})
    assert p.connect_count == 300
    assert len(p.dst_set) == 256


def test_sticky_root_flag_stays_true():
    p = ProcessState(pid=1, ppid=0, comm="sudo", uid=1000)
    p.update({"ts": 1.0, "type": "SETUID", "detail": "old_uid=1000 new_uid=0"})
    assert p.ran_as_root is True
    