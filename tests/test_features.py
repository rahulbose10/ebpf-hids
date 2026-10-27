from server.features import MAX_TRACK, ProcessState, split_addr


def ev(ts, typ, detail, uid=1000, comm="bash"):
    return {"ts": ts, "pid": 1, "ppid": 0, "uid": uid, "comm": comm, "type": typ, "detail": detail}


def test_exec_count_increments():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    p.update(ev(1.0, "EXEC", "/bin/bash"))
    assert p.exec_count == 1


def test_files_written_is_a_set():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    p.update(ev(1.0, "OPEN", "/tmp/a"))
    p.update(ev(2.0, "OPEN", "/tmp/a"))
    assert p.file_write_count == 2
    assert len(p.files_written) == 1


def test_bounded_memory_caps_at_256():
    p = ProcessState(pid=1, ppid=0, comm="bash", uid=1000)
    for i in range(300):
        p.update(ev(float(i), "CONNECT", f"1.2.3.{i}:80"))
    assert p.connect_count == 300
    assert len(p.dst_set) == MAX_TRACK
    assert len(p.event_times) == MAX_TRACK


def test_sticky_root_flag_stays_true():
    p = ProcessState(pid=1, ppid=0, comm="sudo", uid=1000)
    p.update(ev(1.0, "SETUID", "old_uid=1000 new_uid=0"))
    p.update(ev(2.0, "OPEN", "/tmp/x", uid=1000))
    assert p.ran_as_root is True


def test_any_event_as_uid_0_sets_root_flag():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    p.update(ev(1.0, "OPEN", "/tmp/x", uid=0))
    p.update(ev(2.0, "OPEN", "/tmp/y", uid=1000))
    assert p.ran_as_root is True


def test_empty_setuid_detail_does_not_crash():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    p.update(ev(1.0, "SETUID", ""))
    assert p.setuid_count == 1
    assert p.ran_as_root is False


def test_exec_sets_exe_and_comm_from_the_path():
    p = ProcessState(pid=1, ppid=0, comm="python3", uid=1000)
    p.update(ev(1.0, "EXEC", "/usr/bin/a-very-long-program-name", comm="python3"))
    assert p.exe == "/usr/bin/a-very-long-program-name"
    assert p.exe_name == "a-very-long-program-name"
    assert p.comm == "a-very-long-pro"


def test_exe_name_falls_back_to_comm():
    p = ProcessState(pid=1, ppid=0, comm="rsyslogd", uid=104)
    assert p.exe_name == "rsyslogd"


def test_destruction_times_keep_the_newest_not_the_oldest():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    for i in range(MAX_TRACK + 10):
        p.update(ev(float(i), "UNLINK", f"/tmp/{i}"))
    assert p.destruction_times[-1] == float(MAX_TRACK + 9)
    assert p.destruction_count == MAX_TRACK + 10


def test_mprotect_parses_the_sensor_prot_string():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    p.update(ev(1.0, "MPROTECT", "addr=0x7f00 prot=r-x suppressed=3"))
    p.update(ev(2.0, "MPROTECT", "addr=0x7f00 prot=rw- suppressed=0"))
    assert p.mprotect_exec_count == 1


def test_dns_connects_do_not_count_as_network_activity():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    p.update(ev(1.0, "CONNECT", "127.0.0.53:53"))
    assert p.connect_count == 1
    assert p.net_connect_count == 0
    p.update(ev(2.0, "CONNECT", "[2001:db8:0:0:0:0:0:1]:443"))
    assert p.net_connect_count == 1


def test_split_addr_handles_ipv4_and_ipv6():
    assert split_addr("5.6.7.8:4444") == ("5.6.7.8", 4444)
    assert split_addr("[2001:db8:0:0:0:0:0:1]:4444") == ("2001:db8:0:0:0:0:0:1", 4444)
    assert split_addr("") == ("", None)


def test_lifetime_and_process_dict_keys():
    p = ProcessState(pid=1, ppid=0, comm="x", uid=1000)
    p.update(ev(10.0, "EXEC", "/bin/x"))
    p.update(ev(12.5, "OPEN", "/tmp/x"))
    row = p.to_dict(depth=2)
    assert row["lifetime_s"] == 2.5
    assert set(row) == {
        "pid", "ppid", "comm", "uid", "exec_count", "connect_count", "file_write_count",
        "ptrace_count", "setuid_count", "destruction_count", "module_count", "bind_count",
        "mprotect_exec_count", "ran_as_root", "depth", "lifetime_s",
    }
