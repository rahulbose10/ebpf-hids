from server.engine import Engine


def ev(ts, pid, ppid, comm, typ, detail, uid=1000):
    return {"ts": ts, "pid": pid, "ppid": ppid, "uid": uid, "comm": comm, "type": typ, "detail": detail}


def fired(eng, events):
    for e in events:
        eng.process_event(e)
    return [a["rule"] for a in eng.alerts]


def test_ransomware_burst_positive():
    events = [ev(i * 0.1, 1040, 1, "enc", "RENAME", f"/home/u/f{i} -> /home/u/f{i}.locked") for i in range(30)]
    assert "ransomware_burst" in fired(Engine(), events)


def test_ransomware_burst_negative_slow_deletes():
    events = [ev(i * 10.0, 2040, 1, "cleanup", "UNLINK", f"/tmp/old{i}") for i in range(40)]
    assert "ransomware_burst" not in fired(Engine(), events)


def test_ransomware_burst_negative_firefox_measured_burst():
    events = [ev(400.0 + i * 0.003, 2041, 1, "firefox", "RENAME", f"/home/u/.mozilla/s{i}.tmp -> /home/u/.mozilla/s{i}") for i in range(8)]
    assert "ransomware_burst" not in fired(Engine(), events)


def test_log_tampering_positive():
    assert "log_tampering" in fired(Engine(), [ev(1.0, 1050, 1, "bash", "UNLINK", "/var/log/auth.log", uid=0)])


def test_log_tampering_negative_not_a_log_path():
    assert "log_tampering" not in fired(Engine(), [ev(1.0, 2050, 1, "app", "OPEN", "/home/user/notes.txt")])


def test_log_tampering_negative_rsyslog_thread():
    assert "log_tampering" not in fired(Engine(), [ev(1.0, 600, 1, "rs:main Q:Reg", "OPEN", "/var/log/syslog", uid=104)])


def test_persistence_autostart_positive():
    assert "persistence_autostart" in fired(Engine(), [ev(1.0, 1060, 1, "bash", "OPEN", "/etc/cron.d/evil", uid=0)])


def test_persistence_autostart_positive_atomic_rename_into_place():
    events = [ev(1.0, 1061, 1, "bash", "RENAME", "/tmp/x.service -> /etc/systemd/system/x.service", uid=0)]
    assert "persistence_autostart" in fired(Engine(), events)


def test_persistence_autostart_negative_systemd_runtime_files():
    events = [
        ev(1.0, 1, 0, "systemd", "OPEN", "/run/systemd/units/invocation:cron.service", uid=0),
        ev(2.0, 1, 0, "systemd", "OPEN", "/var/lib/systemd/timers/stamp-apt-daily.timer", uid=0),
        ev(3.0, 2060, 1, "cat", "OPEN", "/var/log/cron.log", uid=0),
    ]
    assert "persistence_autostart" not in fired(Engine(), events)


def test_credential_access_positive():
    assert "credential_access" in fired(Engine(), [ev(1.0, 1070, 1, "bash", "OPEN", "/etc/shadow", uid=0)])


def test_credential_access_negative_lookalike_paths():
    events = [
        ev(1.0, 2070, 1, "cat", "OPEN", "/etc/hostname"),
        ev(2.0, 2071, 1, "ss-local", "OPEN", "/tmp/shadowsocks.json"),
        ev(3.0, 2072, 1, "ssh-keygen", "OPEN", "/home/u/.ssh/id_ed25519"),
    ]
    assert "credential_access" not in fired(Engine(), events)


def test_suid_backdoor_positive_setuid_and_setgid():
    events = [
        ev(1.0, 1080, 1, "chmod", "CHMOD", "/tmp/x mode=4755", uid=0),
        ev(2.0, 1081, 1, "chmod", "CHMOD", "/tmp/y mode=2755", uid=0),
    ]
    assert fired(Engine(), events).count("suid_backdoor") == 2


def test_suid_backdoor_negative():
    events = [
        ev(1.0, 2080, 1, "chmod", "CHMOD", "/tmp/x mode=0755", uid=0),
        ev(2.0, 2081, 1, "chmod", "CHMOD", "/tmp mode=1777", uid=0),
    ]
    assert "suid_backdoor" not in fired(Engine(), events)


def test_world_writable_sensitive_positive():
    assert "world_writable_sensitive" in fired(Engine(), [ev(1.0, 1090, 1, "chmod", "CHMOD", "/etc/passwd mode=0666", uid=0)])


def test_world_writable_sensitive_negative():
    assert "world_writable_sensitive" not in fired(Engine(), [ev(1.0, 2090, 1, "chmod", "CHMOD", "/etc/passwd mode=0644", uid=0)])


def test_code_injection_rwx_positive():
    events = [
        ev(1.0, 1100, 1, "inj", "MPROTECT", "addr=0x7f0000 prot=rwx suppressed=0"),
        ev(2.0, 1101, 1, "inj", "MPROTECT", "addr=0x7f1000 prot=-wx suppressed=0"),
    ]
    assert fired(Engine(), events).count("code_injection_rwx") == 2


def test_code_injection_rwx_negative_jit_flip():
    assert "code_injection_rwx" not in fired(Engine(), [ev(1.0, 2100, 1, "gnome-shell", "MPROTECT", "addr=0x7f0000 prot=r-x suppressed=40")])


def test_kernel_module_load_positive():
    eng = Engine()
    fired(eng, [ev(1.0, 1110, 1, "insmod", "MODULE", "evil.ko", uid=0)])
    alert = [a for a in eng.alerts if a["rule"] == "kernel_module_load"][0]
    assert alert["severity"] == "critical"


def test_kernel_module_load_positive_from_memory():
    assert "kernel_module_load" in fired(Engine(), [ev(1.0, 1111, 1, "x", "MODULE", "memory_image len=12345", uid=0)])


def test_kernel_module_load_negative_no_module_event():
    assert "kernel_module_load" not in fired(Engine(), [ev(1.0, 2110, 1, "app", "EXEC", "/usr/bin/app")])


def test_backdoor_listener_positive_netcat_and_python():
    events = [
        ev(1.0, 1120, 1, "bash", "EXEC", "/usr/bin/nc.openbsd"),
        ev(1.1, 1120, 1, "nc", "BIND", "0.0.0.0:4444"),
        ev(2.0, 1121, 1, "python3", "BIND", "127.0.0.1:4445"),
    ]
    assert fired(Engine(), events).count("backdoor_listener") == 2


def test_backdoor_listener_negative_normal_service():
    assert "backdoor_listener" not in fired(Engine(), [ev(1.0, 2120, 1, "nginx", "BIND", "0.0.0.0:80", uid=0)])


def test_download_and_execute_positive_two_processes():
    events = [
        ev(1.0, 1130, 1129, "bash", "EXEC", "/usr/bin/curl"),
        ev(1.2, 1130, 1129, "curl", "CONNECT", "127.0.0.53:53"),
        ev(1.3, 1130, 1129, "curl", "CONNECT", "93.184.216.34:80"),
        ev(1.5, 1130, 1129, "curl", "OPEN", "/tmp/payload"),
        ev(3.0, 1131, 1129, "bash", "EXEC", "/tmp/payload"),
    ]
    assert "download_and_execute" in fired(Engine(), events)


def test_download_and_execute_positive_file_opened_before_connect():
    events = [
        ev(1.0, 1132, 1, "wget", "OPEN", "/tmp/w"),
        ev(1.2, 1132, 1, "wget", "CONNECT", "93.184.216.34:80"),
        ev(4.0, 1133, 1, "bash", "EXEC", "/tmp/w"),
    ]
    assert "download_and_execute" in fired(Engine(), events)


def test_download_and_execute_negative_file_written_offline():
    events = [
        ev(1.0, 2130, 1, "gcc", "OPEN", "/tmp/a.out"),
        ev(2.0, 2131, 1, "bash", "EXEC", "/tmp/a.out"),
    ]
    assert "download_and_execute" not in fired(Engine(), events)


def test_download_and_execute_negative_only_dns():
    events = [
        ev(1.0, 2132, 1, "make", "CONNECT", "127.0.0.53:53"),
        ev(1.5, 2132, 1, "make", "OPEN", "/tmp/build/tool"),
        ev(2.0, 2133, 1, "make", "EXEC", "/tmp/build/tool"),
    ]
    assert "download_and_execute" not in fired(Engine(), events)


# Shapes below were seen raising ransomware_burst during the 15 minute idle
# run on the dev VM (2026-10-27). Username replaced with u.

def burst(pid, comm, typ, details, start=500.0, step=0.02):
    return [ev(start + i * step, pid, 1, comm, typ, d) for i, d in enumerate(details)]


def test_ransomware_burst_negative_apt_clearing_package_lists():
    details = [f"/var/lib/apt/lists/in.archive.ubuntu.com_ubuntu_dists_jammy_part{i}" for i in range(40)]
    assert "ransomware_burst" not in fired(Engine(), burst(3001, "apt", "UNLINK", details))


def test_ransomware_burst_negative_esm_hook():
    details = [f"/var/lib/ubuntu-advantage/apt-esm/var/lib/apt/lists/esm_{i}" for i in range(40)]
    assert "ransomware_burst" not in fired(Engine(), burst(3002, "python3", "UNLINK", details))


def test_ransomware_burst_negative_dpkg_staging_files():
    details = [f"/usr/share/doc/pkg{i}/changelog.Debian.gz.dpkg-tmp" for i in range(40)]
    assert "ransomware_burst" not in fired(Engine(), burst(3003, "dpkg", "UNLINK", details))


def test_ransomware_burst_negative_thunderbird_journals():
    details = [f"/home/u/.thunderbird/q405u9oo.default-release/db{i}.sqlite-journal" for i in range(40)]
    assert "ransomware_burst" not in fired(Engine(), burst(3004, "thunderbird", "UNLINK", details))


def test_ransomware_burst_negative_snap_firefox_cut_rename_paths():
    # each side cut at 59 chars by the sensor, exactly as seen live
    side = "/home/u/snap/firefox/common/.mozilla/firefox/s1xd0i8j.defau"[:59]
    details = [f"{side} -> {side}" for _ in range(40)]
    assert "ransomware_burst" not in fired(Engine(), burst(3005, "firefox", "RENAME", details))


def test_ransomware_burst_positive_documents_still_caught():
    details = [f"/home/u/Documents/report{i}.odt -> /home/u/Documents/report{i}.odt.locked" for i in range(30)]
    assert "ransomware_burst" in fired(Engine(), burst(3006, "python3", "RENAME", details, step=0.1))


def test_ransomware_burst_positive_moving_documents_into_a_cache_folder():
    details = [f"/home/u/Documents/r{i}.odt -> /home/u/.cache/r{i}.locked" for i in range(30)]
    assert "ransomware_burst" in fired(Engine(), burst(3007, "python3", "RENAME", details, step=0.1))


def test_ransomware_burst_positive_package_named_bait_does_not_hide_the_original():
    details = [f"/home/u/Documents/r{i}.odt -> /home/u/Documents/r{i}.dpkg-tmp" for i in range(30)]
    assert "ransomware_burst" in fired(Engine(), burst(3008, "python3", "RENAME", details, step=0.1))


def sudo_exec(ts, pid):
    return ev(ts, pid, 4178, "bash", "EXEC", "/usr/bin/sudo")


def test_credential_access_positive_read_of_shadow():
    events = [
        ev(1.0, 4500, 4178, "bash", "EXEC", "/usr/bin/python3"),
        ev(1.1, 4500, 4178, "python3", "READ", "/etc/shadow"),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_credential_access_sudo_own_reads_stay_quiet():
    events = [
        sudo_exec(1.0, 4397),
        ev(1.01, 4397, 4178, "sudo", "READ", "/etc/sudoers", uid=0),
        ev(1.02, 4397, 4178, "sudo", "READ", "/etc/shadow", uid=1000),
        ev(3.5, 4397, 4178, "sudo", "READ", "/etc/shadow", uid=1000),
    ]
    assert "credential_access" not in fired(Engine(), events)


def test_credential_access_sudo_cat_of_shadow_still_alerts():
    events = [
        sudo_exec(1.0, 4400),
        ev(1.1, 4402, 4401, "sudo", "EXEC", "/usr/bin/cat", uid=0),
        ev(1.2, 4402, 4401, "cat", "READ", "/etc/shadow", uid=0),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_credential_access_denied_plain_cat_still_alerts():
    events = [
        ev(1.0, 4406, 4178, "bash", "EXEC", "/usr/bin/cat"),
        ev(1.1, 4406, 4178, "cat", "READ", "/etc/shadow", uid=1000),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_credential_access_copy_named_sudo_outside_usr_bin_alerts():
    events = [
        ev(1.0, 4600, 4178, "bash", "EXEC", "/tmp/sudo"),
        ev(1.1, 4600, 4178, "sudo", "READ", "/etc/shadow", uid=1000),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_credential_access_account_tools_stay_quiet_on_read():
    events = [
        ev(1.0, 4700, 4178, "sudo", "EXEC", "/usr/bin/passwd", uid=0),
        ev(1.1, 4700, 4178, "passwd", "READ", "/etc/shadow", uid=0),
    ]
    assert "credential_access" not in fired(Engine(), events)


def test_credential_access_su_reading_shadow_stays_quiet():
    events = [
        ev(1.0, 5010, 4178, "bash", "EXEC", "/usr/bin/su"),
        ev(1.1, 5010, 4178, "su", "READ", "/etc/shadow", uid=1000),
    ]
    assert "credential_access" not in fired(Engine(), events)


def test_credential_access_gdm_session_worker_stays_quiet():
    events = [
        ev(1.0, 5381, 1253, "gdm3", "EXEC", "/usr/libexec/gdm-session-worker", uid=0),
        ev(1.1, 5381, 1253, "gdm-session-wor", "READ", "/etc/shadow", uid=0),
    ]
    assert "credential_access" not in fired(Engine(), events)


def test_credential_access_cron_child_without_exec_stays_quiet():
    events = [ev(1.0, 5023, 635, "cron", "READ", "/etc/shadow", uid=0)]
    assert "credential_access" not in fired(Engine(), events)


def test_credential_access_copy_named_cron_alerts():
    events = [
        ev(1.0, 5100, 4178, "bash", "EXEC", "/tmp/cron"),
        ev(1.1, 5100, 4178, "cron", "READ", "/etc/shadow", uid=0),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_credential_access_copy_named_su_alerts():
    events = [
        ev(1.0, 5101, 4178, "bash", "EXEC", "/tmp/su"),
        ev(1.1, 5101, 4178, "su", "READ", "/etc/shadow", uid=1000),
    ]
    assert "credential_access" in fired(Engine(), events)


def test_log_tampering_su_writing_btmp_stays_quiet():
    events = [
        ev(1.0, 5010, 4178, "bash", "EXEC", "/usr/bin/su"),
        ev(1.1, 5010, 4178, "su", "OPEN", "/var/log/btmp", uid=1000),
    ]
    assert "log_tampering" not in fired(Engine(), events)


def test_log_tampering_copy_named_su_on_btmp_alerts():
    events = [
        ev(1.0, 5102, 4178, "bash", "EXEC", "/tmp/su"),
        ev(1.1, 5102, 4178, "su", "OPEN", "/var/log/btmp", uid=1000),
    ]
    assert "log_tampering" in fired(Engine(), events)


def test_log_tampering_other_program_on_btmp_alerts():
    events = [
        ev(1.0, 5103, 4178, "bash", "EXEC", "/usr/bin/python3"),
        ev(1.1, 5103, 4178, "python3", "OPEN", "/var/log/btmp", uid=0),
    ]
    assert "log_tampering" in fired(Engine(), events)


def test_code_injection_rwx_libreoffice_stays_quiet():
    events = [
        ev(1.0, 5043, 5026, "osl_executeProc", "EXEC", "/usr/lib/libreoffice/program/soffice.bin"),
        ev(1.5, 5043, 5026, "soffice.bin", "MPROTECT", "addr=0x7fbeb4eed000 prot=rwx suppressed=0"),
    ]
    assert "code_injection_rwx" not in fired(Engine(), events)


def test_code_injection_rwx_copy_named_soffice_alerts():
    events = [
        ev(1.0, 5200, 4178, "bash", "EXEC", "/tmp/soffice.bin"),
        ev(1.5, 5200, 4178, "soffice.bin", "MPROTECT", "addr=0x7fbeb4eed000 prot=rwx suppressed=0"),
    ]
    assert "code_injection_rwx" in fired(Engine(), events)


def test_connect_after_exec_whoopsie_stays_quiet():
    events = [
        ev(1.0, 4632, 1, "(whoopsie)", "EXEC", "/usr/bin/whoopsie"),
        ev(1.4, 4632, 1, "whoopsie", "CONNECT", "91.189.95.56:443"),
    ]
    assert "connect_after_exec" not in fired(Engine(), events)


def test_connect_after_exec_copy_named_whoopsie_alerts():
    events = [
        ev(1.0, 5201, 4178, "bash", "EXEC", "/tmp/whoopsie"),
        ev(1.4, 5201, 4178, "whoopsie", "CONNECT", "91.189.95.56:443"),
    ]
    assert "connect_after_exec" in fired(Engine(), events)


def cache_swap_events(base):
    events = []
    for i in range(60):
        src = f"{base}/96b{i}.HQHdPV"
        events.append(ev(i * 0.01, 7811, 4178, "npm", "OPEN", src))
        events.append(ev(i * 0.01 + 0.005, 7811, 4178, "npm", "RENAME", f"{src} -> {base}/96b{i}"))
    return events


def test_ransomware_burst_node_compile_cache_stays_quiet():
    events = cache_swap_events("/tmp/node-compile-cache/v22.23.4-x64-9de703df-1000")
    assert "ransomware_burst" not in fired(Engine(), events)


def test_ransomware_burst_same_shape_outside_the_cache_alerts():
    events = cache_swap_events("/tmp/other-dir")
    assert "ransomware_burst" in fired(Engine(), events)


def test_code_injection_rwx_node_under_nvm_stays_quiet():
    events = [
        ev(1.0, 7800, 4178, "bash", "EXEC", "/home/vesper/.nvm/versions/node/v22.23.4/bin/node"),
        ev(1.5, 7800, 4178, "node", "MPROTECT", "addr=0x7f0000 prot=rwx suppressed=0"),
    ]
    assert "code_injection_rwx" not in fired(Engine(), events)


def test_code_injection_rwx_copy_named_node_alerts():
    events = [
        ev(1.0, 7801, 4178, "bash", "EXEC", "/tmp/node"),
        ev(1.5, 7801, 4178, "node", "MPROTECT", "addr=0x7f0000 prot=rwx suppressed=0"),
    ]
    assert "code_injection_rwx" in fired(Engine(), events)


def test_excluded_program_exec_with_empty_path_loses_its_exclusion():
    events = [
        ev(1.0, 7900, 4178, "bash", "EXEC", "/home/vesper/.nvm/versions/node/v22.23.4/bin/node"),
        ev(1.1, 7900, 4178, "node", "EXEC", ""),
        ev(1.5, 7900, 4178, "node", "MPROTECT", "addr=0x7f0000 prot=rwx suppressed=0"),
    ]
    assert "code_injection_rwx" in fired(Engine(), events)
