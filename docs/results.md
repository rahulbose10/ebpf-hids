# L2 detection engine, rule layer numbers

## How to reproduce

    python tests/measure_rules.py

This runs the 14 rules with anomaly_model=None over the replay corpus written inside that script. Ground truth is the pid: 2000 and up is an attack scenario, below 2000 is benign. That split was decided when the corpus was written, never by looking at what the rules fire on, which is the only reason the numbers mean anything.

Alert precision is the share of alerts that landed on attack pids. Scenario recall is how many of the 14 attack scenarios were caught by the rule written for them.

The events follow docs/sensor-contract.md, not the shapes we guessed before the sensor existed: comm on EXEC is still the parent's name, MPROTECT prot is three characters like r-x, DNS lookups show up as CONNECT to 127.0.0.53:53, and the benign side includes the Firefox burst L1 measured (8 renames in about 25 ms).

## First measurement (Shubra, Sep 2026, old corpus)

14 of 14 malicious pids alerted, 0 of 14 benign pids alerted, precision/recall/F1 1.000. That corpus used comm to carry the program name on EXEC and had no hard negatives, so it could not see the problems the review found.

## After the 2026-10-27 review fixes

Measured on Windows 11, Python 3.10.0, with 109 tests passing.

    events: 112  alerts: 14  rules loaded: 14  rule errors: 0
    ground truth: pid >= 2000 is attack, set when the corpus was built, never by asking the rules
    alert precision 1.000  (14 of 14 alerts on attack pids)
    scenario recall 1.000  (14 of 14 attack scenarios caught by their rule)
    F1 1.000
    benign pids alerted: 0 of 21

    connect_after_exec         fired
    network_parent_shell       fired
    ptrace_then_exec           fired
    suid_shell                 fired
    ransomware_burst           fired
    log_tampering              fired
    persistence_autostart      fired
    credential_access          fired
    suid_backdoor              fired
    world_writable_sensitive   fired
    code_injection_rwx         fired
    kernel_module_load         fired
    backdoor_listener          fired
    download_and_execute       fired

    techniques covered (9): T1003, T1055, T1059, T1070, T1071, T1222, T1486, T1547, T1548

## What these numbers do not show

The corpus is synthetic and was written by the people who wrote the rules. A perfect score means the rules do what we meant on the shapes we thought of. It says nothing about a real host.

## On the VM with the real sensor

Ubuntu 22.04, kernel 6.8, VirtualBox. Live pipeline `sudo ./loader/loader | python -m server.ingest`, rules only, no ML.

First live run, about a minute with one curl: 286 events, 0 bad lines, 0 engine errors, 0 dropped. DNS lookups to 127.0.0.53:53 raised nothing. curl's connect to :443 raised connect_after_exec, which is what led to the tuning below.

### Idle run before tuning (2026-10-27, about 15 min)

Normal use only: Firefox and Thunderbird running, terminal commands, ping, curl, wget, sudo apt update, git status. No attack sims. Every alert here is a false positive.

    ingest: 9223 events, 14 alerts, 0 bad lines, 0 engine errors
          8 connect_after_exec
          6 ransomware_burst

connect_after_exec fired on thunderbird, ping, curl, wget and apt's http/https download helpers. ransomware_burst fired on apt and the ESM hook clearing package lists, dpkg deleting .dpkg-tmp files, Firefox renaming inside its profile and Thunderbird deleting sqlite journals. The other 12 rules stayed silent.

### Tuning

ransomware_burst no longer counts deletes and renames under package manager state (/var/lib/apt, /var/lib/dpkg, /var/lib/ubuntu-advantage, /var/cache), dpkg staging files, or browser and mail profile and cache folders in the home directory. A rename only counts as routine when both sides are. ~/Documents and the rest of the home directory still count.

connect_after_exec now skips a short list of network clients matched on the full exe path (curl, wget, ping, git, ssh, apt and its download helpers, anything under /snap). A copy at /tmp/curl still alerts, and interpreters like python3 still alert, because a python one-liner calling home is the case the rule exists for.

What this costs: curl or wget used as a C2 channel no longer trips connect_after_exec. download_and_execute still catches curl writing a file that then gets run.

### Idle run after tuning (2026-10-27, 20:02 to 20:17)

Same kind of use: Firefox, Thunderbird, ping, curl, wget, sudo apt update twice, git status, pytest. No attack sims. The VM had been rebooted in between, so the two runs are not the same workload and the drop is not all down to the tuning. What is certain is that the shapes that fired in the first run did not fire again.

    ingest: 5794 events, 2 alerts, 0 bad lines, 0 engine errors
          1 suid_shell
          1 connect_after_exec

connect_after_exec fired on Thunderbird starting up. It runs from /usr/lib/thunderbird/thunderbird (the deb, not the snap), which the client list did not cover.

suid_shell fired at 20:17 on `cron` running `/bin/sh`, uid 0. Ubuntu's /etc/crontab runs cron.hourly at minute 17. cron is already root, so the uid change before /bin/sh -c is root to root, not an escalation. The rule counted any setuid call.

### Second round of tuning

suid_shell now needs proc.root_gain_count, which only counts a setuid that moved from a non-root uid to 0. cron's 0 to 0 and 0 to 1000 calls no longer count. setuid_count is unchanged and still counts every call.

/usr/lib/thunderbird/ and /usr/lib/firefox/ added to the connect_after_exec client list.

Not yet seen on the real host: the SETUID event cron emits right before the shell. The 0 to 0 shape is inferred from cron running as root, not read off a captured line.

### Attack tests on the VM (2026-10-27, about 20:32)

Three harmless attacks against the live pipeline, everything on loopback or in /tmp, alerts shown with `jq -c`. The listener for the first one was `python3 -m http.server 4444 --bind 127.0.0.1`.

    ingest: 394 events, 6 alerts, 0 bad lines, 0 engine errors

    backdoor_listener     high      python3 BIND 127.0.0.1:4444 (the listener itself)
    connect_after_exec    medium    python3 CONNECT 127.0.0.1:4444 (the client one-liner)
    network_parent_shell  high      sh EXEC /bin/sh, parent had made the connection
    suid_backdoor         high      chmod CHMOD /tmp/lab_sh mode=4755
    ransomware_burst      critical  python3 RENAME /tmp/lab/f24 -> /tmp/lab/f24.locked
    ransomware_burst      critical  rm UNLINK f2.locked (the cleanup, see below)

All three attacks were caught on real sensor events. The listener and the client one-liner each raised an alert of their own as well, which is what those rules are written to do.

The second ransomware_burst alert is `rm -rf /tmp/lab` deleting the 30 renamed files in under 5 seconds. It is the same rule doing what it says, but it means any ordinary `rm -rf` of a folder with 25 or more files will raise a critical alert. The idle runs did not include one, so the false alarm rate for that case is unmeasured. Note also that the path in that alert is `f2.locked`, not `/tmp/lab/f2.locked`: the sensor reports a relative path for unlinkat, so the routine churn exclusion cannot match it either.

### Idle run after the second round (2026-10-27, 20:49:31 to 21:19:33, 30 minutes)

Same kind of use as the earlier runs, with cron.hourly inside the window on purpose. journalctl shows `CMD (cd / && run-parts --report /etc/cron.hourly)` at 21:17:01, inside the recording.

    ingest: 7115 events, 0 alerts, 0 bad lines, 0 engine errors
    dropped events: 0

No alerts. The 14 from the first run and the 2 from the second run (Thunderbird starting, cron.hourly) did not come back. This run is twice as long as the first two and had more varied use than any of them, but it is still one machine, one user and 30 minutes, so 0 is what we measured, not a promise. The exact SETUID line cron emits was not captured, so the root to root shape is still inferred.

Summary of the three idle runs, all with no attack sims:

    run 1, about 15 min, before tuning:   9223 events, 14 alerts
    run 2, about 15 min, first tuning:    5794 events,  2 alerts
    run 3, 30 min, second tuning:         7115 events,  0 alerts

## Known blind spots

credential_access can only see write-intent opens of /etc/shadow, because the sensor reports OPEN for writes only. Reading /etc/shadow, which is what credential dumping actually does, produces no event at all.

Paths from unlinkat, renameat and fchmodat can be relative (for example `cd /var/log && rm auth.log` arrives as `auth.log`), so the path-anchored rules miss them.

`rm -rf` of a folder holding 25 or more files inside 5 seconds raises ransomware_burst at critical severity. Nothing in the rule tells a cleanup from an encryptor except which paths are involved.

Processes that started before the sensor have no EXEC event, so their exe_name falls back to comm, which can be a thread name.