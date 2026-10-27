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

TODO: 15 minutes of normal use (Firefox, terminal, apt update) with no sims running, through `sudo ./loader/loader | python3 -m server.ingest`, then count alerts per rule. Every alert in that window is a false positive, and that count is the number to quote in the viva.

## Known blind spots

credential_access can only see write-intent opens of /etc/shadow, because the sensor reports OPEN for writes only. Reading /etc/shadow, which is what credential dumping actually does, produces no event at all.

Paths from unlinkat, renameat and fchmodat can be relative (for example `cd /var/log && rm auth.log` arrives as `auth.log`), so the path-anchored rules miss them.

Processes that started before the sensor have no EXEC event, so their exe_name falls back to comm, which can be a thread name.