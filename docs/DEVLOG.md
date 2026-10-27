
## 2026-09-16 - L1 kernel sensor, session 1
- Phase 0 done: kernel 6.8.0-138-generic, BTF present at /sys/kernel/btf/vmlinux (6099393 bytes),
  toolchain installed (clang 14, bpftool v7.4.0 / libbpf v1.4).
- Generated bpf/vmlinux.h from BTF, 150673 lines, gitignored since it is machine-specific.
- Repo initialised, .gitattributes committed first (LF enforced), then .gitignore.
- Wrote hello.bpf.c, execve tracepoint + bpf_printk. Compiles clean to eBPF bytecode
  (file reports "ELF 64-bit LSB relocatable, eBPF, with debug_info, not stripped").
- Disassembled it: 10 instructions. "call 6" is bpf_trace_printk called by helper ID,
  which is also why bpf_printk takes only three format args (r1 and r2 are taken).
- Not loaded into the kernel yet. Loader is next session.

## 2026-10-14 - L1 kernel sensor, session 2
- Wrote loader/hello_loader.c with libbpf: open, load, attach, then wait for a signal.
- Loaded hello.bpf.o and attached it to the execve tracepoint. libbpf printed a harmless note about the .rodata.str1.1 section.
- trace_pipe showed an "exec" line for each new program started, including a burst when a new terminal opened. comm showed the parent name (bash) because the hook fires at syscall entry.
- pwd produced no event because it is a shell builtin and does not call execve.
- Verifier exercise: a map lookup dereferenced without a NULL check compiled fine but was rejected at load with "R0 invalid mem access 'map_value_or_null'" after 7 instructions, error -13. Adding "if (!val) return 0;" made it load (xlated 152B, jited 93B). Lesson files not committed.
- Wrote common.h (struct event, 168 bytes, checked with clang and gcc), execve_monitor.bpf.c (ring buffer, 256KB) and loader.c (JSON lines on stdout).
- First load failed with "libbpf: failed to find valid kernel BTF", error -3. The apt libbpf (0.5.0) could not parse the 6.8 kernel's BTF. Built libbpf v1.4.0 as a static library, linked the loader against it, and the load worked.
- Piped loader output through jq. EXEC lines appeared for terminal shell startup and for ls. comm is cut at 15 characters. A program named /tmp/a"b came through as valid JSON with the quote escaped.

## 2026-10-26 - L1 kernel sensor, session 3
- Added file_monitor (OPEN, write intent only), net_monitor (CONNECT, BIND), privesc_monitor (PTRACE, SETUID), file_lifecycle (UNLINK, RENAME), mem_monitor (MPROTECT), module_monitor (MODULE), perm_monitor (CHMOD). 8 monitors, 22 programs, one shared ring buffer.
- strace on this VM: os.rename -> rename, mv -> renameat2, os.unlink -> unlink, rm -> unlinkat, os.chmod -> chmod, chmod(1) -> fchmodat, os.fchmod -> fchmod. Hooking only the *at forms would have seen 2 of 4 file ops and 1 of 3 chmods. Whole families hooked, all seen. fchmodat2 is not used by glibc 2.35, proved it fires with raw syscall 452.
- First setuid version missed calls that change only the real uid (sudo's first switch never showed up). Now falls back to the real uid when euid is -1.
- Idle minute with Firefox open: 72 and 254 events. The 254 was mostly apt-check (104 EXEC, 52 OPEN).
- Port 0 connects were 3 of 8 CONNECT in that minute, now dropped in the kernel. IPv4-mapped and pure IPv6 connects were invisible, now reported. Firefox :443 connects only started showing after that fix.
- mem_monitor rate limit: 514 exec remaps in an idle minute, 21 events emitted, 493 carried in suppressed=. Mostly gnome-shell.
- Firefox renamed 8 files in about 25 ms during normal browsing.
- Event loss: 0 with the reader keeping up. 48019 of a 50000 open flood with the reader stalled 30 s. Now counted in a per-cpu drops map and printed on exit.
- Per-event cost from kernel.bpf_stats_enabled: filtered read-only open 60 ns. Emitted event waking the reader every time 65200 ns. Never waking 128 ns but 48557 dropped. Waking only when 64 KB is pending 1159 ns, 0 dropped.
- My batched wakeup broke quiet events: ring_buffer__poll does not read on timeout, so a lone ls never showed. Added ring_buffer__consume in the loop and at exit.
- correlate.bpf.c (off by default, --correlate): connect stamps the pid, exec checks self then parent within 10 s, exit clears it. Child and same-process cases fire, no-connect and 11 s cases don't. 2 stamps left after the test.
- Still open: no L2 engine yet to pipe into. One OPEN with empty detail at bash startup. *at syscalls can give relative paths. RENAME paths over 59 chars get cut.

## 2026-10-27 - L1 kernel sensor, session 4 (BPF-LSM prevention)
- Enabled BPF-LSM: added bpf to the lsm= list in GRUB, rebooted. /sys/kernel/security/lsm now ends in ,bpf.
- lsm_detect.bpf.c: lsm/ptrace_access_check reported as its own type PTRACE_CHECK, rate-limited per pid, never labelled PTRACE. ps aux and fuser triggered run_cnt=2137 permission checks in a few seconds, none a real ptrace. Standalone, not wired into the main loader.
- enforce.bpf.c: same hook, returns -EPERM for one pid read from a userspace config map. protected_pid=0 denies nothing (fail-open), checked strace -f /bin/true still works with it loaded.
- ips_enforce.c: separate binary, separate make ips target, plain make does not build it. Takes the pid to protect as an argument, writes config, prints BLOCK events. Ships disabled.
- Proved prevention: sudo strace -p <sleep pid> attached fine with no IPS; with the IPS protecting that pid, sudo strace as root got "ptrace(PTRACE_SEIZE): Operation not permitted" and the IPS printed a BLOCK event. Root bypasses yama but the bpf LSM is last in the lsm= order and still denied.
- Scope is ptrace only for now; exec blocking via bprm_check_security deferred. Separate binary, disabled default, narrow policy is the answer to "what if prevention has a bug".
- Still open: wire PTRACE_CHECK into the main loader if wanted, exec enforcement, no L2 engine yet.

## 31 July 2026 - L2 detection engine, session

- Built ProcessState (features.py) with sets for cardinality tracking, tested with
  duplicate file writes to confirm set behavior.
- Built Engine (engine.py) to look up/create ProcessState per pid.
- Built rules_dsl.py: YAML rule loading, field resolution (proc/since/parent), and
  five operators.
- First rule connect_after_exec (T1071) working, but negative test caught a real bug:
  since.exec was using the timestamp of ANY last event, not specifically the last EXEC.
  A CONNECT event slower than 3s was still firing because CONNECT itself became the
  "last event" before the rule check ran. Fixed by adding per-event-type last_seen
  tracking in ProcessState.
- Positive and negative tests both pass now (1 alert / 0 alerts respectively).

## 31 July 2026 - Rule 2 fixed and tested

- network_parent_shell (T1059) rule was missing from 00_core.yml (only 1 rule was
  loading instead of 2) - re-added it with correct YAML indentation.
- Positive test: sshd connects, spawns bash child -> 1 alert (network_parent_shell).
- Negative test: no parent connect -> 0 alerts, as expected.

## 31 July 2026 - Rule 3 and the evt.* fix

- ptrace_then_exec (T1055) initially fired on the PTRACE event alone, not waiting for
  the following EXEC. Root cause: the rule only checked proc.ptrace_count and
  since.ptrace, with no way to check what the CURRENT event's type was.
- Fixed by adding an evt.* field family to resolve_field/check_condition, which reads
  directly from the current event dict instead of accumulated state. Added
  "evt.type eq EXEC" as a condition to the rule.
- All three tests pass: PTRACE alone -> 0 alerts, PTRACE then fast EXEC -> 1 alert,
  PTRACE then slow EXEC -> 0 alerts.

## 31 July 2026 - Rule 4 and the comm staleness bug

- suid_shell (T1548) initially failed positive test: ProcessState.comm is set once at
  process creation and never updated, but real processes change comm via execve()
  (e.g. sudo -> bash). The rule checked proc.comm, which stayed "sudo" forever.
- Fixed by using evt.comm (current event's comm) instead of proc.comm in the rule
  condition, consistent with the evt.* field family added for Rule 3.
- All Phase 1 rules (connect_after_exec, network_parent_shell, ptrace_then_exec,
  suid_shell) now implemented and passing positive + negative tests.

## ML seam implemented and tested

- Added anomaly_model hook to Engine.process_event: if anomaly_model is not None,
  calls model.score(state) and emits an ml_anomaly alert if score >= model.threshold.
- Tested with a fake model (score 0.9 if exec_count > 2, threshold 0.5):
  without model -> 0 alerts; with model after 3 EXECs -> 1 ml_anomaly alert.
- Confirms the seam works without touching Engine code again when a real model
  is plugged in later - only needs .score() and .threshold.

## Converted manual tests to pytest; fixed a path bug

- Wrote tests/test_features.py (4 tests) and tests/test_dsl_engine.py (14 tests),
  covering all 4 rules, dedupe, ML seam, and rule loading - replacing manual REPL checks.
- Running pytest from repo root exposed a bug: Engine's default rules_path was a
  relative string "rules/00_core.yml", which only worked when python was run from
  inside server/. Fixed by using os.path.dirname(__file__) to build an absolute
  default path, so Engine() now works correctly regardless of the working directory.
- All 18 tests (4 + 14) pass.

## Phase 2 begins - ransomware rule

- Added distinct_files_written and distinct_destinations as @property on ProcessState,
  computing len() of the underlying sets on demand rather than storing a separate counter.
- Added mass_file_write_ransomware (T1486): fires when a process writes to >=20 distinct
  files, using evt.type=OPEN plus proc.distinct_files_written.
- Positive test (25 distinct files) produced exactly 1 alert total (not one per file)
  because dedupe correctly suppressed repeats within the 60s window - confirms dedupe
  and the new rule work together correctly.
- Negative test (30 writes to the SAME file) produced 0 alerts, confirming the rule
  distinguishes cardinality (distinct files) from raw event count.

## Phase 2 Step 13-14 - proper ransomware burst rule

- Realized the earlier mass_file_write_ransomware rule (built ahead of the prompt) used
  OPEN + distinct file count, but the spec's actual Step 14 wants a BURST of
  UNLINK/RENAME events in a short sliding window - a different signal (destruction
  speed, not just breadth). Kept the earlier rule as a bonus, built the correct one.
- Extended ProcessState with 6 new counters (unlink, rename, mprotect_exec, module,
  bind, chmod) and a destruction_times list, capped at 256 like other tracked lists.
- Added destruction_burst property: counts how many destruction events happened within
  5s of the most recent one (sliding window, same idea as Person 3's burst_rate).
- ransomware_burst (T1486) rule: evt.type in [UNLINK,RENAME] AND destruction_burst >= 8.
- Positive test: 9 deletes in 4.5s -> 1 alert (fired once burst threshold hit, dedupe
  suppressed the rest). Negative test: 9 deletes 10s apart -> 0 alerts, since no 5s
  window ever contains 8 of them. This negative test is what keeps the rule usable -
  without it, routine slow cleanup scripts would trigger false alarms.

## Phase 2 Step 15 - filesystem rules

- Added server/rules/10_filesystem.yml with 5 rules, each using the matches (regex)
  operator on evt.detail: log_tampering (T1070), persistence_autostart (T1547),
  credential_access (T1003), suid_backdoor (T1548), world_writable_sensitive (T1222).
- Changed Engine to auto-discover and load ALL *.yml files under rules/ (sorted by
  filename) via a new load_all_rules() function, instead of a single hardcoded path.
  This means dropping in a new rules file (e.g. 20_memory_kernel.yml later) requires
  zero code change - consistent with "rules are data, not code".
- 10 tests (5 positive + 5 negative) all pass. Total rules now: 11.

## Phase 2 Step 16 - memory/kernel rules

- Added server/rules/20_memory_kernel.yml with 2 rules:
  - code_injection_rwx (T1055): fires on MPROTECT with proc.mprotect_exec_count >= 1,
    reusing the counter already built in features.py that only increments when the
    requested permission includes execute (rwx/rx) - classic shellcode injection signal.
  - kernel_module_load (T1547): fires on any MODULE event, severity=critical (not high)
    because a loaded kernel module runs with more power than root and can blind or
    disable this very detection tool (rootkit risk) - the one rule where severity
    reflects the blast radius rather than confidence.
- Both positive and negative tests pass. Total rules now: 13/14.

## Phase 2 Step 17 - network rules AND a hidden bug from Step 9

- Added server/rules/30_network.yml: backdoor_listener (T1071, BIND from a shell) and
  download_and_execute (T1059, EXEC of a /tmp file shortly after a CONNECT).
- Testing download_and_execute exposed a bug that had been hiding in connect_after_exec
  since Step 9: that rule never checked evt.type, only proc.connect_count and
  since.exec. When an EXEC event arrived on a process that had connected before,
  since.exec evaluated to 0.0 (the CURRENT event's own timestamp), which is always
  <= 3.0, so connect_after_exec incorrectly fired on EXEC events too - not just CONNECT
  events as its name implies. This never showed up before because every prior test had
  CONNECT as the last event, never EXEC-after-CONNECT in that specific order.
- Fixed by adding "evt.type eq CONNECT" to connect_after_exec's conditions.
- All rules now: 14 official (per the v6 prompt) + 1 bonus (mass_file_write_ransomware,
  built ahead of spec) = 15 total, all tested and passing.

## Phase 2 Step 19 - incident grouping key

- Added server/incidents.py with find_root_pid(engine, pid), which walks the ppid
  chain upward until it finds a process with no known parent (root of the tree).
- Chose process-tree root over source IP as the grouping key because on a single
  host, lineage tells the real story - one attacker's session often reuses IPs or
  switches them, but the process tree shows exactly which process spawned which,
  which is what actually links a multi-stage attack together.
- Tested with a 3-level chain (sshd -> bash -> curl): root of all three pids
  correctly resolves to pid 10 (sshd), the topmost process.

## Phase 2 Step 20 - incident object and grouping

- Added Incident class: auto-generated title, status defaulting to "open",
  first_seen/last_seen auto-expanding as alerts are added, severity tracked as the
  MAX of all its alerts (via SEVERITY_RANK) rather than an average - a single
  critical alert should not be diluted by several low-severity ones.
- Added IncidentManager: routes each alert to find_root_pid, then either adds it to
  an existing incident for that root or creates a new one.
- A debugging note: initial test showed only 1 of 2 expected alerts landing in the
  incident. Root cause was NOT a bug - a stale Engine object from a previous REPL
  session had already recorded a CONNECT event, so connect_count was 2 instead of 1,
  and (unrelated) dedupe timing from the earlier run interfered. A fresh session
  reproduced the correct result: 2 alerts merged into 1 incident, severity=high.
  Lesson: always verify with a clean object before assuming a rule regression.

## Phase 2 Step 21 - status workflow with audit trail

- Added set_status(new_status, actor, note) to Incident: validates against
  VALID_STATUSES (open/investigating/resolved/false_positive), raises ValueError on
  anything else, and appends an audit_log entry (from_status, to_status, actor, note)
  on every valid transition.
- Why an audit trail matters: if an incident is later found to have been closed
  incorrectly (e.g. a real breach marked "false_positive"), the audit log is the only
  way to know who made that call, when, and what reasoning they gave - without it
  there is no accountability and no way to learn from the mistake.
- Tested: valid open->investigating->resolved transitions recorded correctly (2 audit
  entries with correct actor/note), and set_status("banana", ...) correctly raised
  ValueError. Incidents (Steps 19-21) now complete.

## Phase 2 Step 22 - IOC matching

- Added server/ioc.py: IOCStore holds indicators (ip/path/hash) and matches alert
  event details against them using fnmatch (wildcard patterns like /tmp/*.sh or
  1.2.3.*). enrich(alert) adds an ioc_matches field when a hit occurs.
- Key property demonstrated: adding a NEW indicator (store.add(...)) required no code
  change and no restart - it's a data path, not a code path. Contrast with adding a
  new detection rule, which means writing YAML and (for a brand new field/operator)
  possibly touching rules_dsl.py - IOC matching is strictly lighter-weight because the
  matching logic itself never changes, only the data it's matching against.
- Tested: IP match/no-match, path match, and a new IOC added mid-session matching
  immediately without any engine restart.

## Phase 2 Step 23 - MITRE coverage

- Added server/mitre.py: a static TECHNIQUE_CATALOGUE (9 techniques, each with name
  and tactic), plus coverage()/summary() which count how many alerts fired for each
  technique THIS session, and mark each technique as covered (>0 alerts) or not.
- Why this matters beyond a plain alert list: an alert list answers "what happened",
  a coverage matrix answers "what CAN this system detect, and what is currently blind"
  - if the catalogue had 20 techniques but only 9 have rules, the other 11 would be
  invisible blind spots that a raw alert feed would never surface.
- Tested: after firing only connect_after_exec (T1071), summary() correctly reports
  1/9 techniques covered, with the right technique/name/tactic/alert_count for T1071
  and covered=False for the other 8.

## Phase 2 Step 24 - fan-out seam confirmed (FINAL STEP)

- Ran `Select-String -Path "server\engine.py" -Pattern "import"` to verify engine.py's
  import list. Result: only os, glob, features.ProcessState, and rules_dsl's
  load_rules/check_condition - no import of incidents, ioc, mitre, response, or
  alerting anywhere in engine.py.
- Confirms the fan-out discipline held throughout the whole build: the engine's only
  job is deciding whether an event produces an alert. Everything downstream
  (incident correlation, IOC enrichment, response playbooks, notification) is wired
  together by app.py (not yet built), in that specific order - the engine itself
  stays independently testable with zero dependencies on any of them, exactly as it
  has been tested throughout this whole project (bare Engine() calls, no database,
  no incident manager needed).
- THIS COMPLETES ALL 24 STEPS OF THE DETECTION ENGINE (Person 2's full scope per the
  v6 prompt): 14 rules across 9 MITRE techniques, dedupe, ML seam, incidents with
  audit trail, IOC matching, and MITRE coverage tracking - all built, tested, and
  measured (precision/recall/F1 = 1.000/1.000/1.000).

## Closed the test coverage gap for Phase 2 rules

- An external review of the actual repo (not just conversation logs) found that
  the 10 Phase 2 rules had no dedicated pytest positive/negative tests - they were
  only validated via measure_rules.py (an aggregate script) and manual REPL testing,
  not individual asserts as spec Steps 15-17 require.
- Added tests/test_dsl_rules.py: 20 tests (10 rules x positive + negative), each
  using a fresh Engine() per test and checking for the specific rule name in the
  alerts list rather than just len(alerts), so an unrelated rule firing wouldn't
  mask a real failure.
- All 20 pass. Combined with test_features.py (4) and test_dsl_engine.py (14),
  total automated test count is now 38.

## Rule file reorganization to match spec exactly

- Moved ransomware_burst from 00_core.yml to 10_filesystem.yml, matching the spec's
  file layout (00_core.yml=4 rules, 10_filesystem.yml=6 rules including
  ransomware_burst). Removed the earlier bonus rule (mass_file_write_ransomware)
  since it had no spec basis and no dedicated test - kept the rule count exactly at
  the spec's 14, not 15.
- Re-ran full test suite (38 tests) and measure_rules.py after the move: all still
  pass, precision/recall/F1 still 1.000/1.000/1.000, 9/9 techniques. Confirms the
  reorganization was purely structural (file location), not a functional change.
- This closes the last known gap from the external review: rule count, file
  organization, and test coverage all now match the v6 prompt exactly.

## 2026-10-27 - L2 detection engine, review, real sensor, tuning

- Took the engine as delivered by Subhrajit, committed it under his name, then fixed it against docs/sensor-contract.md: imports from the repo root, EXEC comm being the parent's name, IPv6 and relative paths, bounded memory, rule loading that skips a bad rule instead of dying. 109 tests, then 124.
- First live run through sudo ./loader/loader | python -m server.ingest: 286 events, 0 bad lines, 0 engine errors, 0 dropped. DNS lookups to 127.0.0.53:53 stay quiet.
- 15 minute idle run with normal use: 9223 events, 14 alerts, all false. 8 connect_after_exec (curl, wget, ping, apt helpers, Thunderbird), 6 ransomware_burst (apt, dpkg, Firefox and Thunderbird profile churn). The other 12 rules were silent.
- Tuned both rules from that run and ran it again: 5794 events, 2 alerts. Thunderbird again (it runs from /usr/lib/thunderbird, not /snap), and suid_shell on cron.hourly at minute 17, because the rule counted cron's root to root setuid. Fixed both. The two runs were not the same workload, so the drop is not all down to the tuning.
- Three attack tests on the live sensor (reverse shell shape, chmod 4755, 30 fast renames): all caught. The cleanup rm -rf of those 30 files raised ransomware_burst too.
- Third idle run, 30 minutes with cron.hourly at 21:17:01 inside it: 7115 events, 0 alerts, 0 dropped. The cron false alarm is gone on the real host.
- Still open: rm -rf of big folders will alert critical. credential_access cannot see reads of /etc/shadow because the sensor only reports write opens. Relative paths from unlinkat/renameat/fchmodat defeat the path rules.

## 2026-10-27 - L1 kernel sensor, session 5 (live check with the engine, sample file)
- Fast-forwarded l1-sensor to main c9cfd2a, so this branch now has the L2 engine. The "no L2 engine yet" lines in sessions 3 and 4 were true when written and are left as they were.
- Piped the real loader into python -m server.ingest. One run saw 2382 events, 2 alerts, 0 bad lines, 0 engine errors. The alerts: kernel_module_load on MODULE dummy.ko (sudo modprobe dummy) and code_injection_rwx on MPROTECT prot=rwx (python mprotect with PROT_EXEC). Screenshot in docs/live-pipeline.png.
- Rules seen firing on the live sensor so far: connect_after_exec, network_parent_shell, suid_backdoor, backdoor_listener, ransomware_burst (L2 chat) plus kernel_module_load and code_injection_rwx. That is 7 of 14. The other 7 are only proven on mock events and in tests.
- strace -p on a sleeping process gave 2 PTRACE events.
- Added samples/events.jsonl: 160 events from a 45 s and a 20 s capture, lab commands only, 11 of the 12 event types in docs/sensor-contract.md. CORRELATED is missing because it needs --correlate. 42 of the first 192 lines were Firefox profile paths, dropped, and the username and hostname replaced. Replays through server.ingest with 0 bad lines and 3 alerts, all from the lab commands (bind on 127.0.0.1, modprobe dummy, rwx mprotect).
- Still open: reads of /etc/shadow still make no event. rm -rf reports relative paths. A failed exec during a PATH search still shows up as an EXEC event. Exec blocking is not done, only ptrace. 7 rules have never fired live.
