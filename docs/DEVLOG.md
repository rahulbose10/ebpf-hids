
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

The 31 July 2026 dates on this entry and the three after it are the original author's and git cannot back them up. The repo starts on 2026-09-16 and this work was committed on 2026-10-27 (2546c90).

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

- Realized the earlier mass_file_write_ransomware rule (built ahead of the plan) used
  OPEN + distinct file count, but the spec's actual Step 14 wants a BURST of
  UNLINK/RENAME events in a short sliding window - a different signal (destruction
  speed, not just breadth). Kept the earlier rule as a bonus, built the correct one.
- Extended ProcessState with 6 new counters (unlink, rename, mprotect_exec, module,
  bind, chmod) and a destruction_times list, capped at 256 like other tracked lists.
- Added destruction_burst property: counts how many destruction events happened within
  5s of the most recent one (sliding window, same idea as L3's burst_rate).
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
- All rules now: 14 official (per the spec) + 1 bonus (mass_file_write_ransomware,
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
- THIS COMPLETES ALL 24 STEPS OF THE DETECTION ENGINE (L2's full scope per the
  spec): 14 rules across 9 MITRE techniques, dedupe, ML seam, incidents with
  audit trail, IOC matching, and MITRE coverage tracking - all built, tested, and
  measured (precision/recall/F1 = 1.000/1.000/1.000).

## Closed the test coverage gap for Phase 2 rules

- Reading through the repo again found that
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
- This closes the last known gap from that check: rule count, file
  organization, and test coverage all now match the spec exactly.

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
- Rules seen firing on the live sensor so far: connect_after_exec, network_parent_shell, suid_backdoor, backdoor_listener, ransomware_burst (L2 tuning runs) plus kernel_module_load and code_injection_rwx. That is 7 of 14. The other 7 are only proven on mock events and in tests.
- strace -p on a sleeping process gave 2 PTRACE events.
- Added samples/events.jsonl: 160 events from a 45 s and a 20 s capture, lab commands only, 11 of the 12 event types in docs/sensor-contract.md. CORRELATED is missing because it needs --correlate. 42 of the first 192 lines were Firefox profile paths, dropped, and the username and hostname replaced. Replays through server.ingest with 0 bad lines and 3 alerts, all from the lab commands (bind on 127.0.0.1, modprobe dummy, rwx mprotect).
- Still open: reads of /etc/shadow still make no event. rm -rf reports relative paths. A failed exec during a PATH search still shows up as an EXEC event. Exec blocking is not done, only ptrace. 7 rules have never fired live.

## 2026-10-28 - L5 console, session 1 (import, restyle, contract fixes, Linux build)
- Imported Anit Chakraborty's console into console/ on l5-console. Restyled all 14 views to a compact layout with a labeled sidebar. Login page kept as Anit made it.
- Removed data that was shown as if real: placeholder bars in Analytics, invented seed users and webhook in Settings, and "all active, 0 hits" in the Rules fallback. Pages that only keep browser state now say so on the page.
- Rules: the on and where lines are now generated from server/rules/*.yml at main 1f3506c. The old page had made-up conditions, ransomware_burst at 15 instead of 25, and T1059 filed under Command and Control.
- Evaluation read score, threshold, model and status from /api/anomaly. Those names exist only in Anit's stub, not in the contract. It now reads scores[] and is_anomaly.
- usePoll wrote to a ref during render. Moved into an effect. eslint src is clean.
- npm ci and vite build pass on the Ubuntu VM with Node 22.23.4 (built in 993 ms). npm audit shows 6 findings, all in dev tooling, 0 with --omit=dev.
- Only checked in the browser against Anit's stub backend. Never run against the real L4 API or the live sensor.
- Still open: Incidents still reads mock.js. Threat Intel, Enforcement and Settings keep state in the browser only. The /api/mitre shape is not agreed with L4. Attack Range ids are not checked against L4's sim whitelist, and the simulation scripts are not written. No README or DEMO_SCRIPT yet.

## 2026-10-31 - L3 anomaly layer, review and integration
- Took the ML layer as delivered by Manabendra and committed it under his name, his half of features.py added below Subhrajit's ProcessState. It trained and saved, but extract_features read a dict nothing in the engine builds, hour_of_day came from the kernel ts (seconds since boot, so it was hours since boot, not the time of day), the autoencoder threshold was never saved, models landed in whatever folder it ran from, and the attack set was 100 copies of one process.
- Rewrote the L3 half of server/features.py against ProcessState. gen_baseline now feeds synthetic events through ProcessState and capture_baseline replays sensor lines through the Engine, so training rows come from the same code as live scoring.
- server/ml_anomaly.py hands the engine an AnomalyModel: score() returns the contract keys plus confidence, threshold.json stores the feature names and a reordered list is refused, TensorFlow is optional for both training and loading. A model trained on synthetic data is gauge only, and engine.py now checks that before raising ML-ANOM.
- sklearn has a fixed cost per call that was too slow for scoring every event, so single rows walk the trees as numpy arrays. Same scores, timings in results.md.
- Report from my run is in docs/results.md. The synthetic model flags most of samples/events.jsonl and lifetime_sec is far outside training, the train/serve skew a real baseline is meant to fix. The forest never split on exec_count or ptrace_count, both constant in the synthetic data.
- Still open: real host baseline on the VM; gen_replay.py, evaluate.py and measure.py; UNLINK, RENAME, MPROTECT, MODULE, BIND and CHMOD are not in the vector; hour_of_day is raw 0 to 23; anomaly scores live in memory only until L4 stores them.

## 2026-11-01 - L3 anomaly layer, real host baseline on the VM
- Three captures of normal use on the VM, about 15 minutes each, 0 dropped events: 5181, 14593 and 5449 events.
- A model trained on one session flagged 73.07% of the next session while flagging 4.7% of its own. It learned a quarter hour, not the machine.
- Reworked the preprocessing: log scale for counts and rates, age features capped, constant features plus uid and hour_of_day dropped. Five averaged autoencoders instead of one, and learned limits on seven features for what the forest cannot see past its training range.
- Trained on sessions 1 and 2, checked on session 3 which it never saw: 3.43% of events flagged, from 12 of 633 processes, mostly LibreOffice and Rhythmbox, which were new to it. Holdout false alarms 1.22% to 2.43% over the extra seeds, synthetic attacks 78% to 90%. 0.35 ms per event on the VM.
- That is still 20 ML alerts in 15 minutes of normal use, so ML-ANOM stays off by default and the score is a gauge. The forest flagged nothing in the final run; detection comes from the autoencoder and the limits.
- Still open: privesc only 37.5% for the model (L2 suid_shell covers it), L4 loader must pass alerting=False unless --ml-alerting, more varied capture sessions, six event types still outside the vector.

## 2026-11-01 - L4 backend, review and integration
- Took Rishabh's backend as delivered and committed it under his name. It could not run from the repo root, ignored HIDS_SECRET_KEY, seeded no user, and LIMIT -1 skipped the 1000 cap. Fixed those.
- Wired it to the L2 engine with a reorder buffer on kts and the ioc, incidents, responder fan-out. It loads the L3 model from server/ml with alerting off unless --ml-alerting, and starts without it when the files or packages are missing.
- Engine score rows now keep ae_anomaly, limit_anomaly and over_limit, so Detection shows why a row was flagged.
- Console logs in for real, reads incidents from the API, and the gauge shows autoencoder error over threshold.
- Replay on Windows, no model loaded there: ingest: 160 events, 3 alerts, 0 bad lines, 0 engine errors, 0 own events dropped, 0 reordered, 0 late, 0 fan-out errors, 0 scored by ML, 0 flagged
- Live on the VM, about 16 minutes by the wall clock, trained model loaded with alerting off: ingest: 29420 events, 11 alerts, 0 bad lines, 0 engine errors, 10856 own events dropped, 0 reordered, 0 late, 0 fan-out errors, 29420 scored by ML, 20392 flagged. The loader reported dropped events: 0.
- The model flagged 20392 of 29420 events (69.3%) in that run, and 4789 of 6393 (74.9%) in a second live run with no console open.
- Replaying L3's session 3 capture through the same server: 5449 scored by ML, 187 flagged (3.43%), the same as L3's own replay. So L4 scores the way L3 does, and the gap is in the live data, which the training captures do not cover yet. ML stays gauge only until they do.
- Two of the 11 alerts, code_injection_rwx and ransomware_burst, came from the node process of the console dev server and are not attacks.
- Still open: Phase 2 alerting, reports, navigator, users, iocs and enforcement endpoints. Threat Intel still shows sample data. Anomaly scores and their counts live in memory only and reset on restart. No event retention.

## 2026-11-02 - L1 kernel sensor, session 6
- EXEC is now emitted only when execve or execveat returned 0. The entry is saved per tgid when the call starts and sent when it returns. env hids_no_such_cmd gave 13 EXEC events before (12 of them failed PATH lookups) and 1 after. comm is still the parent's name and ts is still when the exec was asked for.
- New event type READ for read-only opens of /etc/shadow, /etc/gshadow, /etc/sudoers and SSH private keys. The loader fills an exact-match map at startup, 3 paths on this VM (no keys). sudo cat /etc/shadow gave 0 events before and READ events from cat and sudo after. This is a new type value, so L2, L3, L4 and L5 have to know about it.
- OPEN, UNLINK, RENAME and CHMOD paths are absolute, resolved in the kernel from the dirfd or the cwd with bpf_loop (new bpf/path.h). A test with relative paths plus an rm -rf of 50 files: 57 of 109 paths relative before, 0 of 109 after.
- RENAME keeps both full paths. It reserves a 1080 byte record while every other type stays at 168 bytes. Two paths of about 120 characters each: 122 characters with both cut before, 244 and complete after. The JSON keys did not change, but a RENAME detail can now be up to 1026 characters.
- ips_enforce takes an optional path and blocks exec of that file with lsm/bprm_check_security. It stores the device and inode, so ./name and hard links are blocked too. /tmp/hids_blocked (a copy of /bin/true): exit 0 before, Operation not permitted and exit 126 after. /bin/true still ran and strace on the protected pid was still denied. Nothing is blocked when no path is given.
- The empty-detail OPEN at bash startup went away with the absolute paths and needed no code of its own: 3 empty out of 106 OPEN events on the old build, 0 empty out of 115 on the new one.
- samples/events.jsonl: the machine id in 9 journal paths replaced with 32 zeros. Still 160 lines and 3 alerts.
- 5 minute idle run, old and new build at the same time over the same window: OPEN 79 and 78, RENAME 33 and 34, CONNECT 28 and 28, UNLINK 24 and 24, MPROTECT 14 and 14, EXEC 1 and 1, CHMOD 1 and 1, READ 0 and 0, dropped events 0 on both. An idle box shows no EXEC difference. The drop only appears when something searches the PATH. The only READ events seen at all were sudo reading /etc/shadow and /etc/sudoers during my own commands.
- 216 tests passed after every item. Last live run through the full system: ingest: 40 events, 0 alerts, 0 bad lines, 0 engine errors, and the loader reported dropped events: 0.
- Still open: samples/events.jsonl has no READ events and the old RENAME form until the full re-capture at the end of the project. READ matches the path as the program passed it, so a relative open of /etc/shadow is missed and keys created after the loader starts are not watched. I did not measure whether cron reads these files. The live run after the absolute path change raised 1 alert and I did not look at which rule. README still shows the old ips_enforce usage. The exec block is by inode, so a copy of the file is not blocked and replacing the file drops the block.

## 2026-11-02 - L2 detection engine, finish session after L1 session 6
- credential_access matches READ as well as OPEN and covers /etc/sudoers. Skipped on exec path: /usr/bin/sudo, /usr/bin/su, /usr/libexec/gdm-session-worker, and cron through exe_path because cron's job forks never exec. Those were the only shadow readers in a 7337 event idle run.
- READ added to EVENT_TYPES so since.read loads. READ does not count toward ProcessState.types, so ML feature 0 keeps the meaning L3 trained on. 8 of 537 processes in the idle run had it raised by 1 before.
- ransomware_burst: unlinks count only for a process that opened a file for writing. rm -rf of 30 and 60 files no longer raises critical, a write then delete loop still does. /tmp/node-compile-cache/ is routine churn after npm raised the rule on 545 cache renames.
- More exec path exclusions: whoopsie for connect_after_exec, LibreOffice and node for code_injection_rwx, su for log_tampering (it writes /var/log/btmp on a failed login).
- An EXEC with an empty path now clears exe instead of keeping the old program. Found while proving suid_shell: execl on a string literal gives an empty EXEC detail from the sensor. 1 of 528 EXEC in the idle run (snap-confine). Sensor side handed to L1.
- All 14 rules fired on the live sensor: 13 in one run (2261 events, 18 alerts), suid_shell with a launcher that copies the path to the stack first. Commands in docs/live-triggers.md.
- Fresh idle run after all changes, 14:52 to 15:20 with cron.hourly inside: 3365 events, 0 alerts. 247 tests pass, measure_rules 14 of 14 and 0 of 30 benign, samples replay still 160 events and 3 alerts.
- Still open: suid_shell misses the string literal launcher until L1 fixes the EXEC path. credential_access matches the path as typed, so a relative read like cd /etc && cat shadow is missed, not tested live. Thunderbird and whoopsie exclusions not rechecked on fresh data. IPS BLOCK lines are skipped as bad lines. samples/events.jsonl has no READ until the final re-capture.

## 2026-11-02 - L1 kernel sensor, three limits found by L2
- EXEC with an empty detail: when the page holding the exec path was not loaded yet, the read at sys_enter failed. A handler on sched/sched_process_exec now fills an empty path from the kernel's own copy. Test program with the path alone in an untouched 64 KB block: 5 of 5 EXEC empty before, 0 of 5 after. Normal execs keep the path as typed.
- Relative READ: a read-only open with a relative path is resolved with abs_path before the lookup. cd /etc && cat shadow: READ from cat 1 before (only the absolute command), 2 after. cat ./shadow is still missed because . is not normalized.
- SSH keys created after start: the loader now re-reads the sensitive list every 10 seconds. A key created after start and read 12 seconds later: 0 READ before, 1 after. The .pub file is still skipped.
- 247 tests passed after each fix, 0 build warnings, full system runs with 0 bad lines and 0 engine errors and 0 dropped events. One live run with the relative cat shadow raised 1 alert, which rule was not checked.
- Still open: a key read within 10 seconds of being created is missed. ./ and ../ forms of a sensitive path are missed. samples/events.jsonl still predates all of today's sensor changes.

## 2026-11-02 - L2 detection engine, retest after the L1 fixes
- Ran the three L1 sensor fixes from main 5260149 through the engine. No L2 code or rule changed. One live run: 241 events, 6 alerts, 0 bad lines, 0 engine errors, 0 dropped events.
- cd /etc && cat shadow: READ detail is /etc/shadow and credential_access fired, as uid 1000 and again under sudo. Four sudo processes read shadow and sudoers in the run and none alerted, so the alert L1 saw came from cat.
- SSH key created after the sensor started and read 12.0 s later: 1 READ, 1 alert.
- execl("/bin/sh") on a string literal from a setuid launcher: EXEC detail /bin/sh, suid_shell fired. 0 empty EXEC details in the run.
- Still open: cat ./shadow is missed (L1's measurement, not tried here). A key read within 10 s of creation is missed. snap-confine not retested. A key that exists at sensor start never tested. samples/events.jsonl predates all of today's sensor changes.
- server/ioc.py did not look at READ events, so a path IOC such as /etc/shadow never enriched a credential_access alert raised by a READ. Added READ to PATH_EVENTS. New test fails without the change. 248 tests pass.

## 2026-11-02 - L3 anomaly layer, retrained on the new sensor
- The 2026-11-01 model was trained on captures from the old sensor, before L1 session 6. Rebuilt the loader: 248 tests passed, a test read of /etc/shadow gave 3 READ events, 0 dropped.
- Old model live on the new sensor: 6112 events, 119 flagged (1.95%), 0 dropped. A quiet session with 42 processes, not comparable with the 69.3% and 74.9% from 2026-11-01.
- A stream saved with tee holds the server's own events, which the live pipeline drops by pid. With those removed the replay matched the live server exactly: 2185 of 11319 and 284 of 10716.
- Three new sessions: new1 (6112 events, 633 rows), new2 (sensor only, 36235 events, 2407 rows), new3 (console open, 11319 events, 1347 rows). The old captures are not used any more.
- Trained on new1 and new2 first. Live on new3: 19.30% flagged, almost all Firefox's cache and socket threads while the console polled the API. The old model flags 64.59% of the same file. Added new3 and trained again on 4387 rows.
- Final check on a session none of the models saw, live, console open, 16.3 min: 10716 events, 284 flagged (2.65%), 4 processes, 4 ML alerts if alerting were on (15 per hour), 0 rule alerts, 0 dropped. On the same file the old model flags 59.15% and the two session model 34.90%.
- Synthetic attacks over the four extra seeds: 64% mean (58 to 74). reverse_shell 93.75%, injection and scanner 100%, mass_write 17.5% (0 to 60), privesc 8.75%. The last two are not reliable on the ML; ransomware_burst and suid_shell cover them.
- ML alerting stays off by default. server/app.py already loads the model with alerting off unless --ml-alerting is given.
- Still open: model files only on the VM, the anomaly_scores table is never written, busy Firefox is 95% of what gets flagged, READ is not a feature, samples/events.jsonl re-capture at the end.

## 2026-11-02 - L4 backend, finish session
- READ and a 1026 character RENAME detail pass through the pipeline, the database and /api/events unchanged. New test, nothing in L4 needed changing.
- The server opened and deleted its own database files on every call and the sensor reported each one: 12579 own events in L3's 16.3 min run. db.py now hands connections back to a pool of up to 8. Same polling script, 400 requests, old db.py against new: 4043 own events in 312 s against 12 in 308 s. A pool test then found a double close that shut a pooled connection, fixed the same day.
- Dropped the anomaly_scores table. Nothing ever wrote to it and both endpoints that read it replaced the numbers with the pipeline counters. API responses unchanged.
- New endpoints: enforcement (GET, POST, action, clear), iocs (GET, POST, DELETE), users (GET, POST, DELETE, role), navigator and navigator/download, reports (summary, alerts.csv, incidents.csv, incident/<id>.html), alerting (GET, POST, test), lineage/<pid>, tree/<root>. Every route in the spec now exists, plus enforcement/action.
- Sweep of all 41 route and method pairs with empty bodies and missing ids: anonymous 2 x 200 and 39 x 401, viewer 18 x 403, analyst 12 x 403, admin no 403, no 5xx for anyone.
- Live run with the sensor: pid 1, NetworkManager and the server itself were guard_blocked through /api/enforcement/action, an ordinary sleep came back dry_run because the responder is off. The Navigator layer downloaded as valid JSON with 9 techniques. Webhook to a local receiver: the test and a real suid_backdoor alert arrived with HTTP 200, the alert with incident_id 2. backdoor_listener fired on the receiver itself, a Python script listening on 127.0.0.1:8099, which is what a bind shell looks like. ingest: 501 events, 2 alerts, 0 bad lines, 0 engine errors, 8 own events dropped, 0 fan-out errors, loader dropped 0.
- 248 tests at the start of the session, 317 at the end.
- Still open: hash IOCs are stored but never match, the sensor does not hash files. Enforcement and alerting settings changed through the API last until restart, on purpose. The layer has not been loaded into MITRE's Navigator site yet. SIM_WHITELIST waits for L5's simulation scripts. The anomaly row has no iforest_anomaly key, so the console cannot say the forest flagged an event (one line in L2's engine.py, one in L5's Detection.jsx).

## 2026-11-02 - L2 detection engine, iforest_anomaly in the anomaly row
- The anomaly score row now carries iforest_anomaly next to ae_anomaly and limit_anomaly. Additive contract change: L4 passes it through /api/anomaly unchanged, L5 can show it. New test, and the key pin in tests/test_ml_features.py updated, 318 passed. Live with the sensor and the real model (iforest+autoencoder+limits): 359 events scored, 3 flagged, all 300 rows in /api/anomaly had the key, none of those 300 was flagged, so a True value has only been seen in the unit test.

## 2026-11-03 - L4 backend, simulation whitelist
- SIM_WHITELIST holds the 8 Attack Range ids from L5's handoff next to demo. /api/sim now answers 503 when the script file is not on the server instead of a 202 that hides it, and the server log prints every run's exit code. New test checks the page's ids against the whitelist both ways, the script paths, the 503 and the logged exit code. 323 tests pass.
- Live, server only: demo gave 202 and "simulation demo exited with code 0" in the server log, reverse-shell gave 503 because its script is still on l5-console.
- Still open: until l5-console is merged, the 8 new buttons answer 503 on main. The button path with the sensor running is L5's check after it pulls this.

## 2026-11-02 - L5 console, every page on the real API
- api.jsx covers every endpoint and Rules goes through it too, so a 401 on any page sends you to the login page. Threat Intel reads /api/iocs and mock.js is gone. Enforcement reads /api/enforcement. Settings reads /api/users, /api/apikeys and /api/alerting.
- The role comes from /api/me. Buttons that need analyst or admin are greyed out with the reason. The server's 403 is what actually stops a viewer.
- Threat Intel against the live server: add gave 201, the same IOC again 409, a bad entry 400, delete 200.
- Settings: the test alert reached a local webhook receiver as JSON, once the URL was saved.
- Evaluation showed 0 ML alerts because it looked for a rule named ML-ANOM. ML alerts carry rule ml_anomaly and technique ML-ANOM. It counts by technique now.
- Overview rows open on click, and the event tape stops while the mouse is over it. Before, rows moved away before they could be clicked.
- Detection says which check flagged a row (forest, autoencoder, limits) and keeps the newest flagged row seen since the page opened. With --ml-alerting and the real host baseline model, 23:54: LS Thread pid 114149 flagged by the autoencoder only, recon error 0.6170 = 1.03x threshold, forest score 0.0269, not flagged. The same pid raised one ml_anomaly alert on a Firefox cache RENAME. About 14 events were scored a second, so the last 300 scores covered about 20 s. No forest flag seen live.
- With --ml-alerting, during a loop that listed a folder, wrote the date to a temp file and deleted it every 5 seconds: 1251 of 3583 scored events flagged, 34.91%. L3's unseen session gave 2.65%. Not explained, to check with L3.
- ATT&CK Map reads only {techniques:[...]} from /api/mitre and showed all 9 techniques.

## 2026-11-03 - L5 console, attack range, demo script, READMEs, IPS check
- Eight simulation scripts in server/simulations/, standard library only. They refuse to run as root and touch only loopback, files under /tmp and one marker file in ~/.config/autostart that is deleted at once. Rootkit, credaccess and privilege escalation ask the kernel for things it refuses (finit_module, reading /etc/shadow, setuid 0), and the sensor reports the attempts anyway because its hooks are at syscall entry.
- First run by hand with the live sensor, 00:09: seven of eight raised what they were meant to. Backdoor raised only suid_backdoor, because the sensor drops binds to port 0. The script now listens on 127.0.0.1:8099, or the next free port up to 8109. Second run 00:16: all eight as intended, each exited 0 in under 1.1 s. By hand, privilege_escalation also raised network_parent_shell, because the runner that started it had API connections open.
- After L4's whitelist (59acea2), each Attack Range button clicked once, server as the normal user, sensor attached, ML alerting off. All eight exited 0. reverse-shell connect_after_exec and network_parent_shell, privilege-escalation ptrace_then_exec and suid_shell, benign-exec-chain nothing, ransomware ransomware_burst, rootkit kernel_module_load, persistence persistence_autostart, credaccess credential_access, backdoor backdoor_listener and suid_backdoor. The page shows these now instead of what each script was designed to raise.
- In the same window, not from the buttons: snapd pid 658 raised ransomware_burst twice and persistence_autostart once, fwupdmgr connect_after_exec, and a python3 connect_after_exec after the last button, most likely the script that listed the alerts. The snapd ones look like false positives, not checked. For L2.
- tests/test_simulation_scripts.py: every whitelisted script exists and every attack script refuses root. It fails when a guard or a file is removed. At 2cd5f7f on the VM: pytest 325 passed, eslint clean, vite build 988 ms.
- Enforcement, manual request on the server's own pid 5554, active response on, dry run on: guard_blocked, "guard: that is the responder itself".
- Download layer JSON opened on mitre-attack.github.io as "eBPF-HIDS detections", the 7 alerted techniques coloured, no error. The site files some techniques under newer tactic names (Stealth, Defense Impairment) than the console's Defense Evasion.
- npm audit: 12 (7 moderate, 5 high), 0 with --omit=dev. Not fixed.
- README screenshots from a fresh database: the ransomware, credaccess and backdoor buttons gave 4 alerts in 3 incidents. Backdoor's two alerts share one incident because they came from one pid.
- IPS check for the demo, 23:44: bpf is in /sys/kernel/security/lsm and make ips built clean. ips_enforce protecting a sleep pid, with /tmp/hids_blocked (a copy of /bin/true) as the blocked path: sudo strace -p got Operation not permitted, /tmp/hids_blocked Operation not permitted with exit code 126, /bin/true exit code 0, one BLOCK line per denial. After Ctrl+C, exit code 0 and strace attached. Added to docs/DEMO_SCRIPT.md as step 7.
- Wrote docs/DEMO_SCRIPT.md, console/README.md and the top-level README.
- Still open: the replay fallback has not been run on the VM. A forest-only flag has not been seen live. A real alert sent by webhook was only seen in L4's run. The 34.91% ML figure. The snapd hits. No tests for the React code.
