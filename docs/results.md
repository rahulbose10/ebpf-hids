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

# L3 anomaly layer

## How to reproduce

Synthetic, runs anywhere:

    pip install -r requirements.txt -r requirements-ml.txt
    python -m scripts.train_ml --sweep --check samples/events.jsonl

Real host, on the VM. The captures stay on the VM because they hold real paths; only the .npy matrices of numbers are used for training.

    python3 -c "import time; print(round(time.time() - time.monotonic()))"
    sudo ./loader/loader > server/ml/captures/session3.jsonl
    python -m scripts.capture_baseline server/ml/captures/baseline.jsonl --boot-epoch <epoch> -o server/ml/baseline.npy
    python -m scripts.train_ml --baseline server/ml/baseline.npy server/ml/session2.npy --repeat 4 --check server/ml/captures/session3.jsonl --boot-epoch <epoch>

The first line prints the boot time as a unix epoch, which turns the kernel ts (seconds since boot) into a clock time. It changes on every reboot. The full report of the last run is written to server/ml/last_report.txt.

## Synthetic baseline (Windows, 2026-10-31)

This is the first rewrite of the layer, before the changes described under the real host baseline below (contamination was 0.02, one autoencoder, no learned limits, hour_of_day still in the model). Kept because it shows the train/serve skew that made the real baseline necessary.

    L3 training report
      data source        synthetic (2500 rows, scripts/gen_baseline.py, seed 7)
      train / holdout    2125 / 375
      contamination      0.02
      autoencoder        yes, threshold 1.3289 (99th percentile of training error)
      holdout normal     forest 2.93% | autoencoder 0.80% | combined 3.20% flagged
      synthetic attacks  forest 50.00% | autoencoder 72.00% | combined 82.00% flagged (100 rows, 5 kinds)
      mean iforest score normal 0.1432 | attack 0.0362
      lifetime_sec       training max 4.40 s
      features never split on: exec_count (training std 0.000), ptrace_count (training std 0.000)
      edge probe         500 connects on a median process: forest 0.155 (normal), autoencoder error 4841.1 vs threshold 1.33
      score time         0.22 ms per event (sklearn decision_function on one row 6.02 ms)
      contamination sweep, forest only, same holdout:
        contamination 0.02 -> holdout false positives 2.93%
        contamination 0.05 -> holdout false positives 4.00%
        contamination 0.10 -> holdout false positives 8.27%
      replay samples/events.jsonl: 160 events from 24 processes scored through the engine
        flagged            forest 46.88% | autoencoder 79.38% | combined 81.88%
        mean iforest score 0.0148
        furthest from training (max z): lifetime_sec 142.6, setuid_count 78.0, connect_rate 34.3

The holdout false positive rate only says the model learned the synthetic distribution. The replay of samples/events.jsonl shows what that is worth on a real host: most real events get flagged and lifetime_sec lands far outside training, because the synthetic processes never live longer than 4.4 s while gnome-shell and Firefox run for minutes. That is why a synthetic model is gauge only.

The synthetic attacks come from the same generator code, so detecting them proves the pipeline works end to end, not that real attacks look like this. That is still true of the attack numbers in the real host section.

## What changed before the real baseline

Count and rate features go through log1p, so one busy process does not stretch the scale for everything else. Features that only grow with age (lifetime, total writes, total connects, distinct files and destinations) are capped at the largest value seen in training, so a process is not suspicious just for being old. Features that never moved in training are dropped, and so are uid and hour_of_day: uid flips to 0 inside every sudo, and hour_of_day made the model flag everything at an hour it had not seen.

The forest only cuts between the smallest and largest value it saw, so 500 connects scores like the largest count in training. Two checks cover that. The autoencoder is now five small networks averaged (one network gave anywhere from 0 to 90 percent on mass_write depending on the seed), and seven rate and count features have a learned limit, 1.5 times past the largest value seen in training. A process that never called ptrace in training trips the limit on its first ptrace.

The verdict is forest OR autoencoder OR limits.

## Real host baseline (VM, Ubuntu 22.04, kernel 6.8, 2026-11-01)

Three captures of normal use, about 15 minutes each, `sudo ./loader/loader > file`, dropped events 0 every time. Firefox with several tabs, Thunderbird, terminal work, ping, curl, sudo apt update. The third session also had LibreOffice and Rhythmbox open. No attack sims in any of them.

    session 1    5181 events    1469 training rows
    session 2   14593 events    1812 training rows
    session 3    5449 events    633 processes, never used for training

capture_baseline replays each file through the Engine, so the rows come from the same code as live scoring. Processes with a single event are skipped and a long lived process gives at most 50 rows, so Firefox does not drown out everything else.

### One session is not enough

The model trained on session 1 alone, scored on session 2, flagged 73.07% of events and would have raised about 160 ML alerts per hour. The same model on its own capture flagged 4.7%. It had learned that one quarter hour, not the machine. This was measured with the code before the last commit (hour_of_day was still inside the forest then).

Reversed, with the current code: trained on session 2 alone, scored on session 1, 8.22% flagged. Session 2 was the busier capture and covers more of what the machine does, which is the hint that more varied training data is the fix, not a different model.

### Trained on sessions 1 and 2, checked on session 3

    python -m scripts.train_ml --baseline server/ml/baseline.npy server/ml/session2.npy --repeat 4 --check server/ml/captures/session3.jsonl --boot-epoch 1793521624 2>&1 | tail -40

The top of the report was cut by tail and is in server/ml/last_report.txt. What was printed:

      synthetic attacks  forest 0.00% | autoencoder 58.00% | limits 36.00% | combined 78.00% flagged (100 rows, 5 kinds)
        reverse_shell    forest 0.00% | autoencoder 90.00% | limits 0.00% | combined 90.00%
        privesc          forest 0.00% | autoencoder 0.00% | limits 0.00% | combined 0.00%
        mass_write       forest 0.00% | autoencoder 100.00% | limits 0.00% | combined 100.00%
        injection        forest 0.00% | autoencoder 0.00% | limits 100.00% | combined 100.00%
        scanner          forest 0.00% | autoencoder 100.00% | limits 80.00% | combined 100.00%
      mean iforest score normal 0.2054 | attack 0.1208
      lifetime_sec       training max 1046.00 s
      features never split on: none
      edge probe         500 connects on a median process: forest 0.206 (normal), autoencoder error 1.88 vs threshold 0.49, limits none
      score time         0.35 ms per event (sklearn decision_function on one row 6.28 ms)
      repeated over 4 more seeds (split, forest and autoencoders all reseeded), combined verdict:
        holdout normal     mean 1.77% (min 1.22%, max 2.43%)
        synthetic attacks  mean 85.00% (min 82.00%, max 90.00%)
          reverse_shell    mean 88.75% (min 80.00%, max 100.00%)
          privesc          mean 37.50% (min 20.00%, max 65.00%)
          mass_write       mean 98.75% (min 95.00%, max 100.00%)
          injection        mean 100.00% (min 100.00%, max 100.00%)
          scanner          mean 100.00% (min 100.00%, max 100.00%)
      replay server/ml/captures/session3.jsonl: 5449 events from 633 processes scored through the engine
        flagged            forest 0.00% | autoencoder 3.43% | limits 0.00% | combined 3.43%
        flagged processes:
          soffice.bin (pid 74050): autoencoder x54
          dconf-service (pid 1441): autoencoder x39
          soffice.bin (pid 74075): autoencoder x13
          NetworkManager (pid 577): autoencoder x11
          systemd-resolve (pid 478): autoencoder x10
          configmgrWriter (pid 74075): autoencoder x8
          rhythmbox (pid 73975): autoencoder x6
          thunderbird (pid 73763): autoencoder x5
          curl (pid 75762): autoencoder x5
          curl (pid 75746): autoencoder x3
          nautilus (pid 73938): autoencoder x2
          glean.dispatche (pid 2351): autoencoder x2
          pool (pid 74020): autoencoder x2
          configmgrWriter (pid 74050): autoencoder x2
          firefox (pid 2351): autoencoder x2
        ML alerts it would raise (engine dedupe, 60 s per process): 20 over 14.9 min of capture, 81 per hour
        furthest from training (max z): connect_rate 5.6, setuid_count 5.4, distinct_files_written 3.8
      saved              /home/vesper/ebpf-hids/server/ml

On a session it never saw, 3.43% of events were flagged, against 73.07% for the single session model. They came from 12 of the 633 processes; the list has 15 lines because three of them show up under two thread names. Over the four extra seeds, holdout false alarms stayed between 1.22% and 2.43%, and synthetic attacks were between 78% and 90% across all five runs.

Most of what got flagged is new rather than hostile. LibreOffice (soffice.bin and its configmgrWriter thread) and Rhythmbox were opened in session 3 and were not running in either training session. A model of normal behaviour flags a program it has never seen, which is the job. The two curl processes were ones I ran by hand in a second terminal. dconf-service, NetworkManager and systemd-resolve are system daemons whose connect and write bursts went past what the training sessions showed (connect_rate at 5.6 standard deviations is the furthest feature).

The forest flagged nothing in this run, normal or attack. Its score still feeds the console gauge, but the detection comes from the autoencoder and the limits.

privesc is the weak spot at 37.5% on average. The model only sees counts and rates, and a short sudo looks like any other short process that becomes root. The suid_shell rule in L2 is what catches that case. In the same way, a reverse shell is caught by the network_parent_shell rule whatever the model says.

### Decision: ML alerting stays off by default

20 ML alerts in 14.9 minutes of normal use is too many for an alert queue where the L2 rules raised 0 over 30 minutes. 81 per hour also overstates it: the engine repeats an alert for the same process every 60 seconds, so soffice.bin open for ten minutes counts several times. Either way it is noise for whoever watches the console.

So the anomaly score is shown per process as a gauge, and ML-ANOM alerts only when the server is started with --ml-alerting. A model trained with --baseline turns alerting on by itself (data_source "baseline"), so the L4 loader has to pass alerting=False unless that flag is given. TODO: do that when the model is hooked into server/app.py.

## Scoring cost

The engine scores on every event, and sklearn's decision_function has a fixed cost per call that is too slow for bursts. score() walks the 200 trees as numpy arrays for single rows and runs the autoencoder's dense layers as plain matrix products, so TensorFlow is only needed for training. tests/test_ml_anomaly.py checks the single row path against sklearn. On the VM: 0.35 ms per event against 6.28 ms for sklearn on one row.

## Still open

Three sessions on one VM with one user is a small sample. A longer and more varied capture (a full working day, package installs, a build) would most likely bring the false alarm rate down further, but that is a guess until it is measured.

UNLINK, RENAME, MPROTECT, MODULE, BIND and CHMOD are not in the feature vector, so the model is blind to them. The rules see them.

Anomaly scores live in memory only until L4 stores them.
