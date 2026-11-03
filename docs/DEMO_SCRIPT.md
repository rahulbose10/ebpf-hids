# Demo script

The order I run the viva demo in, on the Ubuntu VM, from main after l5-console is merged. Every step was seen working on the VM on 2026-11-02 or 2026-11-03 unless the step says otherwise. If the sensor will not load on the day, skip to "Fallback without the sensor" at the bottom.

Three windows open before starting: terminal 1 for the sensor and server, terminal 2 for helpers, Firefox.

## Before the viva

Once, an hour before, not in front of anyone.

```sh
cd ~/ebpf-hids
git checkout main
git pull origin main
source .venv/bin/activate
python3 -m pytest -q
export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"
cd console && npm ci && npm run build && cd ..
```

pytest gave 325 passed on 2026-11-03. The console is served from console/dist, which is not in git, so it has to be built on this machine after every pull or Flask serves an old build.

Write the webhook receiver for step 8 to /tmp. It prints every POST it gets and nothing else.

```sh
cat > /tmp/hook.py <<'EOF'
import http.server


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        print("HOOK", body.decode(), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", 9000), Hook).serve_forever()
EOF
```

## 1. Start the sensor and the server

Terminal 1:

```sh
cd ~/ebpf-hids
source .venv/bin/activate
sudo -v
rm -f data/hids.db*
export HIDS_ADMIN_PASS='pick one'
sudo ./loader/loader 2>/dev/null | python3 -m server.app 2>&1 | tee /tmp/server.log
```

Wait for `Running on http://127.0.0.1:5000`. `sudo -v` comes first because otherwise the sudo password prompt gets buried under the server output.

Say: only the loader runs as root. It loads the eBPF programs, most of which sit on syscall entry tracepoints, and writes one JSON line per event. The server reads those lines on stdin, runs the YAML rules and the ML scorer, keeps alerts and incidents in SQLite and serves the console. The server runs as my normal user.

## 2. Overview

Open http://127.0.0.1:5000 and log in as admin.

The event tape is the live stream. Move the mouse over it and it stops. Click a long RENAME row and the full detail opens.

Say: ts is kernel time in seconds since boot, taken inside the BPF program, and nothing on the way up replaces it with wall clock. Most rows are Firefox itself and the console polling 127.0.0.1:5000.

## 3. One attack end to end

Attack Range, Run simulation on Ransomware burst. Terminal 1 prints `simulation ransomware exited with code 0`. Then Detection: ransomware_burst is at the top of the alert feed, click it for the investigation panel. Then Incidents: the alert is in a case, and the case has a Printable report link.

What each button raised on 2026-11-03, one click each, ML alerting off:

| Button | Rules |
| --- | --- |
| Reverse shell shape | connect_after_exec, network_parent_shell |
| Privilege escalation | ptrace_then_exec, suid_shell |
| Benign exec chain | nothing, it is the control case |
| Ransomware burst | ransomware_burst |
| Rootkit / module load | kernel_module_load |
| Persistence foothold | persistence_autostart |
| Credential access | credential_access |
| Backdoor listener | backdoor_listener, suid_backdoor |

Say: the script writes 30 files under /tmp and renames each to .locked. The rule counts renames and deletes per process inside 5 seconds and fires at 25. The scripts refuse to run as root, and the server only starts names on its whitelist.

## 4. Refused calls are still caught

Click Rootkit / module load, then Credential access.

Say: as my user the kernel refuses both, there is no CAP_SYS_MODULE and /etc/shadow is not readable. The alerts still fire because the hooks sit on syscall entry, before the kernel decides. The sensor reports the attempt, not only the success.

## 5. ATT&CK Map and Navigator

ATT&CK Map shows the techniques alerted this session. Download layer JSON, open https://mitre-attack.github.io/attack-navigator/, Open Existing Layer, Upload from local, pick the file. The alerted techniques come up coloured. Needs internet on the VM.

The site files some techniques under newer tactic names (Stealth, Defense Impairment) than the console's Defense Evasion. Same technique ids.

## 6. Enforcement guards

Terminal 2:

```sh
pgrep -f "python3 -m server.app"
```

Enforcement page: Active response on, Dry run stays on. Under Act on one process, request pid 1, then the pid of NetworkManager (`pgrep NetworkManager`), then the server pid from above. All three come back guard_blocked, with the reason in the last column. For the server pid the reason is `guard: that is the responder itself`. Turn Active response off again.

Say: dry run decides and logs but sends no signal. A real kill needs active response on and dry run off, and then it is SIGTERM, then SIGKILL after the grace period. The guards run first: nothing below pid 300, nothing on the never-kill list, nothing in the server's own process tree. Settings last until the server restarts.

## 7. Roles

Settings, add a user with role viewer. Log out, log in as that user. Rule toggles and the Run simulation buttons are greyed out. Log back in as admin.

Say: greying out is only convenience. The server checks the role on every route and answers 403, and tests/test_endpoints.py calls every API route as anonymous, viewer, analyst and admin and checks the answer.

The 403 itself was not shown live, only through the tests.

## 8. Webhook alerting

Terminal 2:

```sh
python3 /tmp/hook.py
```

Settings: tick Send notifications for new alerts, Webhook URL `http://127.0.0.1:9000/`, Save, then Send test alert. Terminal 2 prints a `HOOK {...}` line.

Then click Backdoor listener or any button whose rule has not fired in the last 5 minutes, since the throttle is 300 s per rule and the default minimum severity is high. A real alert should print a second HOOK line. I only watched the test alert arrive myself. L4 saw a real alert delivered in its live run.

Ctrl+C in terminal 2 when done.

## 9. Stop

Ctrl+C in terminal 1. The server prints its ingest: line with the event and alert counts.

## If asked about the ML

The ML only scores by default and raises no alerts. Restart step 1 with `python3 -m server.app --ml-alerting` and the Detection page shows which check flagged a row (forest, autoencoder or limits) and keeps the newest flagged row on screen.

Be straight about the numbers. L3 measured 2.65% of rows flagged on a session no model had seen. During a synthetic activity loop on 2026-11-02 it flagged 34.91%, and it is not known why. The only flagged row looked at closely was flagged by the autoencoder alone, at 1.03 times its threshold. A forest-only flag has not been seen live, only in a unit test.

## Fallback without the sensor

If the loader will not load:

```sh
cd ~/ebpf-hids
source .venv/bin/activate
rm -f data/hids.db*
export HIDS_ADMIN_PASS='pick one'
python3 -m server.app --replay samples/events.jsonl
```

This replays 160 captured events with 3 alerts, then the server keeps running with no new events. The pages read the replayed data the same way. Do not click Attack Range, the scripts run but nothing is watching. The top bar says sensor offline.

TODO: this was run on a dev copy, not yet on the VM. Run it once during rehearsal.

## Rehearsal log

| Date | Run | What went wrong | Fixed |
| --- | --- | --- | --- |
| TODO | full run with sensor | | |
| TODO | fallback | | |
