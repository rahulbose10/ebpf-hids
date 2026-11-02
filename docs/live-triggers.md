# Live triggers for the 14 L2 rules

Harmless triggers that fired every rule on the real sensor on 2026-11-02 (Ubuntu 22.04, kernel 6.8). Everything stays on loopback or under /tmp/lab17, except two empty files in /var/log and /etc that are deleted right after. The numbers from that run are in docs/results.md.

Run `sudo -v` first in the terminal you trigger from. On the day, a sudo password prompt in the middle of a pasted block swallowed the lines after it and half the block never ran.

## Sensor

Terminal 1, repo root, venv active. Stop it with Ctrl+C when the triggers are done.

```sh
mkdir -p ~/hids-runs
sudo ./loader/loader | tee ~/hids-runs/all14.jsonl | python -m server.ingest > ~/hids-runs/all14-alerts.jsonl 2> ~/hids-runs/all14-ingest.err
```

## Network: backdoor_listener, connect_after_exec, network_parent_shell, download_and_execute

```sh
mkdir -p /tmp/lab17/www
printf '#!/bin/sh\ntrue\n' > /tmp/lab17/www/payload.sh
/usr/bin/python3 -m http.server 8000 --bind 127.0.0.1 --directory /tmp/lab17/www > /dev/null 2>&1 &
SERVER=$!
sleep 2
/usr/bin/python3 -c "import socket, os; socket.create_connection(('127.0.0.1', 8000)); os.system('true')"
sleep 1
curl -s -o /tmp/lab17/payload http://127.0.0.1:8000/payload.sh
chmod +x /tmp/lab17/payload
/tmp/lab17/payload
sleep 1
kill $SERVER
```

## Files: ransomware_burst, log_tampering, persistence_autostart, credential_access, suid_backdoor, world_writable_sensitive

```sh
mkdir -p /tmp/lab17/rw
for i in $(seq 1 30); do echo x > /tmp/lab17/rw/f$i; done
sleep 1
/usr/bin/python3 -c "import os; d='/tmp/lab17/rw'; [os.rename(d+'/'+n, d+'/'+n+'.locked') for n in os.listdir(d)]"
sleep 6
sudo touch /var/log/lab17.log
sudo rm /var/log/lab17.log
mkdir -p ~/.config/autostart
touch ~/.config/autostart/lab17.desktop
rm ~/.config/autostart/lab17.desktop
sudo cat /etc/shadow > /dev/null
touch /tmp/lab17/plain
chmod 4755 /tmp/lab17/plain
sudo touch /etc/lab17.conf
sudo chmod 666 /etc/lab17.conf
sudo rm /etc/lab17.conf
```

## Privilege, memory, kernel: suid_shell, ptrace_then_exec, code_injection_rwx, kernel_module_load

The launcher copies the shell path into a stack buffer before execl. That was needed on the first day, when a plain string literal gave an empty EXEC path and suid_shell stayed quiet. The sensor fix in 5260149 covers the literal too (see docs/results.md), so either form works now. This one stays because it is the one the 14 rule run used.

```sh
cat > /tmp/lab17/su_launch2.c <<'EOF'
#include <string.h>
#include <unistd.h>

int main(void)
{
    char path[16];

    strcpy(path, "/bin/sh");
    setuid(0);
    execl(path, "sh", "-c", "true", (char *)0);
    return 1;
}
EOF
gcc -o /tmp/lab17/su_launch2 /tmp/lab17/su_launch2.c
sudo chown root:root /tmp/lab17/su_launch2
sudo chmod 4755 /tmp/lab17/su_launch2
/tmp/lab17/su_launch2
sleep 2
/usr/bin/python3 -c "
import ctypes, os
libc = ctypes.CDLL(None)
pid = os.fork()
if pid == 0:
    os.pause()
libc.ptrace(16, pid, 0, 0)
os.kill(pid, 9)
os.waitpid(pid, 0)
os.execv('/bin/true', ['true'])
"
sleep 2
/usr/bin/python3 -c "
import ctypes, mmap
m = mmap.mmap(-1, 4096)
a = ctypes.addressof(ctypes.c_char.from_buffer(m))
ctypes.CDLL(None).mprotect(ctypes.c_void_p(a), 4096, 7)
"
sleep 2
sudo modprobe dummy
sudo rmmod dummy
```

## Score and clean up

After Ctrl+C in terminal 1:

```sh
tail -1 ~/hids-runs/all14-ingest.err
for r in connect_after_exec network_parent_shell ptrace_then_exec suid_shell ransomware_burst log_tampering persistence_autostart credential_access suid_backdoor world_writable_sensitive code_injection_rwx kernel_module_load backdoor_listener download_and_execute; do printf '%-26s %s\n' $r $(jq -r --arg r $r 'select(.rule==$r) | .rule' ~/hids-runs/all14-alerts.jsonl | wc -l); done
sudo rm -rf /tmp/lab17
```

Every rule should show 1 or more. suid_backdoor shows 2 because both /tmp/lab17/plain and the launcher get chmod 4755.
