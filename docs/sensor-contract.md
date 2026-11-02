# Sensor output contract (L1)

One JSON object per line on the loader's stdout:

    {"ts":1284.378298,"pid":4314,"ppid":4150,"uid":1000,"comm":"bash","type":"OPEN","detail":"/tmp/x"}

ts is kernel monotonic time in seconds since boot (bpf_ktime_get_ns), not wall clock. Keep it end to end.
Status lines ("sensor up", "dropped events") go to stderr, never stdout.

## detail by type

| type | detail | notes |
|---|---|---|
| EXEC | /usr/bin/ls | a program that started successfully (execve or execveat returned 0); failed attempts, such as a PATH search, are not reported; comm is still the parent's name and ts is when the exec was asked for; the path is never empty, if the program's copy could not be read yet it is taken from the kernel's own copy |
| OPEN | /tmp/x | write intent only (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND) |
| READ | /etc/shadow | read-only open of a path on the loader list (/etc/shadow, /etc/gshadow, /etc/sudoers, SSH private keys under /root/.ssh and /home/*/.ssh, not .pub); a relative path is made absolute first, so cat shadow inside /etc matches; . and .. are not normalized, so cat ./shadow is still missed; detail is the absolute path, and the loader re-reads the list every 10 seconds, so a key created later is watched within 10 seconds; a read in that gap is missed |
| CONNECT | 5.6.7.8:4444 or [2001:db8:0:0:0:0:0:1]:4444 | IPv4-mapped IPv6 is reported as plain IPv4; port 0 is never emitted |
| BIND | 0.0.0.0:4444 or [0:0:0:0:0:0:0:0]:4445 | same formats as CONNECT |
| PTRACE | target_pid=1234 | attach and seize only, refused attempts included |
| SETUID | old_uid=1000 new_uid=0 | setuid, setreuid, setresuid; threaded programs give one event per thread |
| UNLINK | /tmp/x | |
| RENAME | /tmp/old -> /tmp/new | both paths in full, up to 511 characters each, so this detail can be up to 1026 characters while every other type stays under 128 |
| MPROTECT | addr=0x7f12345000 prot=rwx suppressed=41 | exec remaps only, 1 per pid per second; suppressed = remaps dropped since that pid's previous event |
| MODULE | dummy.ko or memory_image len=12345 | memory_image means init_module from a buffer, no file |
| CHMOD | /tmp/x mode=4755 | mode is always 4 octal digits |
| CORRELATED | dst=1.2.3.4:4444 exec=/bin/sh | only when the loader runs with --correlate |

## Parsing notes

CONNECT and BIND: rsplit(":", 1), then strip [ and ] from the address.
RENAME: split(" -> ", 1).
MPROTECT: key=value pairs.
OPEN, UNLINK, RENAME and CHMOD paths are made absolute in the kernel from the directory fd or the cwd, crossing mount points. They are not normalized, so . and .. stay as written, and a path deeper than 32 directories or longer than 511 characters loses its top part. EXEC detail is still the path as the program passed it. READ detail is made absolute the same way when the program passed a relative path.
comm is at most 15 chars and can be a thread name, e.g. "DNS Res~er #12".
detail can be empty when the kernel could not read the string from the process.

## Measured on the dev VM (Ubuntu 22.04, kernel 6.8, VirtualBox)

Idle with Firefox open: 72 and 254 events per minute in two runs, the 254 mostly apt-check.
Firefox renamed 8 files in about 25 ms during normal browsing. A ransomware burst threshold has to sit above that.
Exec remaps: 514 in an idle minute before rate limiting, 21 events after.

## PTRACE_CHECK and enforcement (LSM)

PTRACE_CHECK comes from the lsm/ptrace_access_check hook, not the ptrace syscall. It fires whenever the kernel checks ptrace-level access, which includes anything reading /proc (ps, fuser), so it is far noisier than PTRACE and must never be merged with it. Rate-limited to 1 per pid per second.

    PTRACE_CHECK  target_pid=1234 mode=0x5 suppressed=7

The prevention program (ips_enforce, optional) emits its own stream, not the sensor stream:

    {"ts":..,"pid":..,"comm":"strace","action":"BLOCK","detail":"BLOCKED ptrace target_pid=1234"}
    {"ts":..,"pid":..,"comm":"bash","action":"BLOCK","detail":"BLOCKED exec path=/tmp/hids_blocked"}

Run it as sudo ./loader/ips_enforce <pid-to-protect> [path-to-block-exec]. Without a path nothing is exec-blocked. The path is resolved once at start to its device and inode, so a relative path, a symlink or a hard link to that file are blocked too. A copy is a new inode and still runs, and replacing the file drops the block. The exec detail is the path as typed by the caller, cut at 127 characters.
