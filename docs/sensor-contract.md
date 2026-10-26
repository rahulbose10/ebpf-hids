# Sensor output contract (L1)

One JSON object per line on the loader's stdout:

    {"ts":1284.378298,"pid":4314,"ppid":4150,"uid":1000,"comm":"bash","type":"OPEN","detail":"/tmp/x"}

ts is kernel monotonic time in seconds since boot (bpf_ktime_get_ns), not wall clock. Keep it end to end.
Status lines ("sensor up", "dropped events") go to stderr, never stdout.

## detail by type

| type | detail | notes |
|---|---|---|
| EXEC | /usr/bin/ls | the program being started; comm is still the parent's name at this point |
| OPEN | /tmp/x | write intent only (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND) |
| CONNECT | 5.6.7.8:4444 or [2001:db8:0:0:0:0:0:1]:4444 | IPv4-mapped IPv6 is reported as plain IPv4; port 0 is never emitted |
| BIND | 0.0.0.0:4444 or [0:0:0:0:0:0:0:0]:4445 | same formats as CONNECT |
| PTRACE | target_pid=1234 | attach and seize only, refused attempts included |
| SETUID | old_uid=1000 new_uid=0 | setuid, setreuid, setresuid; threaded programs give one event per thread |
| UNLINK | /tmp/x | |
| RENAME | /tmp/old -> /tmp/new | each side cut at 59 chars |
| MPROTECT | addr=0x7f12345000 prot=rwx suppressed=41 | exec remaps only, 1 per pid per second; suppressed = remaps dropped since that pid's previous event |
| MODULE | dummy.ko or memory_image len=12345 | memory_image means init_module from a buffer, no file |
| CHMOD | /tmp/x mode=4755 | mode is always 4 octal digits |
| CORRELATED | dst=1.2.3.4:4444 exec=/bin/sh | only when the loader runs with --correlate |

## Parsing notes

CONNECT and BIND: rsplit(":", 1), then strip [ and ] from the address.
RENAME: split(" -> ", 1).
MPROTECT: key=value pairs.
Paths from unlinkat, renameat and fchmodat can be relative to an open directory, and fchmod gives a basename only. Never assume a path is complete or absolute.
comm is at most 15 chars and can be a thread name, e.g. "DNS Res~er #12".
detail can be empty when the kernel could not read the string from the process.

## Measured on the dev VM (Ubuntu 22.04, kernel 6.8, VirtualBox)

Idle with Firefox open: 72 and 254 events per minute in two runs, the 254 mostly apt-check.
Firefox renamed 8 files in about 25 ms during normal browsing. A ransomware burst threshold has to sit above that.
Exec remaps: 514 in an idle minute before rate limiting, 21 events after.
