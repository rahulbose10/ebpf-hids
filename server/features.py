import posixpath
import re
from collections import deque

MAX_TRACK = 256
BURST_WINDOW = 5.0
COMM_LEN = 15
DNS_PORT = 53

_NEW_UID = re.compile(r"new_uid=(\d+)")
_OLD_UID = re.compile(r"old_uid=(\d+)")
_PROT = re.compile(r"prot=([r-])([w-])([x-])")

# Deletes and renames that a normal desktop does in bursts on its own.
# Every entry here was seen raising ransomware_burst during the 15 minute
# idle run on the dev VM (2026-10-27): apt and the ESM hook clearing package
# lists, dpkg staging files, Firefox and Thunderbird profile and cache churn.
# These still count in unlink_count and rename_count, they just do not feed
# destruction_burst. Anchored on the start of the path because the sensor
# cuts each side of a RENAME at 59 chars, so the end may be missing.
ROUTINE_CHURN = re.compile(
    r"^/var/lib/(apt|dpkg|ubuntu-advantage|snapd|PackageKit)/"
    r"|^/var/cache/"
    r"|^/(root|home/[^/]+)/\.(cache|mozilla|thunderbird|config|local/share)/"
    r"|^/home/[^/]+/snap/[^/]+/[^/]+/\.(cache|mozilla|thunderbird|config|local)/"
    r"|\.dpkg-(tmp|new|old|dist)$"
)


def is_routine_churn(path):
    return bool(path) and ROUTINE_CHURN.search(path) is not None


def split_addr(detail):
    host, sep, port = detail.rpartition(":")
    if not sep:
        return detail, None
    host = host.strip("[]")
    try:
        return host, int(port)
    except ValueError:
        return host, None


def rename_paths(detail):
    old, sep, new = detail.partition(" -> ")
    if not sep:
        return detail, None
    return old, new


class ProcessState:
    def __init__(self, pid, ppid, comm, uid):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.uid = uid
        self.exe = None

        self.exec_count = 0
        self.connect_count = 0
        self.net_connect_count = 0
        self.file_write_count = 0
        self.ptrace_count = 0
        self.setuid_count = 0
        # setuid calls that went from a non-root uid to 0. cron and other
        # root daemons call setuid(0) while already root before running a
        # job; that is not an escalation and must not count here.
        self.root_gain_count = 0
        self.unlink_count = 0
        self.rename_count = 0
        self.mprotect_exec_count = 0
        self.module_count = 0
        self.bind_count = 0
        self.chmod_count = 0

        self.types = set()
        self.files_written = set()
        self.dst_set = set()

        self.event_times = deque(maxlen=MAX_TRACK)
        self.destruction_times = deque(maxlen=MAX_TRACK)
        self.last_seen = {}
        self.last_alert = {}

        self.first_ts = None
        self.last_ts = None
        self.ran_as_root = uid == 0

    @property
    def exe_name(self):
        if self.exe:
            return posixpath.basename(self.exe)
        return self.comm

    @property
    def distinct_files_written(self):
        return len(self.files_written)

    @property
    def distinct_destinations(self):
        return len(self.dst_set)

    @property
    def destruction_count(self):
        return self.unlink_count + self.rename_count

    @property
    def lifetime_s(self):
        if self.first_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    @property
    def destruction_burst(self):
        if not self.destruction_times:
            return 0
        newest = self.destruction_times[-1]
        return sum(1 for t in self.destruction_times if newest - t <= BURST_WINDOW)

    def update(self, evt):
        etype = evt["type"]
        ts = evt["ts"]
        detail = evt["detail"]

        if self.first_ts is None:
            self.first_ts = ts
            self.last_ts = ts
        else:
            self.first_ts = min(self.first_ts, ts)
            self.last_ts = max(self.last_ts, ts)

        previous = self.last_seen.get(etype)
        self.last_seen[etype] = ts if previous is None else max(previous, ts)
        self.types.add(etype)
        self.event_times.append(ts)

        self.uid = evt["uid"]
        if self.uid == 0:
            self.ran_as_root = True

        if etype == "EXEC":
            self.exec_count += 1
            if detail:
                self.exe = detail
                self.comm = posixpath.basename(detail)[:COMM_LEN]
        elif etype == "CONNECT":
            self.connect_count += 1
            if len(self.dst_set) < MAX_TRACK:
                self.dst_set.add(detail)
            _, port = split_addr(detail)
            if port != DNS_PORT:
                self.net_connect_count += 1
        elif etype == "OPEN":
            self.file_write_count += 1
            if len(self.files_written) < MAX_TRACK:
                self.files_written.add(detail)
        elif etype == "PTRACE":
            self.ptrace_count += 1
        elif etype == "SETUID":
            self.setuid_count += 1
            found = _NEW_UID.search(detail)
            if found and int(found.group(1)) == 0:
                self.ran_as_root = True
                old = _OLD_UID.search(detail)
                if old is None or int(old.group(1)) != 0:
                    self.root_gain_count += 1
        elif etype == "UNLINK":
            self.unlink_count += 1
            if not is_routine_churn(detail):
                self.destruction_times.append(ts)
        elif etype == "RENAME":
            self.rename_count += 1
            # Both sides must be routine. Renaming ~/Documents/a.docx to
            # ~/.cache/a.locked still counts.
            old, new = rename_paths(detail)
            if not (is_routine_churn(old) and (new is None or is_routine_churn(new))):
                self.destruction_times.append(ts)
        elif etype == "MPROTECT":
            found = _PROT.search(detail)
            if found and found.group(3) == "x":
                self.mprotect_exec_count += 1
        elif etype == "MODULE":
            self.module_count += 1
        elif etype == "BIND":
            self.bind_count += 1
        elif etype == "CHMOD":
            self.chmod_count += 1

    def to_dict(self, depth=0):
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "uid": self.uid,
            "exec_count": self.exec_count,
            "connect_count": self.connect_count,
            "file_write_count": self.file_write_count,
            "ptrace_count": self.ptrace_count,
            "setuid_count": self.setuid_count,
            "destruction_count": self.destruction_count,
            "module_count": self.module_count,
            "bind_count": self.bind_count,
            "mprotect_exec_count": self.mprotect_exec_count,
            "ran_as_root": self.ran_as_root,
            "depth": depth,
            "lifetime_s": self.lifetime_s,
        }
