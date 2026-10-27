class ProcessState:
    _MAX_TRACK = 256
    _BURST_WINDOW = 5.0

    def __init__(self, pid, ppid, comm, uid):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.uid = uid

        self.exec_count = 0
        self.connect_count = 0
        self.file_write_count = 0
        self.ptrace_count = 0
        self.setuid_count = 0
        self.unlink_count = 0
        self.rename_count = 0
        self.mprotect_exec_count = 0
        self.module_count = 0
        self.bind_count = 0
        self.chmod_count = 0

        self.types = set()
        self.files_written = set()
        self.dst_set = set()

        self.event_times = []
        self.destruction_times = []
        self.last_seen = {}

        self.ran_as_root = (uid == 0)

    @property
    def distinct_files_written(self):
        return len(self.files_written)

    @property
    def distinct_destinations(self):
        return len(self.dst_set)

    @property
    def destruction_burst(self):
        if not self.destruction_times:
            return 0
        last_ts = self.destruction_times[-1]
        return sum(1 for t in self.destruction_times if last_ts - t <= self._BURST_WINDOW)

    def update(self, evt):
        etype = evt["type"]
        self.last_seen[etype] = evt["ts"]
        self.types.add(etype)

        if len(self.event_times) < self._MAX_TRACK:
            self.event_times.append(evt["ts"])

        if etype == "EXEC":
            self.exec_count += 1
        elif etype == "CONNECT":
            self.connect_count += 1
            if len(self.dst_set) < self._MAX_TRACK:
                self.dst_set.add(evt["detail"])
        elif etype == "OPEN":
            self.file_write_count += 1
            if len(self.files_written) < self._MAX_TRACK:
                self.files_written.add(evt["detail"])
        elif etype == "PTRACE":
            self.ptrace_count += 1
        elif etype == "SETUID":
            self.setuid_count += 1
            new_uid = int(evt["detail"].split("new_uid=")[1])
            if new_uid == 0:
                self.ran_as_root = True
        elif etype == "UNLINK":
            self.unlink_count += 1
            if len(self.destruction_times) < self._MAX_TRACK:
                self.destruction_times.append(evt["ts"])
        elif etype == "RENAME":
            self.rename_count += 1
            if len(self.destruction_times) < self._MAX_TRACK:
                self.destruction_times.append(evt["ts"])
        elif etype == "MPROTECT":
            if "prot=rwx" in evt["detail"] or "prot=rx" in evt["detail"]:
                self.mprotect_exec_count += 1
        elif etype == "MODULE":
            self.module_count += 1
        elif etype == "BIND":
            self.bind_count += 1
        elif etype == "CHMOD":
            self.chmod_count += 1