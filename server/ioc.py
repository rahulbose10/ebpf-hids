from fnmatch import fnmatchcase

from server.features import rename_paths, split_addr

IOC_TYPES = ("ip", "path", "hash")
PATH_EVENTS = ("OPEN", "UNLINK", "EXEC")


def _event_ips(evt):
    etype = evt.get("type")
    detail = evt.get("detail", "")
    if etype in ("CONNECT", "BIND"):
        return [split_addr(detail)[0]]
    if etype == "CORRELATED":
        for part in detail.split():
            if part.startswith("dst="):
                return [split_addr(part[4:])[0]]
    return []


def _event_paths(evt):
    etype = evt.get("type")
    detail = evt.get("detail", "")
    if not detail:
        return []
    if etype in PATH_EVENTS:
        return [detail]
    if etype == "RENAME":
        return [p for p in rename_paths(detail) if p]
    if etype == "CHMOD":
        return [detail.rsplit(" mode=", 1)[0]]
    if etype == "MODULE" and not detail.startswith("memory_image"):
        return [detail]
    if etype == "CORRELATED":
        return [part[5:] for part in detail.split() if part.startswith("exec=")]
    return []


class IOCStore:
    def __init__(self):
        self.indicators = {}
        self.next_id = 1

    def add(self, ioc_type, pattern, description="", ioc_id=None):
        if ioc_type not in IOC_TYPES:
            raise ValueError(f"ioc type must be one of {IOC_TYPES}, got '{ioc_type}'")
        if not pattern:
            raise ValueError("ioc pattern must not be empty")
        if ioc_id is None:
            ioc_id = self.next_id
        self.next_id = max(self.next_id, ioc_id + 1)
        self.indicators[ioc_id] = {
            "id": ioc_id,
            "type": ioc_type,
            "pattern": pattern,
            "description": description,
        }
        return self.indicators[ioc_id]

    def remove(self, ioc_id):
        return self.indicators.pop(ioc_id, None) is not None

    def load(self, rows):
        self.indicators.clear()
        self.next_id = 1
        for row in rows:
            self.add(row["type"], row["pattern"], row.get("description", ""), ioc_id=row.get("id"))

    def all(self):
        return list(self.indicators.values())

    def _match(self, ioc_type, values):
        hits = []
        for ioc in self.indicators.values():
            if ioc["type"] != ioc_type:
                continue
            if any(fnmatchcase(v, ioc["pattern"]) for v in values):
                hits.append(ioc)
        return hits

    def match_ip(self, ip):
        return self._match("ip", [ip])

    def match_path(self, path):
        return self._match("path", [path])

    def match_hash(self, digest):
        return [i for i in self.indicators.values() if i["type"] == "hash" and i["pattern"] == digest]

    def match_event(self, evt):
        return self._match("ip", _event_ips(evt)) + self._match("path", _event_paths(evt))

    def enrich(self, alert):
        evt = alert.get("detail", {}).get("event", {})
        hits = self.match_event(evt)
        if hits:
            alert["detail"]["ioc"] = [
                {"id": h["id"], "type": h["type"], "pattern": h["pattern"], "description": h["description"]}
                for h in hits
            ]
        return alert
