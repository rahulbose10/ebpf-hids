import fnmatch


class IOCStore:
    def __init__(self):
        self.indicators = []  # প্রতিটা: {"type": "ip"|"path"|"hash", "pattern": str, "description": str}

    def add(self, ioc_type, pattern, description=""):
        self.indicators.append({
            "type": ioc_type,
            "pattern": pattern,
            "description": description,
        })

    def match_ip(self, ip_str):
        matches = []
        for ioc in self.indicators:
            if ioc["type"] != "ip":
                continue
            if fnmatch.fnmatch(ip_str, ioc["pattern"]):
                matches.append(ioc)
        return matches

    def match_path(self, path_str):
        matches = []
        for ioc in self.indicators:
            if ioc["type"] != "path":
                continue
            if fnmatch.fnmatch(path_str, ioc["pattern"]):
                matches.append(ioc)
        return matches

    def match_hash(self, hash_str):
        matches = []
        for ioc in self.indicators:
            if ioc["type"] != "hash":
                continue
            if hash_str == ioc["pattern"]:
                matches.append(ioc)
        return matches

    def enrich(self, alert):
        """
        alert এর detail-এ কোনো known IOC মেলে কিনা চেক করে,
        মিললে alert-এ একটা 'ioc_matches' key যোগ করে।
        """
        evt = alert.get("detail", {}).get("event", {})
        etype = evt.get("type")
        detail = evt.get("detail", "")

        matches = []

        if etype == "CONNECT" or etype == "BIND":
            ip_part = detail.split(":")[0] if ":" in detail else detail
            matches.extend(self.match_ip(ip_part))

        if etype in ("OPEN", "UNLINK", "RENAME", "EXEC"):
            matches.extend(self.match_path(detail))

        if matches:
            alert["ioc_matches"] = matches

        return alert