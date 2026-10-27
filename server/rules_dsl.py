import re
from pathlib import Path

import yaml

from server.features import ProcessState

SEVERITIES = ("low", "medium", "high", "critical")
EVENT_FIELDS = {"ts", "pid", "ppid", "uid", "comm", "type", "detail"}
EVENT_TYPES = {
    "EXEC", "OPEN", "CONNECT", "PTRACE", "SETUID", "UNLINK", "RENAME",
    "MPROTECT", "MODULE", "BIND", "CHMOD", "CORRELATED", "PTRACE_CHECK",
}
FILE_FIELDS = {"fetched_age"}
FAMILIES = ("evt", "proc", "parent", "since", "file")

_PROBE = ProcessState(pid=0, ppid=0, comm="", uid=0)


def _in_set(actual, expected):
    return actual in expected


def _matches(actual, expected):
    return actual is not None and expected.search(str(actual)) is not None


OPERATORS = {
    "eq": lambda actual, expected: actual == expected,
    "gte": lambda actual, expected: actual is not None and actual >= expected,
    "lte": lambda actual, expected: actual is not None and actual <= expected,
    "in_set": _in_set,
    "not_in_set": lambda actual, expected: not _in_set(actual, expected),
    "matches": _matches,
    "not_matches": lambda actual, expected: not _matches(actual, expected),
}


class RuleError(ValueError):
    pass


class Condition:
    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise RuleError(f"condition must be a mapping, got {raw!r}")
        for key in ("field", "op", "value"):
            if key not in raw:
                raise RuleError(f"condition {raw!r} is missing '{key}'")

        self.field = str(raw["field"])
        self.op = str(raw["op"])
        family, dot, name = self.field.partition(".")
        if not dot or family not in FAMILIES:
            raise RuleError(f"unknown field '{self.field}', families are {', '.join(FAMILIES)}")
        self.family = family
        self.name = name
        self._check_name()

        if self.op not in OPERATORS:
            raise RuleError(f"unknown op '{self.op}' in {self.field}")
        self.func = OPERATORS[self.op]
        self.value = self._compile_value(raw["value"])

    def _check_name(self):
        if self.family == "evt" and self.name not in EVENT_FIELDS:
            raise RuleError(f"evt.{self.name} is not a sensor field")
        if self.family in ("proc", "parent") and not hasattr(_PROBE, self.name):
            raise RuleError(f"{self.field}: ProcessState has no '{self.name}'")
        if self.family == "since" and self.name.upper() not in EVENT_TYPES:
            raise RuleError(f"{self.field}: '{self.name}' is not an event type")
        if self.family == "file" and self.name not in FILE_FIELDS:
            raise RuleError(f"{self.field}: file.* only supports {sorted(FILE_FIELDS)}")

    def _compile_value(self, value):
        if self.op in ("in_set", "not_in_set"):
            if not isinstance(value, list):
                raise RuleError(f"{self.field} {self.op} needs a list")
            return frozenset(value)
        if self.op in ("matches", "not_matches"):
            try:
                return re.compile(str(value))
            except re.error as exc:
                raise RuleError(f"{self.field}: bad regex {value!r}: {exc}") from exc
        if self.op in ("gte", "lte") and not isinstance(value, (int, float)):
            raise RuleError(f"{self.field} {self.op} needs a number")
        return value

    def resolve(self, state, engine, evt, now):
        if self.family == "evt":
            return evt.get(self.name)
        if self.family == "proc":
            return getattr(state, self.name)
        if self.family == "parent":
            parent = engine.processes.get(state.ppid)
            return getattr(parent, self.name) if parent is not None else None
        if self.family == "since":
            last = state.last_seen.get(self.name.upper())
            return None if last is None else now - last
        return engine.fetched_age(evt.get("detail", ""), now)

    def check(self, state, engine, evt, now):
        return self.func(self.resolve(state, engine, evt, now), self.value)


class Rule:
    def __init__(self, raw, source=""):
        if not isinstance(raw, dict):
            raise RuleError(f"rule must be a mapping, got {raw!r}")
        for key in ("id", "technique", "severity", "description", "where"):
            if key not in raw:
                raise RuleError(f"rule {raw.get('id', '?')} is missing '{key}'")
        if raw["severity"] not in SEVERITIES:
            raise RuleError(f"rule {raw['id']}: severity must be one of {SEVERITIES}")
        if not isinstance(raw["where"], list) or not raw["where"]:
            raise RuleError(f"rule {raw['id']}: 'where' must be a non-empty list")

        self.id = str(raw["id"])
        self.technique = str(raw["technique"])
        self.severity = raw["severity"]
        self.description = str(raw["description"])
        self.enabled = bool(raw.get("enabled", True))
        self.source = source
        self.where = [Condition(c) for c in raw["where"]]

    def matches(self, state, engine, evt, now):
        return all(c.check(state, engine, evt, now) for c in self.where)

    def to_dict(self, hits=0):
        return {
            "id": self.id,
            "technique": self.technique,
            "severity": self.severity,
            "enabled": self.enabled,
            "description": self.description,
            "hits": hits,
        }


def _read_raw_rules(path):
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError("top level must be 'rules:' followed by a list")
    return data["rules"]


def load_rules(filepath):
    path = Path(filepath)
    return [Rule(r, source=path.name) for r in _read_raw_rules(path)]


def load_rules_dir(rules_dir):
    rules = []
    errors = []
    seen = set()
    for path in sorted(Path(rules_dir).glob("*.yml")):
        try:
            raw_rules = _read_raw_rules(path)
        except (OSError, yaml.YAMLError, RuleError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        for raw in raw_rules:
            try:
                rule = Rule(raw, source=path.name)
            except RuleError as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            if rule.id in seen:
                errors.append(f"{path.name}: duplicate rule id '{rule.id}' skipped")
                continue
            seen.add(rule.id)
            rules.append(rule)
    return rules, errors
