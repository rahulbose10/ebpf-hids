import yaml


class Rule:
    def __init__(self, id, technique, severity, description, where):
        self.id = id
        self.technique = technique
        self.severity = severity
        self.description = description
        self.where = where  # list of {field, op, value} dicts


def load_rules(filepath):
    with open(filepath, "r") as f:
        data = yaml.safe_load(f)

    rules = []
    for r in data["rules"]:
        rule = Rule(
            id=r["id"],
            technique=r["technique"],
            severity=r["severity"],
            description=r["description"],
            where=r["where"],
        )
        rules.append(rule)
    return rules

def resolve_field(field, state, engine, now, evt=None):
    family, name = field.split(".", 1)

    if family == "evt":
        return evt.get(name) if evt else None

    if family == "proc":
        return getattr(state, name)

    if family == "since":
        event_type = name.upper()
        last_ts = state.last_seen.get(event_type)
        if last_ts is None:
            return None
        return now - last_ts

    if family == "parent":
        parent_state = engine.processes.get(state.ppid)
        if parent_state is None:
            return None
        return getattr(parent_state, name)

    raise ValueError(f"unknown field family: {field}")

import re


OPERATORS = {
    "eq": lambda actual, expected: actual == expected,
    "gte": lambda actual, expected: actual is not None and actual >= expected,
    "lte": lambda actual, expected: actual is not None and actual <= expected,
    "in_set": lambda actual, expected: actual in expected,
    "matches": lambda actual, expected: actual is not None and re.search(expected, str(actual)) is not None,
}


def check_condition(condition, state, engine, now, evt=None):
    actual = resolve_field(condition["field"], state, engine, now, evt)
    op = condition["op"]
    expected = condition["value"]
    return OPERATORS[op](actual, expected)