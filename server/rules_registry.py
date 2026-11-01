_RULES = [
    {
        "id": "network_parent_shell",
        "technique": "T1059",
        "severity": "high",
        "enabled": True,
        "description": "A shell was started by a program that talks to the network",
        "hits": 0,
    },
    {
        "id": "ptrace_then_exec",
        "technique": "T1055",
        "severity": "critical",
        "enabled": True,
        "description": "A process used ptrace and then ran a new program",
        "hits": 0,
    },
    {
        "id": "suid_shell",
        "technique": "T1548",
        "severity": "high",
        "enabled": True,
        "description": "A shell gained root rights through a setuid change",
        "hits": 0,
    },
    {
        "id": "connect_after_exec",
        "technique": "T1071",
        "severity": "medium",
        "enabled": True,
        "description": "A program made a network connection right after it started",
        "hits": 0,
    },
]


def list_rules():
    return [dict(rule) for rule in _RULES]


def toggle_rule(rule_id):
    for rule in _RULES:
        if rule["id"] == rule_id:
            rule["enabled"] = not rule["enabled"]
            return dict(rule)
    return None
