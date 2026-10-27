TECHNIQUES = {
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
}


def tactic_for(technique):
    info = TECHNIQUES.get(technique)
    return info["tactic"] if info else None


def coverage(technique_counts):
    rows = []
    for tid, info in TECHNIQUES.items():
        count = technique_counts.get(tid, 0)
        rows.append({
            "technique": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "alert_count": count,
            "covered": count > 0,
        })
    return rows


def summary(technique_counts):
    rows = coverage(technique_counts)
    covered = sum(1 for r in rows if r["covered"])
    return {
        "total_techniques": len(rows),
        "covered_techniques": covered,
        "coverage_pct": round(100 * covered / len(rows), 1),
        "rows": rows,
    }
