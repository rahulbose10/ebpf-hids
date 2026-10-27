TECHNIQUE_CATALOGUE = {
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


def coverage(engine):
    """
    প্রতিটা catalogue-এর technique-এর জন্য, এই session-এ কতগুলো alert
    সেই technique ব্যবহার করে ফায়ার করেছে সেটা গোনে।
    """
    counts = {tid: 0 for tid in TECHNIQUE_CATALOGUE}

    for alert in engine.alerts:
        tid = alert.get("technique")
        if tid in counts:
            counts[tid] += 1

    result = []
    for tid, info in TECHNIQUE_CATALOGUE.items():
        result.append({
            "technique": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "alert_count": counts[tid],
            "covered": counts[tid] > 0,
        })

    return result


def summary(engine):
    rows = coverage(engine)
    total = len(rows)
    covered = sum(1 for r in rows if r["covered"])
    return {
        "total_techniques": total,
        "covered_techniques": covered,
        "coverage_pct": round(100 * covered / total, 1) if total > 0 else 0.0,
        "rows": rows,
    }