import csv
import html
import io
import time

from server import mitre

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
SEVERITIES = ("low", "medium", "high", "critical")

ALERT_COLUMNS = ("id", "ts", "rule", "technique", "severity", "confidence", "pid", "comm", "summary", "incident_id")
INCIDENT_COLUMNS = ("id", "title", "root_pid", "root_comm", "severity", "status",
                    "first_seen", "last_seen", "alert_count")

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; color: #111; }}
table {{ border-collapse: collapse; margin-bottom: 1.5em; }}
th, td {{ border: 1px solid #bbb; padding: 4px 8px; text-align: left; vertical-align: top; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Kernel timestamps are seconds since the monitored machine booted, exactly as the sensor recorded them.</p>
<h2>Incident</h2>
<table>
{facts}
</table>
<h2>Alerts ({alert_count})</h2>
<table>
<tr><th>id</th><th>kernel ts</th><th>rule</th><th>technique</th><th>severity</th><th>pid</th><th>process</th><th>summary</th><th>indicators</th></tr>
{alerts}
</table>
<h2>Status history</h2>
{audit}
</body>
</html>
"""


def safe_cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    if text.startswith(FORMULA_START):
        return "'" + text
    return text


def to_csv(rows, columns):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def summary(counts, numbers, statuses, technique_counts, ml_scored, ml_flagged):
    coverage = mitre.summary(technique_counts)
    return {
        "counts": counts,
        "alerts_by_severity": {s: numbers["by_severity"].get(s, 0) for s in SEVERITIES},
        "top_rules": numbers["top_rules"],
        "incidents_by_status": {s: numbers["by_status"].get(s, 0) for s in statuses},
        "techniques": coverage["total_techniques"],
        "techniques_with_alerts": coverage["covered_techniques"],
        "ml": {"scored": ml_scored, "flagged": ml_flagged},
    }


def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _indicators(alert):
    detail = alert.get("detail")
    hits = detail.get("ioc") if isinstance(detail, dict) else None
    if not isinstance(hits, list):
        return ""
    return ", ".join(str(hit.get("pattern")) for hit in hits if isinstance(hit, dict))


def incident_html(incident, audit):
    title = f"Incident {incident.get('id')}: {incident.get('title') or ''}"
    facts = [
        ("Status", incident.get("status")),
        ("Severity", incident.get("severity")),
        ("Root process", f"{incident.get('root_comm') or ''} (pid {incident.get('root_pid')})"),
        ("First seen, kernel ts", incident.get("first_seen")),
        ("Last seen, kernel ts", incident.get("last_seen")),
        ("Alert count", incident.get("alert_count")),
    ]
    alerts = incident.get("alerts") or []
    alert_rows = [
        "<tr>" + "".join(f"<td>{_e(v)}</td>" for v in (
            a.get("id"), a.get("ts"), a.get("rule"), a.get("technique"), a.get("severity"),
            a.get("pid"), a.get("comm"), a.get("summary"), _indicators(a),
        )) + "</tr>"
        for a in alerts
    ]
    if audit:
        audit_html = "<table>\n<tr><th>when (UTC)</th><th>from</th><th>to</th><th>by</th><th>note</th></tr>\n" + "\n".join(
            "<tr>" + "".join(f"<td>{_e(v)}</td>" for v in (
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(row.get("ts") or 0)),
                row.get("old_status"), row.get("new_status"), row.get("changed_by"), row.get("note"),
            )) + "</tr>"
            for row in audit
        ) + "\n</table>"
    else:
        audit_html = "<p>No status changes yet.</p>"
    return PAGE.format(
        title=_e(title),
        facts="\n".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in facts),
        alert_count=len(alerts),
        alerts="\n".join(alert_rows),
        audit=audit_html,
    )
