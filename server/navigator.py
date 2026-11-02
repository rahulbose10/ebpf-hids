import re

from server import mitre

TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")

LAYER_NAME = "eBPF-HIDS detections"
DESCRIPTION = (
    "Techniques that eBPF-HIDS rules detect, scored by how many alerts each one raised. "
    "ML anomalies are left out, because ML-ANOM is not an ATT&CK technique."
)


def real_counts(technique_counts):
    return {tid: n for tid, n in technique_counts.items() if TECHNIQUE_ID.fullmatch(str(tid))}


def build_layer(technique_counts):
    counts = real_counts(technique_counts)
    techniques = []
    for tid in sorted(set(mitre.TECHNIQUES) | set(counts)):
        count = counts.get(tid, 0)
        if tid in mitre.TECHNIQUES:
            note = f"{count} alerts" if count else "a rule covers this, no alerts yet"
        else:
            note = f"{count} alerts, raised by a rule outside the mapped set"
        techniques.append({
            "techniqueID": tid,
            "score": count,
            "comment": note,
            "enabled": True,
        })
    top = max([t["score"] for t in techniques] + [1])
    return {
        "name": LAYER_NAME,
        "versions": {"navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": DESCRIPTION,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": top},
        "legendItems": [
            {"label": "covered by a rule, no alerts", "color": "#ffffff"},
            {"label": "most alerts", "color": "#ff6666"},
        ],
    }
