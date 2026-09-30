"""Network Analyzer tool -- reports traffic anomalies and suspicious connections.

Deterministic and offline. Input is an incident dict.
"""


def network_analyzer(incident: dict) -> dict:
    ind = incident.get("indicators", {})
    increase = int(ind.get("traffic_increase_pct", 0))
    suspicious = bool(ind.get("suspicious_outbound", False))
    dest = ind.get("suspicious_destination")

    findings = []
    severity = "LOW"

    if increase >= 100:
        severity = "HIGH"
        findings.append(f"Outbound traffic increased by {increase}% (severe anomaly)")
    elif increase >= 40:
        severity = "MEDIUM"
        findings.append(f"Outbound traffic increased by {increase}%")
    elif increase > 0:
        findings.append(f"Minor traffic deviation of {increase}% (within tolerance)")
    else:
        findings.append("Network traffic within normal baseline")

    if suspicious:
        severity = "HIGH"
        label = f" to {dest}" if dest else ""
        findings.append(f"Suspicious outbound connection detected{label}")

    return {
        "tool": "network_analyzer",
        "status": "completed",
        "findings": findings,
        "severity": severity,
    }
