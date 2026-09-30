"""Threat Analyzer tool -- correlates indicators to identify threat patterns.

Deterministic and offline. Input is an incident dict.
"""


def threat_analyzer(incident: dict) -> dict:
    ind = incident.get("indicators", {})
    failed = int(ind.get("failed_logins", 0))
    unknown = bool(ind.get("unknown_device", False))
    increase = int(ind.get("traffic_increase_pct", 0))
    suspicious = bool(ind.get("suspicious_outbound", False))
    port_scan = bool(ind.get("port_scan_detected", False))

    signals = []
    if failed >= 5:
        signals.append("failed authentication burst")
    if unknown:
        signals.append("unknown device")
    if increase >= 100:
        signals.append("severe traffic spike")
    if suspicious:
        signals.append("suspicious outbound connection")
    if port_scan:
        signals.append("internal port scan")

    findings = []
    if len(signals) >= 3:
        severity = "HIGH"
        findings.append("Multiple correlated indicators suggest a coordinated security incident")
        findings.append("Correlated signals: " + ", ".join(signals))
    elif len(signals) == 2:
        severity = "MEDIUM"
        findings.append("Two related indicators may represent an emerging threat")
        findings.append("Correlated signals: " + ", ".join(signals))
    elif len(signals) == 1:
        severity = "MEDIUM" if signals[0] in ("unknown device", "suspicious outbound connection") else "LOW"
        findings.append(f"Single notable indicator observed: {signals[0]}")
    else:
        severity = "LOW"
        findings.append("No correlated threat pattern identified")

    return {
        "tool": "threat_analyzer",
        "status": "completed",
        "findings": findings,
        "severity": severity,
    }
