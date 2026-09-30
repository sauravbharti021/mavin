"""Log Analyzer tool -- inspects authentication / log indicators of an incident.

Deterministic and offline. Input is an incident dict (see data/incidents.json).
"""


def log_analyzer(incident: dict) -> dict:
    ind = incident.get("indicators", {})
    failed = int(ind.get("failed_logins", 0))

    findings = []
    if failed >= 10:
        severity = "HIGH"
        findings.append(f"{failed} failed authentication attempts detected (brute-force pattern)")
    elif failed >= 5:
        severity = "MEDIUM"
        findings.append(f"{failed} failed authentication attempts detected")
    elif failed >= 1:
        severity = "LOW"
        findings.append(f"{failed} failed authentication attempt(s) detected")
    else:
        severity = "LOW"
        findings.append("No failed authentication attempts in the reviewed window")

    return {
        "tool": "log_analyzer",
        "status": "completed",
        "findings": findings,
        "severity": severity,
    }
