"""Risk Assessment module -- deterministic rule-based scoring.

Consumes the raw incident indicators (already surfaced by the tools) and
produces a risk level, numeric score, evidence list and recommended action.
No ML, no external calls.
"""

# Points per indicator. Chosen so a single coordinated incident lands in HIGH.
WEIGHTS = {
    "unknown_device": 30,
    "suspicious_outbound": 30,
    "port_scan": 15,
    "failed_logins_high": 25,   # >= 10
    "failed_logins_med": 15,    # 5-9
    "failed_logins_low": 5,     # 1-4
    "traffic_high": 25,         # >= 100%
    "traffic_med": 12,          # 40-99%
}


def assess_risk(incident: dict) -> dict:
    ind = incident.get("indicators", {})
    failed = int(ind.get("failed_logins", 0))
    unknown = bool(ind.get("unknown_device", False))
    increase = int(ind.get("traffic_increase_pct", 0))
    suspicious = bool(ind.get("suspicious_outbound", False))
    dest = ind.get("suspicious_destination")
    port_scan = bool(ind.get("port_scan_detected", False))

    score = 0
    evidence = []

    if failed >= 10:
        score += WEIGHTS["failed_logins_high"]
        evidence.append(f"{failed} failed logins")
    elif failed >= 5:
        score += WEIGHTS["failed_logins_med"]
        evidence.append(f"{failed} failed logins")
    elif failed >= 1:
        score += WEIGHTS["failed_logins_low"]
        evidence.append(f"{failed} failed login(s)")

    if unknown:
        score += WEIGHTS["unknown_device"]
        evidence.append("Unknown device connected")

    if increase >= 100:
        score += WEIGHTS["traffic_high"]
        evidence.append(f"{increase}% traffic increase")
    elif increase >= 40:
        score += WEIGHTS["traffic_med"]
        evidence.append(f"{increase}% traffic increase")

    if suspicious:
        score += WEIGHTS["suspicious_outbound"]
        evidence.append(f"Suspicious outbound connection{f' to {dest}' if dest else ''}")

    if port_scan:
        score += WEIGHTS["port_scan"]
        evidence.append("Internal port scan detected")

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    summary, recommended_action = _narrative(risk_level, unknown, suspicious, failed, increase)

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "summary": summary,
        "evidence": evidence,
        "recommended_action": recommended_action,
    }


def _narrative(risk_level, unknown, suspicious, failed, increase):
    if risk_level == "HIGH":
        summary = (
            "Multiple security indicators occurred within the same timeframe and "
            "may be connected, consistent with a coordinated security incident."
        )
        recommended_action = (
            "Isolate the affected device and investigate the associated credentials "
            "and network destination."
        )
    elif risk_level == "MEDIUM":
        summary = (
            "One or more notable indicators were observed. The activity is suspicious "
            "but does not yet show a fully correlated attack pattern."
        )
        recommended_action = (
            "Monitor the affected system, review recent authentication activity, and "
            "confirm the device and connection are expected."
        )
    else:
        summary = "No suspicious indicators of concern were identified in this incident."
        recommended_action = "No immediate action required. Continue routine monitoring."

    return summary, recommended_action
