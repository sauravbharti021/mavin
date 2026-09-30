"""Device Checker tool -- determines whether a device is known or suspicious.

Deterministic and offline. Input is an incident dict.
"""


def device_checker(incident: dict) -> dict:
    ind = incident.get("indicators", {})
    unknown = bool(ind.get("unknown_device", False))
    mac = ind.get("unknown_device_mac")

    findings = []
    if unknown:
        severity = "HIGH"
        label = f" ({mac})" if mac else ""
        findings.append(f"Unrecognized device connected to the vessel network{label}")
        findings.append("Device is not present in the approved asset inventory")
    else:
        severity = "LOW"
        findings.append("All connected devices match the approved asset inventory")

    return {
        "tool": "device_checker",
        "status": "completed",
        "findings": findings,
        "severity": severity,
    }
