"""MARIS investigation agent.

Controlled, deterministic agentic workflow:

    PLAN  -> select relevant tools for the incident
    TOOL  -> run each selected tool
    OBSERVE -> collect tool results
    CORRELATE -> merge tool findings into an evidence list
    ASSESS -> deterministic risk assessment + recommended action

No LLM, no external calls -- reliability over complexity for the demo.
"""

from tools import log_analyzer, device_checker, network_analyzer, threat_analyzer
from agent.risk_assessment import assess_risk

# Registry the agent plans over.
TOOL_REGISTRY = {
    "log_analyzer": log_analyzer,
    "device_checker": device_checker,
    "network_analyzer": network_analyzer,
    "threat_analyzer": threat_analyzer,
}


def _plan(incident: dict) -> list:
    """Decide which tools are relevant. threat_analyzer always runs last to
    correlate. Others run when their indicator is present, but for a stable
    demo we run all four whenever any indicator exists."""
    ind = incident.get("indicators", {})
    selected = []
    reasoning = []

    if ind.get("failed_logins", 0):
        selected.append("log_analyzer")
        reasoning.append("Failed login attempts present -> run Log Analyzer")
    if "unknown_device" in ind:
        selected.append("device_checker")
        reasoning.append("Device state available -> run Device Checker")
    if "traffic_increase_pct" in ind or ind.get("suspicious_outbound"):
        selected.append("network_analyzer")
        reasoning.append("Network indicators present -> run Network Analyzer")

    # Ensure the core three always run so the demo is consistent.
    for core in ("log_analyzer", "device_checker", "network_analyzer"):
        if core not in selected:
            selected.append(core)

    selected.append("threat_analyzer")
    reasoning.append("Correlate all indicators -> run Threat Analyzer")
    return selected, reasoning


def investigate(incident: dict) -> dict:
    # PLAN
    selected_tools, reasoning = _plan(incident)

    # TOOL + OBSERVE
    tool_results = {}
    for name in selected_tools:
        result = TOOL_REGISTRY[name](incident)
        tool_results[name] = result
        top = result["findings"][0] if result["findings"] else "no findings"
        reasoning.append(f"{name} -> {result['severity']}: {top}")

    # CORRELATE
    evidence = []
    for result in tool_results.values():
        evidence.extend(result.get("findings", []))

    # ASSESS
    risk = assess_risk(incident)

    return {
        "status": "completed",
        "risk_level": risk["risk_level"],
        "risk_score": risk["risk_score"],
        "summary": risk["summary"],
        "evidence": risk["evidence"],
        "correlated_findings": evidence,
        "tool_results": tool_results,
        "reasoning": reasoning,
        "recommended_action": risk["recommended_action"],
    }
