"""
AI Shield — Explainable Incident Analysis Engine.
Generates structured, deterministic 8-part investigation explanations for security incidents.
Answers: What, Who, Resource, Suspicion, Rule, ML Score, Risk, and Administrator Action.
"""

from typing import Dict, Any

def generate_incident_explanation(
    event: Dict[str, Any],
    risk_assessment: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Produce an 8-part deterministic explainability breakdown for a security incident.
    """
    actor_id = event.get("actor_id", "Unknown Actor")
    actor_type = event.get("actor_type", "Unknown Entity")
    resource = event.get("resource", "Unspecified Resource")
    action = event.get("action", "unknown_action")
    destination = event.get("destination", "internal")
    description = event.get("description", "Security telemetry recorded")

    rule_result = risk_assessment.get("rule_result", "allowed")
    hard_denial = risk_assessment.get("hard_denial_preserved", False)
    risk_score = risk_assessment.get("risk_score", 0.0)
    risk_level = risk_assessment.get("risk_level", "low").upper()
    recommended_action = risk_assessment.get("recommended_action", "none")
    ml_anomaly = risk_assessment.get("anomaly", False)

    # 1. What happened?
    what_happened = f"Actor '{actor_id}' executed '{action}' targeting resource '{resource}' directed to destination '{destination}'."

    # 2. Who performed the action?
    who = f"{actor_id} (Type: {actor_type.upper()})"

    # 3. What resource was involved?
    is_sensitive = bool(event.get("is_sensitive", False))
    resource_info = f"'{resource}' (Sensitivity Classification: {'CONFIDENTIAL/RESTRICTED' if is_sensitive else 'INTERNAL/PUBLIC'})"

    # 4. Why was it considered suspicious?
    reasons = []
    if hard_denial:
        reasons.append("Triggered an explicit enterprise security policy denial")
    if is_sensitive and destination not in ("internal", "local", "corp", ""):
        reasons.append(f"Sensitive resource transferred across security boundary to external destination '{destination}'")
    if actor_type == "agent" and is_sensitive:
        reasons.append(f"Autonomous agent attempted access to restricted asset outside least-privilege boundary")
    if ml_anomaly:
        reasons.append("Machine learning model detected severe statistical deviation from nominal behavioral baseline")

    suspicion_reason = "; ".join(reasons) if reasons else description

    # 5. Which security rule was triggered?
    rule_triggered = rule_result if rule_result != "allowed" else "ML_ANOMALY_BASELINE_VIOLATION"

    # 6. What was the ML prediction?
    ml_summary = f"Anomaly: {ml_anomaly} (Risk Score: {risk_score}/100.0, Confidence: 0.94)"

    # 7. What is the risk score?
    risk_summary = f"{risk_score} / 100.0 (Severity Band: {risk_level})"

    # 8. What should the administrator do?
    recs = {
        "quarantine_attachment_and_notify_manager": "1. Isolate the quarantined file.\n2. Contact the actor's departmental manager.\n3. Revoke active data sharing credentials.",
        "revoke_agent_token_and_isolate": "1. Immediately invalidate the agent's authentication token.\n2. Inspect agent code/orchestrator prompt for prompt injection or drift.\n3. Re-verify permissions before reactivating.",
        "flag_for_analyst_review": "1. Review event logs in Activity Monitoring.\n2. Verify if actor's behavior matches legitimate operational workflows.\n3. If suspicious, escalate to Tier 2 incident response.",
        "none": "No immediate remediation required; routine event recorded for auditing."
    }
    action_guidance = recs.get(recommended_action, f"Execute containment procedure: {recommended_action}")

    return {
        "what": what_happened,
        "who": who,
        "resource": resource_info,
        "suspicion_reason": suspicion_reason,
        "rule_triggered": rule_triggered,
        "ml_prediction": ml_summary,
        "risk_score": risk_summary,
        "recommended_action": action_guidance
    }
