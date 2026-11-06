"""
AI Shield — Automated Incident and Alert Generator.
Evaluates processed security events and generates corresponding alerts and incidents.
Enforces multi-tenant organization isolation, deduplication, and 8-part deterministic explanations.
"""

import uuid
import json
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from backend.repository import Repository
from security.explanations import generate_incident_explanation

def generate_alert_type(event_type: str, rule_result: str) -> str:
    """Map rule result and event type to a standard alert type category."""
    if "dlp" in rule_result or "share" in rule_result:
        return "DLP_VIOLATION"
    elif "agent" in rule_result:
        return "UNAUTHORIZED_AGENT_ACCESS"
    elif "auth" in rule_result or "login" in rule_result or "brute" in rule_result:
        return "ANOMALOUS_AUTHENTICATION"
    elif "export" in rule_result:
        return "REMOVABLE_MEDIA_EXFILTRATION"
    elif "anomaly" in rule_result:
        return "STATISTICAL_ANOMALY"
    else:
        return f"HIGH_RISK_{event_type.upper()}"

def evaluate_and_generate_alerts(
    event_record: Dict[str, Any],
    risk_assessment: Dict[str, Any],
    supabase_client=None
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Generate alerts and incidents for high/critical security events.
    Persists through unified repository with tenant organization isolation.
    Returns: (alert_record, incident_record)
    """
    event_id = event_record.get("event_id")
    org_id = event_record.get("organization_id", "org_default")
    actor_id = event_record.get("actor_id", "unknown_actor")
    resource = event_record.get("resource", "unspecified_resource")
    action = event_record.get("action", "unknown_action")
    event_type = event_record.get("event_type", "security_event")

    risk_level = risk_assessment.get("risk_level", "low").lower()
    rule_result = risk_assessment.get("rule_result", "allowed")
    recommended_action = risk_assessment.get("recommended_action", "none")
    hard_denial = risk_assessment.get("hard_denial_preserved", False)

    now_iso = datetime.now(timezone.utc).isoformat()
    created_alert = None
    created_incident = None

    # Check eligibility: Alerts triggered for high or critical risk
    should_alert = risk_level in ("high", "critical") or hard_denial
    # Incidents created for critical violations or confirmed hard denials
    should_create_incident = risk_level == "critical" or hard_denial

    if not should_alert and not should_create_incident:
        return None, None

    incident_id = None

    # 1. GENERATE INCIDENT (if critical or hard denial)
    if should_create_incident:
        try:
            # Check deduplication: does an incident already exist for this event_id?
            if supabase_client is not None:
                existing_res = supabase_client.table("security_incidents").select("*").eq("event_id", event_id).execute()
                existing_incs = existing_res.data or []
            else:
                existing_incs, _ = Repository.list_incidents(organization_id=org_id, filters={"event_id": event_id}, limit=1)

            if existing_incs:
                created_incident = existing_incs[0]
                incident_id = created_incident.get("incident_id")
            else:
                incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
                title = f"Security Violation: {rule_result} ({event_id})"

                # Build 8-part structured explanation
                explanation = generate_incident_explanation(event_record, risk_assessment)
                description = (
                    f"Incident Investigation Summary for {event_id}:\n"
                    f"- What: {explanation['what']}\n"
                    f"- Actor: {explanation['who']}\n"
                    f"- Resource: {explanation['resource']}\n"
                    f"- Suspicion: {explanation['suspicion_reason']}\n"
                    f"- Policy: {explanation['rule_triggered']}\n"
                    f"- ML Signal: {explanation['ml_prediction']}\n"
                    f"- Risk Assessment: {explanation['risk_score']}\n"
                    f"- Recommended Remediation:\n{explanation['recommended_action']}"
                )

                inc_record = {
                    "incident_id": incident_id,
                    "organization_id": org_id,
                    "title": title,
                    "description": description,
                    "severity": risk_level,
                    "status": "open",
                    "actor_id": actor_id,
                    "event_id": event_id,
                    "assigned_to": None,
                    "resolved_at": None,
                    "created_at": now_iso,
                    "updated_at": now_iso
                }
                if supabase_client is not None:
                    ins_res = supabase_client.table("security_incidents").insert(inc_record).execute()
                    created_incident = ins_res.data[0] if (ins_res and ins_res.data) else inc_record
                else:
                    created_incident = Repository.create_incident(inc_record)
        except Exception as e:
            print(f"[Pipeline] Warning: Failed to create incident for event {event_id}: {e}")

    # 2. GENERATE ALERT (for high or critical risk)
    if should_alert:
        try:
            # Check deduplication: does an alert already exist for this event_id?
            if supabase_client is not None:
                existing_res = supabase_client.table("alerts").select("*").eq("event_id", event_id).execute()
                existing_alts = existing_res.data or []
            else:
                existing_alts, _ = Repository.list_alerts(organization_id=org_id, filters={"event_id": event_id}, limit=1)

            if existing_alts:
                created_alert = existing_alts[0]
            else:
                alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
                alert_type = generate_alert_type(event_type, rule_result)
                message = (
                    f"Simulated event on '{resource}' by '{actor_id}' flagged as {risk_level.upper()} risk. "
                    f"Recommended Action: {recommended_action}."
                )
                alt_record = {
                    "alert_id": alert_id,
                    "organization_id": org_id,
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "alert_type": alert_type,
                    "severity": risk_level,
                    "message": message,
                    "is_read": False,
                    "created_at": now_iso
                }
                if supabase_client is not None:
                    ins_res = supabase_client.table("alerts").insert(alt_record).execute()
                    created_alert = ins_res.data[0] if (ins_res and ins_res.data) else alt_record
                else:
                    created_alert = Repository.create_alert(alt_record)
        except Exception as e:
            print(f"[Pipeline] Warning: Failed to create alert for event {event_id}: {e}")
            print(f"[Pipeline] Warning: Failed to create alert for event {event_id}: {e}")

    return created_alert, created_incident
