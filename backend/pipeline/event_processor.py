"""
AI Shield — Central Event Processing Pipeline Orchestrator.
Orchestrates the entire event lifecycle:
Receive Event → Validate Event → Duplicate Check → Evaluate Rules → Score ML →
Calculate Risk → Store Results via Multi-Tenant Repository → Generate Incident/Alert
"""

import uuid
from typing import Dict, Any, Tuple
from backend.repository import Repository
from backend.utils.validation import validate_event_payload, get_current_iso_timestamp
from backend.pipeline.security_adapter import get_security_adapter
from backend.pipeline.ml_adapter import get_ml_adapter
from backend.pipeline.risk_engine import calculate_composite_risk
from backend.pipeline.incident_generator import evaluate_and_generate_alerts
from backend.integrations.jev_client import JevClient

def process_security_event(raw_payload: Dict[str, Any], client=None) -> Tuple[bool, Any, int]:
    """
    Execute the central event processing pipeline for an incoming event.
    
    Returns:
        (success: bool, result_or_error: dict | str, status_code: int)
    """
    # STEP 1: VALIDATE EVENT
    is_valid, err_msg, cleaned = validate_event_payload(raw_payload)
    if not is_valid:
        return False, err_msg, 400

    try:
        org_id = cleaned.get("organization_id", "org_default")

        # STEP 2: DUPLICATE CHECK (Event ID)
        if client is not None:
            check_res = client.table("security_events").select("event_id").eq("event_id", cleaned["event_id"]).execute()
            if check_res.data:
                return False, f"Event with event_id '{cleaned['event_id']}' already exists", 409
        else:
            existing_event = Repository.get_event(cleaned["event_id"], organization_id=org_id)
            if existing_event:
                return False, f"Event with event_id '{cleaned['event_id']}' already exists", 409

        # STEP 3: EVALUATE SECURITY RULES
        sec_adapter = get_security_adapter()
        sec_result = sec_adapter.evaluate(cleaned)

        # STEP 4: OBTAIN ML RESULT (OR RESPECT INCOMING ML SCORES)
        ml_adapter = get_ml_adapter()
        ml_result = ml_adapter.score(cleaned)

        # STEP 5: CALCULATE COMPOSITE RISK (PRESERVING HARD DENIALS)
        risk_assessment = calculate_composite_risk(sec_result, ml_result, cleaned)

        # Merge calculated detection attributes into the cleaned event
        cleaned["rule_result"] = risk_assessment["rule_result"]
        cleaned["anomaly"] = risk_assessment["anomaly"]
        cleaned["risk_score"] = risk_assessment["risk_score"]
        cleaned["risk_level"] = risk_assessment["risk_level"]
        cleaned["recommended_action"] = risk_assessment["recommended_action"]

        # Clearly distinguish telemetry ingestion from actual access enforcement
        is_flagged = str(risk_assessment.get("rule_result", "")).startswith("flagged_")
        action_permitted = not (is_flagged or risk_assessment.get("hard_denial_preserved", False))
        cleaned["action_permitted"] = action_permitted

        # STEP 5.5: TYPESAFE JEV AI DECISION SUPPORT LAYER
        hard_denial_applied = bool(risk_assessment.get("hard_denial_preserved", False))
        jev_assessment = JevClient.evaluate_security_event(cleaned, rule_override_applied=hard_denial_applied)
        risk_assessment["jev_assessment"] = jev_assessment

        # STEP 6: STORE ENRICHED EVENT IN REPOSITORY (Multi-Tenant Persistence)
        if client is not None:
            insert_res = client.table("security_events").insert(cleaned).execute()
            saved_event = insert_res.data[0] if (insert_res and insert_res.data) else cleaned
        else:
            saved_event = Repository.create_event(cleaned)

        # STEP 7: AUTOMATIC INCIDENTS AND ALERTS (DEDUPLICATED)
        alert_record, incident_record = evaluate_and_generate_alerts(
            saved_event, risk_assessment, client
        )

        pipeline_output = {
            "event": saved_event,
            "risk_assessment": risk_assessment,
            "jev_assessment": jev_assessment,
            "alert": alert_record,
            "incident": incident_record,
            "action_permitted": action_permitted,
            "enforcement_status": "permitted" if action_permitted else "blocked"
        }

        return True, pipeline_output, 201

    except RuntimeError as re:
        return False, f"Database configuration error: {str(re)}", 503
    except Exception as e:
        err_str = str(e)
        if "23505" in err_str or "duplicate key" in err_str or "UNIQUE constraint" in err_str:
            return False, f"Duplicate event_id conflict: {err_str}", 409
        return False, f"Pipeline processing failed: {err_str}", 500
