import re
import uuid
from flask import Blueprint, request
from backend.repository import Repository
from backend.auth import get_tenant_organization_id
from backend.utils.response import api_response, error_response
from backend.pipeline.event_processor import process_security_event

events_bp = Blueprint("events", __name__)

DANGEROUS_QUERY_CHARS = re.compile(r"['\";]|--|/\*|\*/")

@events_bp.route("/api/events", methods=["GET"])
def get_events():
    """
    Retrieve security events partitioned by tenant organization.
    Supports optional filters: event_type, actor_type, actor_id, is_sensitive, risk_level, limit, offset.
    """
    event_type = request.args.get("event_type")
    actor_type = request.args.get("actor_type")
    actor_id = request.args.get("actor_id")
    is_sensitive_param = request.args.get("is_sensitive")
    risk_level = request.args.get("risk_level")
    org_id = get_tenant_organization_id()

    # Input sanitization & injection validation
    for param_name, param_val in [("event_type", event_type), ("actor_type", actor_type), ("actor_id", actor_id), ("risk_level", risk_level)]:
        if param_val and DANGEROUS_QUERY_CHARS.search(param_val):
            return error_response(f"Invalid characters detected in query parameter '{param_name}'", 400)

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    filters = {}
    if event_type:
        filters["event_type"] = event_type
    if actor_type:
        filters["actor_type"] = actor_type
    if actor_id:
        filters["actor_id"] = actor_id
    if is_sensitive_param is not None:
        filters["is_sensitive"] = is_sensitive_param.lower() in ("true", "1")
    if risk_level:
        filters["risk_level"] = risk_level.lower()

    events, total_count = Repository.list_events(
        organization_id=org_id,
        filters=filters,
        limit=limit,
        offset=offset
    )

    meta = {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "returned": len(events)
    }
    return api_response(data=events, message="Events retrieved successfully", meta=meta, status_code=200)

@events_bp.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id):
    """Retrieve a single security event within the caller's authorized organization."""
    org_id = get_tenant_organization_id()
    event = Repository.get_event(event_id, organization_id=org_id)
    if not event:
        return error_response(f"Security event with ID '{event_id}' not found", 404)
    return api_response(data=event, message="Event retrieved successfully", status_code=200)

@events_bp.route("/api/events", methods=["POST"])
def create_event():
    """
    Ingest a new security event conforming to docs/api_contract.md.
    Enforces multi-tenant organization isolation and distinguishes event ingestion
    from access authorization enforcement.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    payload = request.get_json()
    # Enforce tenant isolation on incoming events
    org_id = get_tenant_organization_id()
    if not payload.get("organization_id"):
        payload["organization_id"] = org_id

    success, result, status_code = process_security_event(payload)
    if not success:
        return error_response(result, status_code)

    saved_event = result["event"]
    action_permitted = result.get("action_permitted", True)

    meta = {
        "action_permitted": action_permitted,
        "enforcement_status": result.get("enforcement_status", "permitted")
    }
    if result.get("alert"):
        meta["alert_id"] = result["alert"].get("alert_id")
    if result.get("incident"):
        meta["incident_id"] = result["incident"].get("incident_id")
    if result.get("risk_assessment"):
        meta["risk_level"] = result["risk_assessment"].get("risk_level")
        meta["risk_score"] = result["risk_assessment"].get("risk_score")

    message = (
        "Security event registered successfully"
        if action_permitted
        else f"Event recorded: Operation BLOCKED by security policy ({saved_event.get('rule_result')})"
    )

    return api_response(
        data=saved_event,
        message=message,
        meta=meta,
        status_code=201
    )
