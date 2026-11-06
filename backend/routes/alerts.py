import re
import uuid
from flask import Blueprint, request
from backend.repository import Repository
from backend.auth import get_tenant_organization_id
from backend.utils.response import api_response, error_response
from backend.utils.validation import get_current_iso_timestamp

alerts_bp = Blueprint("alerts", __name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
DANGEROUS_QUERY_CHARS = re.compile(r"['\";]|--|/\*|\*/")

@alerts_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Retrieve security alerts partitioned by tenant organization.
    Supports optional filters: severity, is_read, limit, offset.
    """
    severity = request.args.get("severity")
    is_read_param = request.args.get("is_read")
    org_id = get_tenant_organization_id()

    # Input sanitization
    for param_name, param_val in [("severity", severity), ("is_read", is_read_param)]:
        if param_val and DANGEROUS_QUERY_CHARS.search(param_val):
            return error_response(f"Invalid characters detected in query parameter '{param_name}'", 400)

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    filters = {}
    if severity:
        filters["severity"] = severity.lower()
    if is_read_param is not None:
        filters["is_read"] = is_read_param.lower() in ("true", "1")

    alerts, total_count = Repository.list_alerts(
        organization_id=org_id,
        filters=filters,
        limit=limit,
        offset=offset
    )

    meta = {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "returned": len(alerts)
    }
    return api_response(data=alerts, message="Alerts retrieved successfully", meta=meta, status_code=200)

@alerts_bp.route("/api/alerts", methods=["POST"])
def create_alert():
    """
    Create a new alert within tenant organization.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    required = ["alert_type", "severity", "message"]
    for field in required:
        if not data.get(field):
            return error_response(f"Missing required field: '{field}'", 400)

    severity = str(data["severity"]).strip().lower()
    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity '{severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}", 400)

    alert_id = data.get("alert_id") or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    event_id = data.get("event_id")
    incident_id = data.get("incident_id")
    alert_type = str(data["alert_type"]).strip()
    message = str(data["message"]).strip()
    now_iso = get_current_iso_timestamp()
    org_id = get_tenant_organization_id()

    alert_record = {
        "alert_id": alert_id,
        "organization_id": org_id,
        "event_id": event_id,
        "incident_id": incident_id,
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "is_read": False,
        "created_at": now_iso
    }

    saved = Repository.create_alert(alert_record)
    return api_response(data=saved, message="Alert created successfully", status_code=201)

@alerts_bp.route("/api/alerts/<alert_id>", methods=["PATCH", "PUT"])
def update_alert(alert_id):
    """
    Update alert read/acknowledged status.
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    data = request.get_json()
    is_read = data.get("is_read")
    if is_read is None:
        return error_response("Field 'is_read' boolean required", 400)

    org_id = get_tenant_organization_id()
    updated = Repository.update_alert(alert_id, {"is_read": bool(is_read)}, organization_id=org_id)
    if not updated:
        return error_response(f"Alert '{alert_id}' not found", 404)
    return api_response(data=updated, message="Alert updated successfully", status_code=200)

@alerts_bp.route("/api/alerts/acknowledge-all", methods=["POST"])
def acknowledge_all_alerts():
    """
    Mark all unread alerts as read for the authorized organization.
    """
    org_id = get_tenant_organization_id()
    alerts, _ = Repository.list_alerts(organization_id=org_id, filters={"is_read": False}, limit=200)
    count = 0
    for a in alerts:
        Repository.update_alert(a["alert_id"], {"is_read": True}, organization_id=org_id)
        count += 1
    return api_response(data={"acknowledged_count": count}, message="All alerts acknowledged", status_code=200)
