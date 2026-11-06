import re
import uuid
from flask import Blueprint, request
from backend.repository import Repository
from backend.auth import get_tenant_organization_id
from backend.utils.response import api_response, error_response
from backend.utils.validation import get_current_iso_timestamp

incidents_bp = Blueprint("incidents", __name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved", "false_positive", "closed"}
DANGEROUS_QUERY_CHARS = re.compile(r"['\";]|--|/\*|\*/")

@incidents_bp.route("/api/incidents", methods=["GET"])
def get_incidents():
    """
    Retrieve security incidents partitioned by tenant organization.
    Supports optional filters: severity, status, actor_id, limit, offset.
    """
    severity = request.args.get("severity")
    status = request.args.get("status")
    actor_id = request.args.get("actor_id")
    org_id = get_tenant_organization_id()

    # Input validation
    for param_name, param_val in [("severity", severity), ("status", status), ("actor_id", actor_id)]:
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
    if status:
        filters["status"] = status.lower()
    if actor_id:
        filters["actor_id"] = actor_id

    incidents, total_count = Repository.list_incidents(
        organization_id=org_id,
        filters=filters,
        limit=limit,
        offset=offset
    )

    meta = {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "returned": len(incidents)
    }
    return api_response(data=incidents, message="Incidents retrieved successfully", meta=meta, status_code=200)

@incidents_bp.route("/api/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """Retrieve a single incident within the caller's authorized organization."""
    org_id = get_tenant_organization_id()
    incident = Repository.get_incident(incident_id, organization_id=org_id)
    if not incident:
        return error_response(f"Incident with ID '{incident_id}' not found", 404)
    return api_response(data=incident, message="Incident retrieved successfully", status_code=200)

@incidents_bp.route("/api/incidents", methods=["POST"])
def create_incident():
    """
    Create a new security incident within tenant organization.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    if not isinstance(data, dict):
        return error_response("Payload must be a JSON object", 400)

    required_fields = ["title", "description", "severity"]
    for field in required_fields:
        val = data.get(field)
        if not val or not str(val).strip():
            return error_response(f"Missing or empty required field: '{field}'", 400)

    title = str(data["title"]).strip()
    description = str(data["description"]).strip()
    severity = str(data["severity"]).strip().lower()

    if severity not in VALID_SEVERITIES:
        return error_response(f"Invalid severity '{severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}", 400)

    status = str(data.get("status", "open")).strip().lower()
    if status not in VALID_INCIDENT_STATUSES:
        return error_response(f"Invalid status '{status}'. Must be one of: {sorted(list(VALID_INCIDENT_STATUSES))}", 400)

    incident_id = data.get("incident_id")
    if incident_id:
        incident_id = str(incident_id).strip()
    else:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    org_id = get_tenant_organization_id()

    # Check for existing incident conflict
    existing = Repository.get_incident(incident_id, organization_id=org_id)
    if existing:
        return error_response(f"Incident with ID '{incident_id}' already exists", 409)

    incident_record = {
        "incident_id": incident_id,
        "organization_id": org_id,
        "title": title,
        "description": description,
        "severity": severity,
        "status": status,
        "actor_id": data.get("actor_id"),
        "event_id": data.get("event_id"),
        "assigned_to": data.get("assigned_to"),
        "resolved_at": None,
        "created_at": get_current_iso_timestamp(),
        "updated_at": get_current_iso_timestamp()
    }

    saved = Repository.create_incident(incident_record)
    return api_response(data=saved, message="Incident created successfully", status_code=201)

@incidents_bp.route("/api/incidents/<incident_id>", methods=["PATCH", "PUT"])
def update_incident(incident_id):
    """
    Update incident status, assigned analyst, or resolution notes.
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    org_id = get_tenant_organization_id()
    data = request.get_json()
    updates = {}
    now_iso = get_current_iso_timestamp()

    if "status" in data:
        st = str(data["status"]).strip().lower()
        if st not in VALID_INCIDENT_STATUSES:
            return error_response(f"Invalid status '{st}'. Allowed: {sorted(list(VALID_INCIDENT_STATUSES))}", 400)
        updates["status"] = st
        if st in ("resolved", "closed"):
            updates["resolved_at"] = now_iso

    if "assigned_to" in data:
        updates["assigned_to"] = str(data["assigned_to"]).strip()

    if "description" in data:
        updates["description"] = str(data["description"]).strip()

    if not updates:
        return error_response("No valid fields provided for update", 400)

    updated = Repository.update_incident(incident_id, updates, organization_id=org_id)
    if not updated:
        return error_response(f"Incident '{incident_id}' not found", 404)
    return api_response(data=updated, message="Incident updated successfully", status_code=200)
