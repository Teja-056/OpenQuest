"""
AI Shield — Data Loss Prevention (DLP) Routes Blueprint.
Provides /api/dlp/violations, /api/dlp/inspect, /api/dlp/policies, /api/dlp/quarantine/upload.
"""

from flask import Blueprint, request
from backend.repository import Repository
from security.dlp_engine import DLPEngine
from backend.auth import require_auth, require_role, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, get_tenant_organization_id
from backend.utils.response import api_response, error_response

dlp_bp = Blueprint("dlp", __name__)

@dlp_bp.route("/api/dlp/violations", methods=["GET"])
def list_dlp_violations():
    """Retrieve recorded DLP violations and quarantine events for organization."""
    org_id = get_tenant_organization_id()
    violations = Repository.list_dlp_violations(organization_id=org_id)
    return api_response(data=violations, message="DLP violations retrieved successfully", status_code=200)

@dlp_bp.route("/api/dlp/inspect", methods=["POST"])
def inspect_content():
    """
    Direct inspection endpoint to scan payload content for sensitive PII or secrets.
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    data = request.get_json()
    content = str(data.get("content", ""))
    resource_name = str(data.get("resource_name", "unspecified"))

    matches = DLPEngine.scan_content(content)
    classification = DLPEngine.classify_resource(resource_name, matches=matches)

    return api_response(
        data={
            "classification": classification,
            "sensitive_patterns_found": len(matches) > 0,
            "matches_count": len(matches),
            "matches": matches
        },
        message="Content inspected successfully",
        status_code=200
    )

@dlp_bp.route("/api/dlp/policies", methods=["GET"])
def list_policies():
    """List active security and DLP policies."""
    policies = Repository.list_dlp_policies()
    return api_response(data=policies, message="Policies retrieved successfully", status_code=200)

@dlp_bp.route("/api/dlp/policies", methods=["POST"])
@require_auth
@require_role(ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN)
def create_policy():
    """Create or update a security policy."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    data = request.get_json()
    if not data.get("policy_name"):
        return error_response("Field 'policy_name' is required", 400)

    created = Repository.create_dlp_policy(data)
    return api_response(data=created, message="Policy registered successfully", status_code=201)

@dlp_bp.route("/api/dlp/quarantine/upload", methods=["POST"])
def quarantine_upload():
    """
    Safely quarantine an uploaded file without path traversal risk.
    """
    if "file" not in request.files:
        return error_response("No file provided in multipart form data (key: 'file')", 400)

    file_obj = request.files["file"]
    if not file_obj.filename:
        return error_response("Empty filename provided", 400)

    content_bytes = file_obj.read()
    success, msg, path = DLPEngine.quarantine_file(file_obj.filename, content_bytes)

    if not success:
        return error_response(msg, 400)

    return api_response(
        data={"filename": file_obj.filename, "quarantine_path": path, "size_bytes": len(content_bytes)},
        message=msg,
        status_code=201
    )
