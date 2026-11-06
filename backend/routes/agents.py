"""
AI Shield — AI Agent Management Routes Blueprint.
Provides /api/agents, /api/agents/<id>, /api/agents/<id>/status, /api/agents/<id>/violations.
Enforces multi-tenant organization isolation and least-privilege boundary checks.
"""

from flask import Blueprint, request
from backend.repository import Repository
from security.agent_guard import AgentGuard
from backend.auth import require_auth, require_role, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, get_current_user, get_tenant_organization_id
from backend.utils.response import api_response, error_response

agents_bp = Blueprint("agents", __name__)

@agents_bp.route("/api/agents", methods=["GET"])
def list_agents():
    """Retrieve all registered AI agents with optional status filtering within organization."""
    status = request.args.get("status")
    org_id = get_tenant_organization_id()
    agents = Repository.list_agents(organization_id=org_id, status=status)
    return api_response(data=agents, message="Agents retrieved successfully", status_code=200)

@agents_bp.route("/api/agents/<agent_id>", methods=["GET"])
def get_agent(agent_id):
    """Retrieve details for a specific AI agent within caller's organization."""
    org_id = get_tenant_organization_id()
    agent = Repository.get_agent(agent_id, organization_id=org_id)
    if not agent:
        return error_response(f"Agent with ID '{agent_id}' not found", 404)
    return api_response(data=agent, message="Agent retrieved successfully", status_code=200)

@agents_bp.route("/api/agents", methods=["POST"])
@require_auth
@require_role(ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN)
def register_agent():
    """Register a new AI agent with least-privilege permission matrix."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    data = request.get_json()
    name = str(data.get("name", "")).strip()
    if not name:
        return error_response("Field 'name' is required", 400)

    org_id = get_tenant_organization_id()
    data["organization_id"] = org_id

    created = Repository.create_agent(data)
    return api_response(data=created, message="AI Agent registered successfully", status_code=201)

@agents_bp.route("/api/agents/<agent_id>/status", methods=["PATCH", "PUT"])
@require_auth
@require_role(ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN)
def update_agent_status(agent_id):
    """
    Update status of an AI agent (e.g. suspend or reactivate).
    Requires administrative privileges and mandatory audit justification.
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    data = request.get_json()
    new_status = str(data.get("status", "")).strip().lower()
    if new_status not in ("active", "suspended", "under_investigation", "revoked"):
        return error_response(f"Invalid status '{new_status}'. Allowed: active, suspended, under_investigation, revoked", 400)

    user = get_current_user() or {}
    admin_name = user.get("username", "admin")
    reason = str(data.get("reason", "")).strip()

    # Enforce non-empty justification for status changes (especially reactivation)
    if not reason:
        return error_response("A non-empty 'reason' justification is required for agent status changes", 400)

    org_id = get_tenant_organization_id()
    updated = Repository.update_agent_status(
        agent_id,
        new_status,
        reason=f"Changed by {admin_name}: {reason}",
        organization_id=org_id
    )
    if not updated:
        return error_response(f"Agent '{agent_id}' not found", 404)

    return api_response(data=updated, message=f"Agent status updated to '{new_status}'", status_code=200)

@agents_bp.route("/api/agents/<agent_id>/violations", methods=["GET"])
def get_agent_violations(agent_id):
    """Retrieve violation audit history for an AI agent."""
    org_id = get_tenant_organization_id()
    violations = Repository.list_agent_violations(agent_id=agent_id, organization_id=org_id)
    return api_response(data=violations, message="Violations retrieved successfully", status_code=200)
