"""
AI Shield SaaS — Organization Settings, Audit Logs, and Executive Reports Blueprint.
"""

from datetime import datetime, timezone
from flask import Blueprint, request
from backend.auth import require_auth, get_tenant_organization_id, get_current_user
from backend.repository import Repository
from backend.utils.response import api_response, error_response

org_bp = Blueprint("organization", __name__)

@org_bp.route("/api/organization/profile", methods=["GET"])
@require_auth
def get_profile():
    """Retrieve organization profile and settings."""
    org_id = get_tenant_organization_id()
    org = Repository.get_organization(org_id)
    if not org:
        return error_response("Organization not found", 404)
    return api_response(data=org, message="Organization profile retrieved", status_code=200)

@org_bp.route("/api/organization/profile", methods=["PUT"])
@require_auth
def update_profile():
    """Update organization settings."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    user = get_current_user()
    org_id = get_tenant_organization_id()
    data = request.get_json()

    updated = Repository.update_organization(org_id, data)

    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user["sub"] if user else "system",
        actor_email=user.get("username", "system") if user else "system",
        action="UPDATE_ORG_PROFILE",
        resource=f"organizations/{org_id}",
        details="Organization profile updated",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    return api_response(data=updated, message="Organization profile updated successfully", status_code=200)

@org_bp.route("/api/organization/audit-logs", methods=["GET"])
@require_auth
def get_audit_logs():
    """Retrieve audit trail logs for tenant organization."""
    org_id = get_tenant_organization_id()
    limit = min(int(request.args.get("limit", 50)), 100)
    logs = Repository.list_audit_logs(org_id, limit=limit)
    return api_response(data=logs, message="Audit logs retrieved", status_code=200)

@org_bp.route("/api/organization/report", methods=["GET"])
@require_auth
def get_executive_report():
    """
    Generate an executive security report summarizing posture, compliance score,
    cloud status, endpoint EDR health, and critical incidents.
    """
    org_id = get_tenant_organization_id()
    org = Repository.get_organization(org_id)
    stats = Repository.get_dashboard_stats(org_id)
    sub = Repository.get_subscription(org_id)
    cloud = Repository.get_cloud_integration(org_id)
    wazuh = Repository.get_wazuh_integration(org_id)

    # Calculate compliance and hygiene score (0 - 100)
    base_score = 94.0
    if stats.get("critical_incidents", 0) > 0:
        base_score -= min(30.0, stats["critical_incidents"] * 10.0)
    if stats.get("open_incidents", 0) > 0:
        base_score -= min(15.0, stats["open_incidents"] * 2.5)
    if cloud and cloud.get("status") == "CONNECTED":
        base_score += 3.0
    if wazuh and wazuh.get("status") in ("ACTIVE", "LISTENING"):
        base_score += 3.0
    compliance_score = max(20.0, min(99.0, round(base_score, 1)))

    report = {
        "organization_id": org_id,
        "company_name": org.get("name") if org else "Enterprise",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "compliance_score": compliance_score,
        "posture_grade": "A" if compliance_score >= 90 else ("B" if compliance_score >= 75 else "C"),
        "metrics_summary": {
            "total_security_events": stats.get("total_events", 0),
            "open_incidents": stats.get("open_incidents", 0),
            "critical_incidents": stats.get("critical_incidents", 0),
            "resolved_incidents": stats.get("resolved_incidents", 0),
            "dlp_violations": stats.get("dlp_violations", 0),
            "api_threats_blocked": stats.get("api_threats", 0),
            "active_ai_agents": stats.get("active_agents", 0)
        },
        "integrations": {
            "cloud_provider": org.get("cloud_provider", "AWS") if org else "AWS",
            "cloud_status": cloud.get("status", "UNCONFIGURED") if cloud else "UNCONFIGURED",
            "cloud_findings": cloud.get("findings_count", 0) if cloud else 0,
            "wazuh_status": wazuh.get("status", "UNCONFIGURED") if wazuh else "UNCONFIGURED",
            "wazuh_agents": wazuh.get("agent_count", 0) if wazuh else 0
        },
        "subscription_tier": sub.get("tier", "STARTER"),
        "recommendations": [
            "Ensure AWS SecurityAudit role trust policy restricts access to AI Shield External ID.",
            "Verify all endpoint servers run Wazuh EDR agents with active heartbeat.",
            "Audit DLP policies quarterly for compliance with SOC2 and ISO 27001 standards."
        ]
    }

    return api_response(data=report, message="Executive security report generated", status_code=200)
