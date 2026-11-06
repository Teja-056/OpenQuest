"""
AI Shield SaaS — Wazuh Endpoint EDR Ingestion Blueprint.
Provides webhook endpoint for Wazuh alerts, agent status tracking,
and automated endpoint enrollment scripts.
"""

from flask import Blueprint, request
from backend.auth import require_auth, get_tenant_organization_id, get_current_user
from backend.repository import Repository
from backend.integrations.wazuh_client import WazuhIntegrationService
from backend.pipeline.event_processor import process_security_event
from backend.utils.response import api_response, error_response

wazuh_bp = Blueprint("wazuh", __name__)

@wazuh_bp.route("/api/integrations/wazuh/alert", methods=["POST"])
def ingest_wazuh_alert():
    """
    Ingest Wazuh EDR alert via webhook.
    Authenticates via:
      - X-Webhook-Secret header, OR
      - X-Organization-ID header, OR
      - ?organization_id= query param with valid secret
    """
    if not request.is_json:
        return error_response("Wazuh alert payload must be JSON", 400)

    raw_alert = request.get_json()

    # Determine tenant organization
    org_id = request.args.get("organization_id") or request.headers.get("X-Organization-ID")
    secret_header = request.headers.get("X-Webhook-Secret") or request.headers.get("X-Wazuh-Signature")

    wazuh_cfg = None
    if secret_header:
        wazuh_cfg = Repository.get_wazuh_by_secret(secret_header)
        if wazuh_cfg:
            org_id = wazuh_cfg["organization_id"]

    if not org_id and not wazuh_cfg:
        org_id = "org_default"

    # Enforce subscription endpoint limits
    allowed, limit_msg, sub = Repository.check_subscription_limits(org_id, "endpoint")
    if not allowed:
        return error_response(limit_msg, 429, details={"subscription": sub})

    # Normalize Wazuh alert to AI Shield SecurityEvent
    normalized_event = WazuhIntegrationService.normalize_wazuh_alert(raw_alert, org_id)

    # Process through central security pipeline (Rule Engine + Agent Guard + ML + Jev + Risk Engine)
    success, result, status_code = process_security_event(normalized_event)

    # Update Wazuh integration metrics
    agent_info = raw_alert.get("agent", {})
    existing = Repository.get_wazuh_integration(org_id)
    current_agents = existing.get("agent_count", 0) if existing else 0

    Repository.save_wazuh_integration(org_id, {
        "status": "ACTIVE",
        "agent_count": max(current_agents, 1),
        "last_alert_at": normalized_event.get("timestamp")
    })

    if not success:
        return error_response(str(result), status_code)

    return api_response(
        data=result,
        message="Wazuh endpoint alert ingested and processed through security pipeline",
        status_code=201
    )

@wazuh_bp.route("/api/integrations/wazuh/status", methods=["GET"])
@require_auth
def get_wazuh_status():
    """Retrieve Wazuh manager status, agent count, and enrollment credentials."""
    org_id = get_tenant_organization_id()
    integration = Repository.get_wazuh_integration(org_id)
    if not integration:
        integration = {
            "organization_id": org_id,
            "status": "UNCONFIGURED",
            "agent_count": 0,
            "webhook_secret": f"whsec_{org_id}",
            "manager_url": ""
        }

    enrollment = WazuhIntegrationService.generate_enrollment_commands(
        organization_id=org_id,
        manager_url=integration.get("manager_url", ""),
        enrollment_key=integration.get("webhook_secret", "")
    )

    return api_response(
        data={
            "integration": integration,
            "is_connected": integration.get("status") in ("ACTIVE", "LISTENING"),
            "enrollment_commands": enrollment
        },
        message="Wazuh status retrieved",
        status_code=200
    )

@wazuh_bp.route("/api/integrations/wazuh/configure", methods=["POST"])
@require_auth
def configure_wazuh():
    """Save Wazuh manager host URL and update webhook settings."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    user = get_current_user()
    org_id = get_tenant_organization_id()
    data = request.get_json()

    manager_url = str(data.get("manager_url", "")).strip()
    status = "LISTENING" if manager_url else "UNCONFIGURED"

    saved = Repository.save_wazuh_integration(org_id, {
        "manager_url": manager_url,
        "status": status
    })

    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user["sub"] if user else "system",
        actor_email=user.get("username", "system") if user else "system",
        action="CONFIGURE_WAZUH",
        resource=f"integrations/wazuh/{org_id}",
        details=f"Configured Wazuh manager: {manager_url}. Status: {status}",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    return api_response(
        data=saved,
        message="Wazuh endpoint configuration saved",
        status_code=200
    )
