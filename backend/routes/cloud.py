"""
AI Shield SaaS — AWS Cloud Security Routes Blueprint.
Manages AWS connections via STS AssumeRole, status verification,
CloudTrail & Security Hub polling, and IAM trust policy generation.
"""

from flask import Blueprint, request
from backend.auth import require_auth, get_tenant_organization_id, get_current_user
from backend.repository import Repository
from backend.integrations.aws_client import AWSIntegrationService
from backend.pipeline.event_processor import process_security_event
from backend.utils.response import api_response, error_response

cloud_bp = Blueprint("cloud", __name__)

@cloud_bp.route("/api/cloud/aws/status", methods=["GET"])
@require_auth
def get_aws_status():
    """Retrieve AWS integration status, configuration, and IAM trust policy."""
    org_id = get_tenant_organization_id()
    integration = Repository.get_cloud_integration(org_id, provider="AWS")
    if not integration:
        integration = {
            "organization_id": org_id,
            "provider": "AWS",
            "account_id": "",
            "role_arn": "",
            "external_id": f"aishield-{org_id}-def",
            "regions": ["us-east-1"],
            "status": "UNCONFIGURED",
            "findings_count": 0
        }

    trust_policy = AWSIntegrationService.generate_trust_policy(integration.get("external_id", ""))

    return api_response(
        data={
            "integration": integration,
            "is_connected": integration.get("status") == "CONNECTED",
            "trust_policy": trust_policy
        },
        message="AWS integration status retrieved",
        status_code=200
    )

@cloud_bp.route("/api/cloud/aws/connect", methods=["POST"])
@require_auth
def connect_aws():
    """
    Connect and validate customer's AWS account.
    Expects JSON: { account_id, role_arn, regions }
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    user = get_current_user()
    org_id = get_tenant_organization_id()
    data = request.get_json()

    account_id = str(data.get("account_id", "")).strip()
    role_arn = str(data.get("role_arn", "")).strip()
    regions = data.get("regions", ["us-east-1"])
    if isinstance(regions, str):
        regions = [regions]

    # Check subscription limit for cloud accounts
    allowed, limit_msg, sub = Repository.check_subscription_limits(org_id, "cloud_account")
    if not allowed:
        return error_response(limit_msg, 403, details={"subscription": sub})

    # Retrieve or generate external_id
    existing = Repository.get_cloud_integration(org_id, "AWS")
    external_id = existing.get("external_id") if existing else f"aishield-{org_id}-sec"

    # Test actual connection
    test_res = AWSIntegrationService.test_connection(account_id, role_arn, external_id, regions)

    # Save integration record
    new_status = test_res.get("status", "UNCONFIGURED")
    saved = Repository.save_cloud_integration(org_id, {
        "account_id": account_id,
        "role_arn": role_arn,
        "external_id": external_id,
        "regions": regions,
        "status": new_status,
        "error_message": test_res.get("error"),
        "findings_count": existing.get("findings_count", 0) if existing else 0
    })

    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user["sub"] if user else "system",
        actor_email=user.get("username", "unknown") if user else "system",
        action="AWS_CONNECT_ATTEMPT",
        resource=f"cloud_integrations/aws/{account_id}",
        details=f"AWS connection status: {new_status}. Error: {test_res.get('error')}",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    if test_res.get("is_connected"):
        return api_response(
            data={"integration": saved, "test_result": test_res},
            message="AWS connection verified and activated successfully!",
            status_code=200
        )
    else:
        return api_response(
            data={"integration": saved, "test_result": test_res},
            message=f"AWS connection test: {test_res.get('error', 'Configuration required')}",
            status_code=200
        )

@cloud_bp.route("/api/cloud/aws/sync", methods=["POST"])
@require_auth
def sync_aws():
    """
    Synchronize CloudTrail events and Security Hub findings for active AWS connection.
    Feeds high-severity findings into the central event pipeline.
    """
    org_id = get_tenant_organization_id()
    integration = Repository.get_cloud_integration(org_id, "AWS")

    if not integration or integration.get("status") != "CONNECTED":
        return error_response("AWS integration is not connected. Please configure and test AWS role first.", 400)

    role_arn = integration.get("role_arn", "")
    external_id = integration.get("external_id", "")
    regions = integration.get("regions", ["us-east-1"])

    ct_events, ct_err = AWSIntegrationService.fetch_cloudtrail_events(role_arn, external_id, regions)
    sh_findings, sh_err = AWSIntegrationService.fetch_security_hub_findings(role_arn, external_id, regions)

    # Ingest findings into security events pipeline
    ingested_count = 0
    for finding in sh_findings:
        sev = finding.get("severity", "MEDIUM").lower()
        evt_payload = {
            "organization_id": org_id,
            "event_type": "cloud_security_finding",
            "actor_type": "external",
            "actor_id": "AWS-SecurityHub",
            "resource": finding.get("resource_type", "AWS::Resource"),
            "is_sensitive": sev in ("high", "critical"),
            "action": finding.get("title", "Security Hub Finding"),
            "destination": regions[0] if regions else "us-east-1",
            "source": "aws_security_hub",
            "description": finding.get("description", "Security Hub finding alert"),
            "risk_score": 85.0 if sev == "critical" else (70.0 if sev == "high" else 45.0),
            "risk_level": sev,
            "recommended_action": "Remediate finding in AWS console"
        }
        process_security_event(evt_payload)
        ingested_count += 1

    total_findings = len(sh_findings)
    Repository.save_cloud_integration(org_id, {
        "account_id": integration.get("account_id"),
        "role_arn": role_arn,
        "external_id": external_id,
        "regions": regions,
        "status": "CONNECTED",
        "findings_count": total_findings,
        "last_sync_at": None  # Repository will set to now
    })

    return api_response(
        data={
            "cloudtrail_events_count": len(ct_events),
            "security_hub_findings_count": len(sh_findings),
            "ingested_into_pipeline": ingested_count,
            "cloudtrail_events": ct_events[:10],
            "security_hub_findings": sh_findings[:10]
        },
        message="AWS synchronization completed successfully",
        status_code=200
    )

@cloud_bp.route("/api/cloud/aws/trust-policy", methods=["GET"])
@require_auth
def get_trust_policy():
    """Return customer-specific AWS IAM Trust Policy JSON."""
    org_id = get_tenant_organization_id()
    integration = Repository.get_cloud_integration(org_id, "AWS")
    external_id = integration.get("external_id") if integration else f"aishield-{org_id}-def"
    policy = AWSIntegrationService.generate_trust_policy(external_id)
    return api_response(
        data={"trust_policy": policy, "external_id": external_id},
        message="IAM Trust Policy generated",
        status_code=200
    )
