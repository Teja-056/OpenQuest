"""
AI Shield SaaS — Subscription Management Blueprint.
Provides tier selection, limit inspection, and administrator upgrade workflows.
"""

from flask import Blueprint, request
from backend.auth import require_auth, get_tenant_organization_id, get_current_user
from backend.repository import Repository
from backend.utils.response import api_response, error_response

subscription_bp = Blueprint("subscription", __name__)

TIER_SPECS = {
    "STARTER": {
        "tier": "STARTER",
        "name": "Starter Defense",
        "price_monthly": 49,
        "max_endpoints": 5,
        "max_cloud_accounts": 1,
        "description": "Essential cybersecurity monitoring for small startups and teams.",
        "features": [
            "Up to 5 endpoint agents",
            "1 AWS cloud account",
            "Basic security event monitoring",
            "Incident & alert management",
            "DLP detection",
            "Community support"
        ]
    },
    "PROFESSIONAL": {
        "tier": "PROFESSIONAL",
        "name": "Professional SOC",
        "price_monthly": 199,
        "max_endpoints": 25,
        "max_cloud_accounts": 3,
        "description": "Advanced AI-powered threat hunting and compliance for growing SMEs.",
        "features": [
            "Up to 25 endpoint agents",
            "3 AWS cloud accounts",
            "Isolation Forest ML anomaly detection",
            "TypeSafe Jev AI decision support",
            "Wazuh EDR deep integration",
            "Automated compliance reports",
            "Standard support"
        ]
    },
    "ENTERPRISE": {
        "tier": "ENTERPRISE",
        "name": "Enterprise Shield",
        "price_monthly": 499,
        "max_endpoints": 1000,
        "max_cloud_accounts": 50,
        "description": "Unrestricted scale, priority SLAs, dedicated intelligence, and custom policies.",
        "features": [
            "Unlimited / 1,000+ endpoints",
            "Up to 50 cloud accounts",
            "Custom ML model retraining",
            "Agent Guard zero-trust enforcement",
            "Real-time TypeSafe Jev & RLCD analysis",
            "Automated incident remediation",
            "24/7 dedicated SOC support"
        ]
    }
}

@subscription_bp.route("/api/subscription", methods=["GET"])
@require_auth
def get_subscription_status():
    """Retrieve tenant subscription details, active tier, and resource quotas."""
    org_id = get_tenant_organization_id()
    sub = Repository.get_subscription(org_id)
    tier_info = TIER_SPECS.get(sub.get("tier", "STARTER"), TIER_SPECS["STARTER"])

    max_end = sub.get("max_endpoints", 5)
    cur_end = sub.get("current_endpoints_count", 0)
    endpoint_usage_pct = min(100.0, round((cur_end / max(max_end, 1)) * 100, 1))

    max_cld = sub.get("max_cloud_accounts", 1)
    cur_cld = sub.get("current_cloud_accounts_count", 0)
    cloud_usage_pct = min(100.0, round((cur_cld / max(max_cld, 1)) * 100, 1))

    return api_response(
        data={
            "subscription": sub,
            "tier_spec": tier_info,
            "usage": {
                "endpoints": {
                    "current": cur_end,
                    "max": max_end,
                    "percentage": endpoint_usage_pct,
                    "at_limit": cur_end >= max_end and sub.get("tier") != "ENTERPRISE"
                },
                "cloud_accounts": {
                    "current": cur_cld,
                    "max": max_cld,
                    "percentage": cloud_usage_pct,
                    "at_limit": cur_cld >= max_cld and sub.get("tier") != "ENTERPRISE"
                }
            }
        },
        message="Subscription status retrieved",
        status_code=200
    )

@subscription_bp.route("/api/subscription/tiers", methods=["GET"])
def get_tiers():
    """Return available subscription plans and their limits."""
    return api_response(data=list(TIER_SPECS.values()), message="Subscription tiers retrieved", status_code=200)

@subscription_bp.route("/api/subscription/upgrade", methods=["POST"])
@require_auth
def upgrade_subscription():
    """Upgrade or downgrade tenant subscription tier."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    user = get_current_user()
    org_id = get_tenant_organization_id()
    data = request.get_json()

    tier = str(data.get("tier", "")).strip().upper()
    if tier not in TIER_SPECS:
        return error_response(f"Invalid subscription tier '{tier}'. Must be one of: {list(TIER_SPECS.keys())}", 400)

    updated = Repository.update_subscription(org_id, tier)

    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user["sub"] if user else "system",
        actor_email=user.get("username", "system") if user else "system",
        action="SUBSCRIPTION_TIER_CHANGED",
        resource=f"subscriptions/{org_id}",
        details=f"Subscription tier changed to {tier}",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    return api_response(
        data=updated,
        message=f"Subscription upgraded to {tier} successfully",
        status_code=200
    )
