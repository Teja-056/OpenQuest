"""
AI Shield — Dashboard Analytics & Aggregated Metrics Blueprint.
Provides live, dynamic security stats calculated directly from database records,
strictly partitioned by tenant organization.
"""

from flask import Blueprint, request
from backend.repository import Repository
from backend.auth import get_tenant_organization_id
from backend.utils.response import api_response, error_response

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """
    Compute live operational metrics across all modules for authorized organization.
    Never returns hardcoded or faked data.
    """
    try:
        org_id = get_tenant_organization_id()
        stats_payload = Repository.get_dashboard_stats(organization_id=org_id)
        return api_response(data=stats_payload, message="Dashboard metrics computed successfully", status_code=200)

    except RuntimeError as re:
        return error_response("Database configuration error", 503, details=str(re))
    except Exception as e:
        return error_response("Failed to generate dashboard statistics", 500, details=str(e))
