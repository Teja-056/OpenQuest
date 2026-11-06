"""
AI Shield — API Threat Monitoring Routes Blueprint.
Provides /api/threats, /api/threats/blocked.
"""

from flask import Blueprint, request
from backend.repository import Repository
from backend.middleware.threat_detector import get_threat_detector
from backend.utils.response import api_response, error_response

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/api/threats", methods=["GET"])
def get_threats():
    """Retrieve logged API threats, rate limit events, and brute-force detections."""
    limit = min(int(request.args.get("limit", 50)), 200)
    threats = Repository.list_api_threats(limit=limit)
    return api_response(data=threats, message="API threat logs retrieved", status_code=200)

@threats_bp.route("/api/threats/status", methods=["GET"])
def get_threat_status():
    """Return active IP blocking state and rate limit parameters."""
    detector = get_threat_detector()
    active_blocks = []
    import time
    now = time.time()
    for ip, exp in detector._blocked_ips.items():
        if now < exp:
            active_blocks.append({"client_ip": ip, "remaining_seconds": round(exp - now, 1)})

    return api_response(
        data={
            "blocked_clients": active_blocks,
            "blocked_count": len(active_blocks),
            "window_seconds": 60,
            "burst_limit": 30
        },
        message="Active threat status retrieved",
        status_code=200
    )
