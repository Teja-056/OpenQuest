"""
AI Shield — API Threat Detection & Rate Limiting Engine.
Monitors client IPs, tracks request frequencies, detects brute force attempts,
evaluates threat scores, and enforces sliding-window rate limits.
"""

import time
from collections import defaultdict
from typing import Dict, Any, Tuple, Optional, List
from flask import request
from backend.config import Config
from backend.repository import Repository

class APIThreatDetector:
    """
    Sliding-window request rate limiter and suspicious client monitor.
    """
    def __init__(self):
        # Maps client_ip -> list of request timestamps [t1, t2, ...]
        self._request_history = defaultdict(list)
        # Maps client_ip -> failed login attempt timestamps
        self._failed_auth_history = defaultdict(list)
        # Blocked client IPs until timestamp
        self._blocked_ips = {}

    def get_client_ip(self) -> str:
        """
        Extract client IP safely.
        Validates IP format and prevents arbitrary header spoofing.
        """
        raw_ip = request.remote_addr or "127.0.0.1"
        # Only trust X-Forwarded-For if incoming connection is from local/reverse proxy
        if request.headers.get("X-Forwarded-For") and raw_ip in ("127.0.0.1", "::1", "localhost", "10.0.0.0/8"):
            forwarded = request.headers["X-Forwarded-For"].split(",")[0].strip()
            # Basic validation of IP characters
            if all(c in "0123456789abcdefABCDEF.:" for c in forwarded) and len(forwarded) <= 45:
                return forwarded
        return raw_ip

    def evaluate_request(self) -> Tuple[bool, Optional[str], float]:
        """
        Evaluate incoming HTTP request.
        Returns: (is_allowed: bool, violation_reason: Optional[str], threat_score: float)
        """
        client_ip = self.get_client_ip()
        now = time.time()
        window = Config.RATE_LIMIT_WINDOW
        burst_limit = Config.RATE_LIMIT_BURST

        # For localhost / dashboard operator development, allow a generous burst limit
        if client_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
            burst_limit = max(burst_limit, 500)

        # 1. Check if IP is currently under temporary restriction
        if client_ip in self._blocked_ips:
            block_expires = self._blocked_ips[client_ip]
            if now < block_expires:
                return False, f"Client IP '{client_ip}' temporarily blocked for abusive request rate. Try again later.", 95.0
            else:
                del self._blocked_ips[client_ip]

        # 2. Clean sliding window history
        timestamps = [t for t in self._request_history[client_ip] if now - t < window]
        timestamps.append(now)
        self._request_history[client_ip] = timestamps

        req_count = len(timestamps)

        # 3. Rate Limit Enforcement
        if req_count > burst_limit:
            # Block client for 20 seconds
            self._blocked_ips[client_ip] = now + 20.0
            threat_record = {
                "client_ip": client_ip,
                "endpoint": request.path,
                "method": request.method,
                "threat_type": "rate_limit_exceeded",
                "threat_score": 90.0,
                "request_count": req_count,
                "details": f"Exceeded {burst_limit} requests within {window}s window ({req_count} requests recorded)."
            }
            Repository.record_api_threat(threat_record)
            return False, f"Rate limit exceeded: {req_count} requests in {window}s (Limit: {burst_limit})", 90.0

        # 4. Evaluate Threat Score
        threat_score = 10.0
        if req_count > (burst_limit * 0.7):
            threat_score = 65.0
        elif req_count > (burst_limit * 0.4):
            threat_score = 35.0

        # Check for abuse of sensitive endpoints
        sensitive_endpoints = ["/api/auth/login", "/api/events", "/api/agents"]
        if any(request.path.startswith(ep) for ep in sensitive_endpoints) and req_count > 15:
            threat_score = max(threat_score, 75.0)

        return True, None, threat_score

    def record_failed_auth(self, client_ip: str):
        """Track failed authentication to catch brute force attacks."""
        now = time.time()
        history = [t for t in self._failed_auth_history[client_ip] if now - t < 300]  # 5 min window
        history.append(now)
        self._failed_auth_history[client_ip] = history

        if len(history) >= 5:
            # Block client for 300 seconds
            self._blocked_ips[client_ip] = now + 300.0
            threat_record = {
                "client_ip": client_ip,
                "endpoint": "/api/auth/login",
                "method": "POST",
                "threat_type": "brute_force",
                "threat_score": 95.0,
                "request_count": len(history),
                "details": f"Brute force detection: {len(history)} failed logins in 5 minutes."
            }
            Repository.record_api_threat(threat_record)
            print(f"[APIThreatDetector] ALERT: Brute force lockout applied to client IP {client_ip}.")

# Global detector singleton
_threat_detector = APIThreatDetector()

def get_threat_detector() -> APIThreatDetector:
    return _threat_detector
