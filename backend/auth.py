"""
AI Shield — Authentication and Role-Based Access Control (RBAC).
Provides cryptographically secure password hashing (PBKDF2-HMAC-SHA256),
JWT token generation/verification, and role authorization decorators.
"""

import os
import uuid
import hmac
import hashlib
import binascii
import json
import base64
from functools import wraps
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
from flask import request, jsonify, g
from backend.config import Config
from backend.repository import Repository
from backend.utils.response import error_response

# Supported Roles Hierarchy
ROLE_SUPER_ADMIN = "SUPER_ADMIN"
ROLE_ORG_ADMIN = "ORGANIZATION_ADMIN"
ROLE_ANALYST = "SECURITY_ANALYST"
ROLE_EMPLOYEE = "EMPLOYEE"

VALID_ROLES = {ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE}

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"{binascii.hexlify(salt).decode('ascii')}${binascii.hexlify(dk).decode('ascii')}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored salt$hash string."""
    try:
        salt_hex, key_hex = stored_hash.split("$", 1)
        salt = binascii.unhexlify(salt_hex.encode("ascii"))
        new_dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(binascii.hexlify(new_dk).decode("ascii"), key_hex)
    except Exception:
        return False

def generate_token(user: Dict[str, Any], expires_hours: Optional[int] = None) -> str:
    """
    Generate cryptographically signed Bearer JWT token.
    Uses HMAC-SHA256 with Config.SECRET_KEY.
    """
    if expires_hours is None:
        expires_hours = Config.JWT_EXPIRATION_HOURS

    exp = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    payload = {
        "sub": user["user_id"],
        "username": user["username"],
        "role": user.get("role", ROLE_ANALYST),
        "organization_id": user.get("organization_id", "org_default"),
        "exp": int(exp.timestamp())
    }

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    sig = hmac.new(Config.SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signature and expiration of JWT token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()

        # Verify signature
        expected_sig = hmac.new(Config.SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        # Decode payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode()
        payload = json.loads(payload_json)

        # Verify expiration
        exp_timestamp = payload.get("exp", 0)
        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        if now_timestamp > exp_timestamp:
            return None

        return payload
    except Exception:
        return None

def seed_default_users():
    """Ensure baseline admin and analyst accounts exist for demo/development."""
    if Config.ENV == "production":
        print("[Auth] Production environment detected: Hardcoded default users are disabled for security.")
        return

    default_users = [
        {
            "user_id": "USR-SUPERADMIN-001",
            "username": "superadmin",
            "email": "superadmin@aishield.local",
            "password_hash": hash_password("SuperAdmin@AIShield2026!"),
            "role": ROLE_SUPER_ADMIN,
            "organization_id": "org_default"
        },
        {
            "user_id": "USR-ADMIN-001",
            "username": "admin",
            "email": "admin@aishield.local",
            "password_hash": hash_password("Admin@AIShield2026!"),
            "role": ROLE_ORG_ADMIN,
            "organization_id": "org_default"
        },
        {
            "user_id": "USR-ANALYST-001",
            "username": "analyst",
            "email": "analyst@aishield.local",
            "password_hash": hash_password("Analyst@AIShield2026!"),
            "role": ROLE_ANALYST,
            "organization_id": "org_default"
        }
    ]

    for u in default_users:
        existing = Repository.get_user_by_username(u["username"])
        if not existing:
            Repository.create_user(u)

# Seed default users on startup
try:
    seed_default_users()
except Exception as e:
    print(f"[Auth] Notice: Default users check bypassed: {e}")

# ------------------------------------------------------------------------------
# RBAC Decorators
# ------------------------------------------------------------------------------
def get_current_user() -> Optional[Dict[str, Any]]:
    """Return user dict from request context or Bearer header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    return verify_token(token)

def get_tenant_organization_id() -> Optional[str]:
    """
    Enforce strict multi-tenant organization boundary.
    - Super Admins can view all tenants (returns None or explicit ?organization_id filter).
    - Regular Admins, Analysts, Employees: strictly returns their own user['organization_id'].
      Any client-supplied query parameter attempting to cross tenant boundary is ignored.
    - Unauthenticated context: defaults to 'org_default'.
    """
    user = get_current_user()
    if not user:
        return "org_default"

    user_role = user.get("role", "")
    if user_role == ROLE_SUPER_ADMIN:
        requested_org = request.args.get("organization_id")
        return requested_org if requested_org else None

    # Tenant lock: strictly enforced from verified JWT token
    return user.get("organization_id", "org_default")

def create_admin_account(username: str, password: str, email: str, role: str = ROLE_ORG_ADMIN, organization_id: str = "org_default") -> Dict[str, Any]:
    """Secure programmatic creation of administrative accounts for production setup."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}")
    user_record = {
        "user_id": f"USR-{uuid.uuid4().hex[:8].upper()}",
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "organization_id": organization_id,
        "status": "active"
    }
    return Repository.create_user(user_record)

def require_auth(f):
    """Decorator requiring a valid authenticated user session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return error_response("Authentication required: Missing or invalid Bearer token", 401)
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

def require_role(*allowed_roles):
    """Decorator requiring user to possess one of the allowed roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return error_response("Authentication required", 401)
            user_role = user.get("role", "")
            # Super admin can access anything
            if user_role == ROLE_SUPER_ADMIN:
                g.user = user
                return f(*args, **kwargs)

            if user_role not in allowed_roles:
                return error_response(f"Access denied: Requires role in {allowed_roles}", 403)

            g.user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator
