"""
AI Shield — Authentication Routes Blueprint.
Provides /api/auth/login, /api/auth/me, /api/auth/logout.
"""

from flask import Blueprint, request
from backend.auth import (
    verify_password,
    generate_token,
    require_auth,
    get_current_user
)
from backend.repository import Repository
from backend.utils.response import api_response, error_response

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    """
    Authenticate user with username and password.
    Returns signed Bearer JWT token and user profile.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return error_response("Both 'username' and 'password' are required", 400)

    user = Repository.get_user_by_username(username)
    if not user:
        return error_response("Invalid username or password", 401)

    if user.get("status") != "active":
        return error_response("User account is suspended or inactive", 403)

    if not verify_password(password, user.get("password_hash", "")):
        return error_response("Invalid username or password", 401)

    # Generate token
    token = generate_token(user)

    user_profile = {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "organization_id": user["organization_id"]
    }

    return api_response(
        data={"token": token, "user": user_profile},
        message="Authentication successful",
        status_code=200
    )

@auth_bp.route("/api/auth/me", methods=["GET"])
@require_auth
def get_current_profile():
    """Return profile of currently authenticated user session."""
    user = get_current_user()
    db_user = Repository.get_user_by_id(user["sub"]) if user else None
    if not db_user:
        return error_response("User session valid but record not found", 404)

    profile = {
        "user_id": db_user["user_id"],
        "username": db_user["username"],
        "email": db_user["email"],
        "role": db_user["role"],
        "organization_id": db_user["organization_id"],
        "status": db_user["status"],
        "created_at": db_user.get("created_at")
    }
    return api_response(data=profile, message="User profile retrieved", status_code=200)

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    """Client-side token revocation confirmation."""
    return api_response(data=None, message="Logged out successfully", status_code=200)
