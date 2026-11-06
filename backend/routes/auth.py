"""
AI Shield — SaaS Authentication & Onboarding Routes Blueprint.
Provides company registration, multi-step onboarding, and JWT session management.
"""

import re
import uuid
from flask import Blueprint, request
from backend.auth import (
    verify_password,
    hash_password,
    generate_token,
    require_auth,
    get_current_user,
    get_tenant_organization_id,
    ROLE_ORG_ADMIN
)
from backend.repository import Repository
from backend.utils.response import api_response, error_response

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    """
    Authenticate user with username or email, and password.
    Returns signed Bearer JWT token, user profile, and tenant organization metadata.
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    identifier = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not identifier or not password:
        return error_response("Both 'username' and 'password' are required", 400)

    # Check by username first; if not found, check by email
    user = Repository.get_user_by_username(identifier)
    if not user:
        user = Repository.get_user_by_email(identifier)

    if not user:
        return error_response("Invalid username or password", 401)

    if user.get("status") != "active":
        return error_response("User account is suspended or inactive", 403)

    if not verify_password(password, user.get("password_hash", "")):
        return error_response("Invalid username or password", 401)

    # Generate token
    token = generate_token(user)

    org = Repository.get_organization(user.get("organization_id", "org_default"))

    user_profile = {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "organization_id": user["organization_id"],
        "organization_name": org.get("name") if org else "Default Enterprise",
        "onboarding_completed": bool(org.get("onboarding_completed")) if org else True
    }

    return api_response(
        data={"token": token, "user": user_profile, "organization": org},
        message="Authentication successful",
        status_code=200
    )

@auth_bp.route("/api/auth/register-company", methods=["POST"])
def register_company():
    """
    Register a new SaaS company and administrator account.
    Fields:
      - company_name (str)
      - owner_name (str)
      - email (str)
      - phone (str)
      - industry (str)
      - country (str)
      - employee_count (int)
      - password (str)
    """
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    data = request.get_json()
    company_name = str(data.get("company_name", "")).strip()
    owner_name = str(data.get("owner_name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    phone = str(data.get("phone", "")).strip()
    industry = str(data.get("industry", "Technology")).strip()
    country = str(data.get("country", "United States")).strip()
    employee_count = int(data.get("employee_count", 10))
    password = str(data.get("password", "")).strip()
    subscription_tier = str(data.get("subscription_tier", "STARTER")).strip().upper()

    # Validation
    if not company_name:
        return error_response("Company name is required", 400)
    if not owner_name:
        return error_response("Owner name is required", 400)
    if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return error_response("A valid business email address is required", 400)
    if len(password) < 8:
        return error_response("Password must be at least 8 characters in length", 400)

    # Check for duplicate email
    if Repository.get_user_by_email(email):
        return error_response("An account with this email address is already registered", 409)

    # Generate unique organization ID
    slug = re.sub(r"[^a-zA-Z0-9]", "", company_name).lower()[:10] or "company"
    org_id = f"org_{slug}_{uuid.uuid4().hex[:6]}"

    # Generate unique username
    username_base = email.split("@")[0].lower()
    username = username_base
    suffix = 1
    while Repository.get_user_by_username(username):
        username = f"{username_base}{suffix}"
        suffix += 1

    # 1. Create Organization
    org_record = Repository.create_organization({
        "organization_id": org_id,
        "name": company_name,
        "owner_name": owner_name,
        "email": email,
        "phone": phone,
        "industry": industry,
        "country": country,
        "employee_count": employee_count,
        "subscription_tier": subscription_tier,
        "onboarding_completed": False,
        "onboarding_step": 1
    })

    # 2. Create Company Administrator User
    user_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
    admin_user = Repository.create_user({
        "user_id": user_id,
        "organization_id": org_id,
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": ROLE_ORG_ADMIN,
        "status": "active"
    })

    # 3. Create initial employee record for the owner
    emp_id = f"EMP-{uuid.uuid4().hex[:6].upper()}"
    Repository.create_employee({
        "employee_id": emp_id,
        "organization_id": org_id,
        "name": owner_name,
        "email": email,
        "department": "Executive",
        "role": "Company Administrator",
        "risk_score": 0.0,
        "status": "active"
    })

    # 4. Generate JWT token
    token = generate_token(admin_user)

    # 5. Audit Log
    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user_id,
        actor_email=email,
        action="REGISTER_COMPANY",
        resource=f"organizations/{org_id}",
        details=f"Company '{company_name}' registered with initial {subscription_tier} tier.",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    user_profile = {
        "user_id": admin_user["user_id"],
        "username": admin_user["username"],
        "email": admin_user["email"],
        "role": admin_user["role"],
        "organization_id": org_id,
        "organization_name": company_name,
        "onboarding_completed": False
    }

    return api_response(
        data={
            "token": token,
            "user": user_profile,
            "organization": org_record
        },
        message="Company registered successfully. Welcome to AI Shield!",
        status_code=201
    )

@auth_bp.route("/api/auth/onboarding", methods=["POST"])
@require_auth
def update_onboarding():
    """
    Save multi-step onboarding progress:
    - Step 1: Profile (industry, country, employee_count)
    - Step 2: Cloud infrastructure selection (AWS role / credentials)
    - Step 3: Endpoint configuration (Wazuh manager url)
    - Step 4: Subscription plan selection
    - Step 5: Onboarding completion
    """
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    user = get_current_user()
    org_id = user.get("organization_id", "org_default")
    data = request.get_json()

    step = int(data.get("step", 1))
    completed = bool(data.get("completed", False))

    org_updates = {"onboarding_step": step}
    if completed:
        org_updates["onboarding_completed"] = 1

    # Optional profile updates
    if "industry" in data:
        org_updates["industry"] = data["industry"]
    if "country" in data:
        org_updates["country"] = data["country"]
    if "employee_count" in data:
        org_updates["employee_count"] = int(data["employee_count"])

    # Optional cloud configuration
    cloud_data = data.get("cloud")
    if cloud_data and isinstance(cloud_data, dict):
        account_id = cloud_data.get("account_id", "").strip()
        role_arn = cloud_data.get("role_arn", "").strip()
        regions = cloud_data.get("regions", ["us-east-1"])
        if account_id and role_arn:
            Repository.save_cloud_integration(org_id, {
                "account_id": account_id,
                "role_arn": role_arn,
                "regions": regions,
                "status": "UNCONFIGURED"  # Requires live validation test
            })
            org_updates["cloud_provider"] = "AWS"

    # Optional wazuh configuration
    endpoint_data = data.get("endpoint")
    if endpoint_data and isinstance(endpoint_data, dict):
        manager_url = endpoint_data.get("manager_url", "").strip()
        if manager_url:
            Repository.save_wazuh_integration(org_id, {
                "manager_url": manager_url,
                "status": "UNCONFIGURED"
            })

    # Optional subscription tier update
    if "subscription_tier" in data:
        tier = data["subscription_tier"].upper()
        Repository.update_subscription(org_id, tier)
        org_updates["subscription_tier"] = tier

    updated_org = Repository.update_organization(org_id, org_updates)

    Repository.add_audit_log(
        organization_id=org_id,
        actor_id=user["sub"],
        actor_email=user["username"],
        action="UPDATE_ONBOARDING",
        resource=f"organizations/{org_id}/onboarding",
        details=f"Updated onboarding to step {step}. Completed: {completed}",
        ip_address=request.remote_addr or "127.0.0.1"
    )

    return api_response(
        data={"organization": updated_org, "step": step, "completed": completed},
        message="Onboarding configuration updated",
        status_code=200
    )

@auth_bp.route("/api/auth/onboarding-status", methods=["GET"])
@require_auth
def get_onboarding_status():
    """Return onboarding status, cloud connection status, and Wazuh setup status."""
    user = get_current_user()
    org_id = user.get("organization_id", "org_default")
    org = Repository.get_organization(org_id)
    cloud = Repository.get_cloud_integration(org_id)
    wazuh = Repository.get_wazuh_integration(org_id)
    sub = Repository.get_subscription(org_id)

    return api_response(
        data={
            "organization": org,
            "cloud_integration": cloud,
            "wazuh_integration": wazuh,
            "subscription": sub,
            "onboarding_completed": bool(org.get("onboarding_completed")) if org else False,
            "current_step": org.get("onboarding_step", 1) if org else 1
        },
        message="Onboarding status retrieved",
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

    org = Repository.get_organization(db_user.get("organization_id", "org_default"))

    profile = {
        "user_id": db_user["user_id"],
        "username": db_user["username"],
        "email": db_user["email"],
        "role": db_user["role"],
        "organization_id": db_user["organization_id"],
        "organization_name": org.get("name") if org else "Default Enterprise",
        "status": db_user["status"],
        "created_at": db_user.get("created_at")
    }
    return api_response(data=profile, message="User profile retrieved", status_code=200)

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    """Client-side token revocation confirmation."""
    return api_response(data=None, message="Logged out successfully", status_code=200)
