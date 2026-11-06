import uuid
from flask import Blueprint, request
from backend.repository import Repository
from backend.auth import get_tenant_organization_id, require_auth, require_role, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ANALYST
from backend.utils.response import api_response, error_response
from backend.utils.validation import validate_employee_payload, get_current_iso_timestamp

employees_bp = Blueprint("employees", __name__)

@employees_bp.route("/api/employees", methods=["GET"])
def get_employees():
    """
    Retrieve employees partitioned by tenant organization.
    Supports optional query filters: department, status, limit, offset.
    """
    department = request.args.get("department")
    status = request.args.get("status")
    org_id = get_tenant_organization_id()

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error_response("Query parameters 'limit' and 'offset' must be valid integers", 400)

    employees, total_count = Repository.list_employees(
        organization_id=org_id,
        department=department,
        status=status,
        limit=limit,
        offset=offset
    )

    meta = {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "returned": len(employees)
    }
    return api_response(data=employees, message="Employees retrieved successfully", meta=meta, status_code=200)

@employees_bp.route("/api/employees/<employee_id>", methods=["GET"])
def get_employee(employee_id):
    """Retrieve a single employee within the caller's authorized organization."""
    org_id = get_tenant_organization_id()
    employee = Repository.get_employee(employee_id, organization_id=org_id)
    if not employee:
        return error_response(f"Employee with ID '{employee_id}' not found", 404)
    return api_response(data=employee, message="Employee retrieved successfully", status_code=200)

@employees_bp.route("/api/employees", methods=["POST"])
def create_employee():
    """Register a new employee into caller's organization."""
    if not request.is_json:
        return error_response("Request body must be JSON with Content-Type: application/json", 400)

    payload = request.get_json()
    is_valid, err_msg, cleaned = validate_employee_payload(payload)
    if not is_valid:
        return error_response(err_msg, 400)

    org_id = get_tenant_organization_id()
    cleaned["organization_id"] = org_id

    # Check for existing employee_id conflict
    existing = Repository.get_employee(cleaned["employee_id"], organization_id=org_id)
    if existing:
        return error_response(f"Employee with ID '{cleaned['employee_id']}' already exists", 409)

    # Check for email conflict
    all_emps, _ = Repository.list_employees(organization_id=org_id, limit=200)
    if any(e.get("email") == cleaned["email"] for e in all_emps):
        return error_response(f"Employee with email '{cleaned['email']}' already exists", 409)

    created = Repository.create_employee(cleaned)
    return api_response(data=created, message="Employee created successfully", status_code=201)

@employees_bp.route("/api/employees/<employee_id>", methods=["PATCH", "PUT"])
def update_employee(employee_id):
    """Update employee details (status, department, role, risk_score)."""
    if not request.is_json:
        return error_response("Request body must be JSON", 400)

    org_id = get_tenant_organization_id()
    data = request.get_json()
    allowed_updates = {}
    for key in ("name", "department", "role", "status", "risk_score"):
        if key in data:
            allowed_updates[key] = data[key]

    updated = Repository.update_employee(employee_id, allowed_updates, organization_id=org_id)
    if not updated:
        return error_response(f"Employee with ID '{employee_id}' not found", 404)
    return api_response(data=updated, message="Employee updated successfully", status_code=200)

@employees_bp.route("/api/employees/<employee_id>", methods=["DELETE"])
def delete_employee(employee_id):
    """Remove employee record from organization."""
    org_id = get_tenant_organization_id()
    success = Repository.delete_employee(employee_id, organization_id=org_id)
    if not success:
        return error_response(f"Employee with ID '{employee_id}' not found", 404)
    return api_response(data=None, message="Employee deleted successfully", status_code=200)
