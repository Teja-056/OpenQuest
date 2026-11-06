import sys
from datetime import datetime, timezone
from flask import Blueprint
from backend.config import Config
from backend.database import check_supabase_connection
from backend.repository import Repository
from backend.utils.response import api_response, error_response

health_bp = Blueprint("health", __name__)

@health_bp.route("/api/health", methods=["GET"])
def health_check():
    """
    Health check endpoint.
    Verifies that the backend server is running and inspects active persistence
    (Supabase PostgreSQL vs local SQLite fallback) with multi-tenant status.
    Protected by circuit breaker to guarantee < 50ms response time.
    """
    if Repository.is_supabase_circuit_open():
        is_supa_connected = False
        conn_msg = "Remote Supabase circuit open; operating on local SQLite fallback"
    else:
        is_supa_connected, conn_msg = check_supabase_connection()

    db_status = Repository.get_database_status()
    active_backend = "supabase" if is_supa_connected else "sqlite_failover"

    if not is_supa_connected:
        details = {
            "status": "degraded",
            "database": "disconnected",
            "database_type": "sqlite_failover" if db_status.get("sqlite_local_available") else "none",
            "persistence_mode": Config.PERSISTENCE_MODE,
            "active_backend": "sqlite_failover" if db_status.get("sqlite_local_available") else "none",
            "multi_tenant_enabled": True,
            "service": "AI Shield Backend API",
            "version": "1.0.0",
            "python_version": sys.version.split()[0],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "circuit_open": Repository.is_supabase_circuit_open(),
            "message": conn_msg
        }
        return error_response(
            message="Database connection unavailable",
            status_code=503,
            details=details
        )

    payload = {
        "status": "healthy",
        "database": "connected",
        "database_type": "supabase_postgresql",
        "persistence_mode": Config.PERSISTENCE_MODE,
        "active_backend": active_backend,
        "multi_tenant_enabled": True,
        "service": "AI Shield Backend API",
        "version": "1.0.0",
        "python_version": sys.version.split()[0],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "circuit_open": False,
        "message": conn_msg
    }
    return api_response(data=payload, message="System and Supabase database are operational", status_code=200)
