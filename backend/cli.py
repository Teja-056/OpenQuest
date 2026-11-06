"""
AI Shield — Production Administration & Database CLI.
Provides operational utilities for:
- Initializing production administrative accounts without hardcoded defaults.
- Verifying database consistency across remote Supabase and local SQLite.
- Printing or executing database schema migrations.
"""

import sys
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Config
from backend.repository import Repository
from backend.auth import create_admin_account, ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ANALYST

def cmd_init_admin(args):
    """Securely bootstrap an initial administrator account."""
    print("=" * 60)
    print("AI-SHIELD PRODUCTION ADMINISTRATOR INITIALIZATION")
    print("=" * 60)
    username = args.username.strip()
    password = args.password.strip()
    email = args.email.strip()
    role = args.role.strip()
    org_id = args.org.strip()

    if len(password) < 12:
        print("ERROR: Administrator password must be at least 12 characters long.")
        sys.exit(1)

    existing = Repository.get_user_by_username(username)
    if existing:
        print(f"ERROR: User '{username}' already exists.")
        sys.exit(1)

    user = create_admin_account(
        username=username,
        password=password,
        email=email,
        role=role,
        organization_id=org_id
    )
    print(f"SUCCESS: Created {role} user '{username}' (User ID: {user['user_id']}) for organization '{org_id}'.")

def cmd_check_db(args):
    """Audit database consistency and report active persistence layer."""
    print("=" * 60)
    print("AI-SHIELD DATABASE CONSISTENCY AUDIT")
    print("=" * 60)
    status = Repository.get_database_status()
    print(f"Configured Persistence Mode: {Config.PERSISTENCE_MODE}")
    print(f"Active Backend:              {status['active_backend']}")
    print(f"Supabase Configured:         {status['supabase_configured']}")
    print(f"Supabase Connected:          {status['supabase_connected']}")
    print("\nTable Consistency Inspection:")
    for table_name, details in status.get("tables", {}).items():
        print(f"  - {table_name:<20}: remote_supabase={str(details.get('in_supabase')):<5}  local_sqlite={str(details.get('in_sqlite')):<5}")

def main():
    parser = argparse.ArgumentParser(description="AI-Shield Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-admin
    p_admin = subparsers.add_parser("init-admin", help="Bootstrap a production administrator account")
    p_admin.add_argument("--username", required=True, help="Administrator username")
    p_admin.add_argument("--password", required=True, help="Secure password (min 12 chars)")
    p_admin.add_argument("--email", required=True, help="Administrator email address")
    p_admin.add_argument("--role", default=ROLE_ORG_ADMIN, choices=[ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ANALYST], help="Assigned role")
    p_admin.add_argument("--org", default="org_default", help="Organization identifier")
    p_admin.set_defaults(func=cmd_init_admin)

    # check-db
    p_db = subparsers.add_parser("check-db", help="Audit database consistency and table presence")
    p_db.set_defaults(func=cmd_check_db)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
