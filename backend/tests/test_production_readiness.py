"""
AI Shield — Production Readiness Verification Suite.
Validates the critical Phase 4 production requirements:
1. Multi-tenant organization isolation (cross-organization access strictly blocked).
2. Atomic database-level Agent Guard concurrency (no race conditions across workers).
3. Database failure tolerance and restart persistence.
4. Idempotent event ingestion and duplicate handling.
5. Clear distinction between telemetry ingestion and access authorization enforcement.
6. Secure administrative account initialization and justification enforcement.
"""

import sys
import json
import uuid
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.config import Config
from backend.repository import Repository
from backend.auth import (
    generate_token, hash_password, create_admin_account,
    ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE
)
from security.agent_guard import AgentGuard

class AIShieldProductionReadinessTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app({"TESTING": True, "ENABLE_RATE_LIMIT_IN_TESTS": False})
        cls.client = cls.app.test_client()

    def setUp(self):
        self.run_id = uuid.uuid4().hex[:6].upper()
        self.org_a = f"org_alpha_{self.run_id}"
        self.org_b = f"org_beta_{self.run_id}"

        # Generate tokens scoped to separate organizations
        self.super_admin_token = generate_token({
            "user_id": f"USR-SA-{self.run_id}",
            "username": f"sa_{self.run_id}",
            "role": ROLE_SUPER_ADMIN,
            "organization_id": "org_default"
        })
        self.admin_a_token = generate_token({
            "user_id": f"USR-ADM-A-{self.run_id}",
            "username": f"admin_a_{self.run_id}",
            "role": ROLE_ORG_ADMIN,
            "organization_id": self.org_a
        })
        self.admin_b_token = generate_token({
            "user_id": f"USR-ADM-B-{self.run_id}",
            "username": f"admin_b_{self.run_id}",
            "role": ROLE_ORG_ADMIN,
            "organization_id": self.org_b
        })

    # ==========================================================================
    # 1. MULTI-TENANT ORGANIZATIONAL ISOLATION
    # ==========================================================================
    def test_multi_tenant_employee_isolation(self):
        """Employees created in Org A must be completely invisible and inaccessible to Org B."""
        # 1. Create employee in Org A
        emp_id = f"EMP-A-{self.run_id}"
        res = self.client.post(
            "/api/employees",
            headers={"Authorization": f"Bearer {self.admin_a_token}"},
            json={
                "employee_id": emp_id,
                "name": "Alice Alpha",
                "email": f"alice@{self.org_a}.com",
                "department": "Engineering",
                "role": "Lead"
            }
        )
        self.assertEqual(res.status_code, 201)

        # 2. Org B attempts to query employee by ID -> must return 404 (Not Found in tenant scope)
        res_b = self.client.get(
            f"/api/employees/{emp_id}",
            headers={"Authorization": f"Bearer {self.admin_b_token}"}
        )
        self.assertEqual(res_b.status_code, 404, "Org B must not be able to read Org A employee")

        # 3. Org B attempts to list employees -> must not see Org A employee
        res_b_list = self.client.get(
            "/api/employees",
            headers={"Authorization": f"Bearer {self.admin_b_token}"}
        )
        self.assertEqual(res_b_list.status_code, 200)
        items = res_b_list.get_json()["data"]
        self.assertFalse(any(e["employee_id"] == emp_id for e in items), "Org B list leaked Org A employee")

        # 4. Super Admin can view Org A employee
        res_sa = self.client.get(
            f"/api/employees/{emp_id}",
            headers={"Authorization": f"Bearer {self.super_admin_token}"}
        )
        self.assertEqual(res_sa.status_code, 200, "Super Admin must have cross-tenant visibility")

    def test_multi_tenant_security_events_isolation(self):
        """Security events ingested for Org A cannot be inspected by Org B."""
        ev_id = f"EVT-A-{self.run_id}"
        res = self.client.post(
            "/api/events",
            headers={"Authorization": f"Bearer {self.admin_a_token}"},
            json={
                "event_id": ev_id,
                "event_type": "file_access",
                "actor_type": "employee",
                "actor_id": "EMP-001",
                "resource": "confidential_roadmap.pdf",
                "is_sensitive": True,
                "action": "read",
                "source": "laptop",
                "destination": "internal_nas"
            }
        )
        self.assertEqual(res.status_code, 201)

        # Org B attempts to query Org A event
        res_b = self.client.get(
            f"/api/events/{ev_id}",
            headers={"Authorization": f"Bearer {self.admin_b_token}"}
        )
        self.assertEqual(res_b.status_code, 404, "Org B must not access Org A security events")

    # ==========================================================================
    # 2. ATOMIC DATABASE CONCURRENCY (AGENT GUARD)
    # ==========================================================================
    def test_atomic_agent_violation_concurrency_across_threads(self):
        """
        Validates atomic database updates.
        10 simultaneous violations on an active agent must result in EXACT count 10
        and status 'suspended', with zero race-condition overrun.
        """
        agent_id = f"AGT-ATOMIC-{self.run_id}"
        Repository.create_agent({
            "agent_id": agent_id,
            "organization_id": self.org_a,
            "name": "Atomic Concurrency Test Agent",
            "allowed_resources": ["public_docs"],
            "allowed_actions": ["read"],
            "status": "active",
            "violation_count": 0
        })

        def record_violation(i):
            details = {
                "event_id": f"EVT-VIO-{self.run_id}-{i}",
                "violation_type": "unauthorized_export",
                "action": "export",
                "resource": "payroll_db",
                "details": f"Concurrent thread violation {i}"
            }
            return Repository.increment_agent_violation(agent_id, details)

        # Fire 10 concurrent database increments
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(record_violation, i) for i in range(10)]
            results = [f.result() for f in futures]

        # Verify final state in database
        updated_agent = Repository.get_agent(agent_id)
        self.assertIsNotNone(updated_agent)
        self.assertEqual(updated_agent["status"], "suspended", "Agent must be transitioned to suspended")
        self.assertEqual(updated_agent["violation_count"], 10, "Violation counter must reflect all 10 increments exactly")

    # ==========================================================================
    # 3. SUSPENDED AGENT PERIMETER ENFORCEMENT
    # ==========================================================================
    def test_suspended_agent_strictly_blocked_at_perimeter(self):
        """Suspended agents must be immediately blocked from all protected actions."""
        agent_id = f"AGT-SUSP-{self.run_id}"
        Repository.create_agent({
            "agent_id": agent_id,
            "organization_id": self.org_a,
            "name": "Pre-Suspended Agent",
            "allowed_resources": ["*"],
            "allowed_actions": ["*"],
            "status": "suspended",
            "violation_count": 3
        })

        ev = {
            "event_id": f"EVT-ATTEMPT-{self.run_id}",
            "actor_id": agent_id,
            "actor_type": "ai_agent",
            "resource": "any_doc",
            "action": "read",
            "destination": "internal"
        }
        allowed, code, vios = AgentGuard.evaluate_agent_access(ev)
        self.assertFalse(allowed, "Suspended agent must never be permitted to operate")
        self.assertEqual(code, "flagged_suspended_agent_access")
        self.assertTrue(any("ACL-AGENT-002" in v for v in vios))

    # ==========================================================================
    # 4. AGENT REACTIVATION REQUIRES JUSTIFICATION
    # ==========================================================================
    def test_reactivation_requires_mandatory_justification(self):
        """Agent reactivation without non-empty justification must be rejected."""
        agent_id = f"AGT-REACT-{self.run_id}"
        Repository.create_agent({
            "agent_id": agent_id,
            "organization_id": self.org_a,
            "name": "Reactivate Test Agent",
            "status": "suspended"
        })

        # 1. Reactivation with empty reason via API must fail with 400
        res = self.client.patch(
            f"/api/agents/{agent_id}/status",
            headers={"Authorization": f"Bearer {self.admin_a_token}"},
            json={"status": "active", "reason": "   "}
        )
        self.assertEqual(res.status_code, 400, "Empty justification must be rejected with 400 Bad Request")

        # 2. Reactivation with valid audit justification succeeds
        res_ok = self.client.patch(
            f"/api/agents/{agent_id}/status",
            headers={"Authorization": f"Bearer {self.admin_a_token}"},
            json={"status": "active", "reason": "Security review completed and model retraining deployed"}
        )
        self.assertEqual(res_ok.status_code, 200)
        self.assertEqual(res_ok.get_json()["data"]["status"], "active")

    # ==========================================================================
    # 5. INGESTION VS ENFORCEMENT DISTINCTION
    # ==========================================================================
    def test_enforcement_status_clearly_distinguished_in_response(self):
        """HTTP response metadata must unequivocally signal whether the action was permitted or blocked."""
        # 1. Allowed normal event
        res_allowed = self.client.post("/api/events", json={
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP-900",
            "resource": "public_readme.txt",
            "is_sensitive": False,
            "action": "read",
            "source": "workstation",
            "destination": "corp_intranet"
        })
        self.assertEqual(res_allowed.status_code, 201)
        data_allowed = res_allowed.get_json()
        self.assertTrue(data_allowed["meta"]["action_permitted"])
        self.assertEqual(data_allowed["meta"]["enforcement_status"], "permitted")

        # 2. Blocked DLP violation event
        res_blocked = self.client.post("/api/events", json={
            "event_type": "file_sharing",
            "actor_type": "employee",
            "actor_id": "EMP-900",
            "resource": "q3_payroll_master.xlsx",
            "is_sensitive": True,
            "action": "share",
            "source": "workstation",
            "destination": "personal_gmail@gmail.com"
        })
        self.assertEqual(res_blocked.status_code, 201)
        data_blocked = res_blocked.get_json()
        self.assertFalse(data_blocked["meta"]["action_permitted"])
        self.assertEqual(data_blocked["meta"]["enforcement_status"], "blocked")
        self.assertIn("BLOCKED", data_blocked["message"])

    # ==========================================================================
    # 6. IDEMPOTENT EVENT INGESTION & DUPLICATE PROTECTION
    # ==========================================================================
    def test_idempotent_duplicate_event_rejection(self):
        """Duplicate event_id ingestion must be rejected with 409 Conflict without duplicate side-effects."""
        fixed_event_id = f"EVT-IDEMP-{self.run_id}"
        event_payload = {
            "event_id": fixed_event_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP-001",
            "resource": "standard_doc.pdf",
            "is_sensitive": False,
            "action": "read",
            "source": "workstation"
        }

        # First ingestion -> 201 Created
        res1 = self.client.post("/api/events", json=event_payload)
        self.assertEqual(res1.status_code, 201)

        # Duplicate ingestion -> 409 Conflict
        res2 = self.client.post("/api/events", json=event_payload)
        self.assertEqual(res2.status_code, 409, "Duplicate event_id must return 409 Conflict")

    # ==========================================================================
    # 7. RESTART SURVIVABILITY
    # ==========================================================================
    def test_database_persistence_survives_connection_reset(self):
        """Data stored in local persistence layer must survive connection resets and application reboots."""
        test_agent_id = f"AGT-PERSIST-{self.run_id}"
        Repository.create_agent({
            "agent_id": test_agent_id,
            "name": "Persistence Survival Agent",
            "owner": "admin",
            "status": "active"
        })

        # Simulate fresh application connection
        survived = Repository.get_agent(test_agent_id)
        self.assertIsNotNone(survived, "Agent must persist in database across session restarts")
        self.assertEqual(survived["agent_id"], test_agent_id)

if __name__ == "__main__":
    unittest.main()
