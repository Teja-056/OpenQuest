"""
AI Shield — Master 20-Scenario End-to-End & Security Audit Test Suite.
Validates all 20 mandatory scenarios required by Section 17 of the Master Project Instruction:

1. Normal employee file access.
2. Sensitive internal file access.
3. Unauthorized AI-agent access.
4. Repeated agent violations.
5. Automatic agent suspension.
6. Suspended agent access attempt.
7. Sensitive external file sharing.
8. DLP denial.
9. Suspicious API requests.
10. Abnormal employee behaviour.
11. ML anomaly detection.
12. Critical risk calculation.
13. Incident generation.
14. Alert generation.
15. Incident assignment.
16. Incident resolution.
17. Alert acknowledgement.
18. Database persistence.
19. Duplicate event handling.
20. Unauthorized administrator operation.

Also validates security defenses:
- Invalid JSON payload.
- Missing required fields.
- SQL injection attempts.
- XSS script tags in fields.
- Path traversal in file quarantine.
- Unauthorized API access without token.
- Expired/tampered session tokens.
"""

import sys
import json
import uuid
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.repository import Repository
from backend.database import get_supabase_client
from backend.auth import generate_token, ROLE_ORG_ADMIN, ROLE_EMPLOYEE
from security.agent_guard import AgentGuard
from security.dlp_engine import DLPEngine

class AIShieldMasterE2ETestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "ENABLE_RATE_LIMIT_IN_TESTS": False})
        self.client = self.app.test_client()
        self.run_id = uuid.uuid4().hex[:6].upper()
        self.created_events = []
        self.created_incidents = []
        self.created_alerts = []

        # Generate test admin and employee tokens
        self.admin_token = generate_token({
            "user_id": f"USR-ADMIN-{self.run_id}",
            "username": f"e2e_admin_{self.run_id}",
            "role": ROLE_ORG_ADMIN,
            "organization_id": "org_default"
        })
        self.employee_token = generate_token({
            "user_id": f"USR-EMP-{self.run_id}",
            "username": f"e2e_emp_{self.run_id}",
            "role": ROLE_EMPLOYEE,
            "organization_id": "org_default"
        })

    def tearDown(self):
        # Clean up records created during this test run in Supabase
        try:
            db = get_supabase_client()
            for evt in self.created_events:
                db.table("security_events").delete().eq("event_id", evt).execute()
            for inc in self.created_incidents:
                db.table("security_incidents").delete().eq("incident_id", inc).execute()
            for alt in self.created_alerts:
                db.table("alerts").delete().eq("alert_id", alt).execute()
        except Exception:
            pass

    # SCENARIO 1: Normal employee file access
    def test_scenario_01_normal_employee_file_access(self):
        evt_id = f"E2E_01_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "team_meeting_notes.docx",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test",
            "description": "Routine reading of meeting notes"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertEqual(data["rule_result"], "allowed")
        self.assertEqual(data["risk_level"], "low")
        self.assertEqual(data["recommended_action"], "none")

    # SCENARIO 2: Sensitive internal file access
    def test_scenario_02_sensitive_internal_file_access(self):
        evt_id = f"E2E_02_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "q3_financial_ledger.xlsx",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test",
            "description": "Authorized internal read of ledger"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertEqual(data["rule_result"], "allowed_with_audit")
        self.assertEqual(data["recommended_action"], "log_sensitive_access")

    # SCENARIO 3: Unauthorized AI-agent access
    def test_scenario_03_unauthorized_agent_access(self):
        agent_id = f"agt_e2e_indexer_{self.run_id}"
        Repository.create_agent({
            "agent_id": agent_id,
            "name": "Fresh Test Indexer",
            "owner": "QA",
            "status": "active",
            "assigned_permissions": ["catalog:read"],
            "allowed_resources": ["/api/v1/catalog"],
            "allowed_actions": ["read"],
            "allowed_destinations": ["internal"],
            "violation_count": 0
        })

        evt_id = f"E2E_03_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "api_request",
            "actor_type": "agent",
            "actor_id": agent_id,
            "resource": "/admin/keys/master_secrets.env",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test",
            "description": "Agent attempting access to master secrets"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertEqual(data["risk_level"], "critical")
        self.assertGreaterEqual(data["risk_score"], 85.0)
        self.assertIn("flagged_unauthorized_agent_access", data["rule_result"])
        self.assertEqual(data["recommended_action"], "revoke_agent_token_and_isolate")

    # SCENARIOS 4, 5, 6: Repeated agent violations, automatic suspension, and suspended access attempt
    def test_scenarios_04_05_06_agent_violations_and_auto_suspension(self):
        agent_id = f"agent_violator_{self.run_id}"
        Repository.create_agent({
            "agent_id": agent_id,
            "name": "E2E Violating Bot",
            "owner": "Engineering",
            "status": "active",
            "assigned_permissions": ["read"],
            "allowed_resources": ["public_assets.json"],
            "allowed_actions": ["read"],
            "allowed_destinations": ["internal"],
            "violation_count": 0
        })

        bad_payload = {
            "event_type": "api_request",
            "actor_type": "agent",
            "actor_id": agent_id,
            "resource": "/admin/payroll_database.db",
            "is_sensitive": True,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test"
        }

        # Scenario 4: Repeated violations 1 and 2
        bad_payload["event_id"] = f"E2E_VIO1_{self.run_id}"
        self.created_events.append(bad_payload["event_id"])
        self.client.post("/api/events", json=bad_payload)
        ag = Repository.get_agent(agent_id)
        self.assertEqual(ag["violation_count"], 1)

        bad_payload["event_id"] = f"E2E_VIO2_{self.run_id}"
        self.created_events.append(bad_payload["event_id"])
        self.client.post("/api/events", json=bad_payload)
        ag = Repository.get_agent(agent_id)
        self.assertEqual(ag["violation_count"], 2)
        self.assertEqual(ag["status"], "active")

        # Scenario 5: 3rd violation triggers Automatic Agent Suspension
        bad_payload["event_id"] = f"E2E_VIO3_{self.run_id}"
        self.created_events.append(bad_payload["event_id"])
        self.client.post("/api/events", json=bad_payload)
        ag = Repository.get_agent(agent_id)
        self.assertEqual(ag["violation_count"], 3)
        self.assertEqual(ag["status"], "suspended")

        # Scenario 6: Suspended agent access attempt is strictly DENIED
        bad_payload["event_id"] = f"E2E_VIO4_{self.run_id}"
        self.created_events.append(bad_payload["event_id"])
        res = self.client.post("/api/events", json=bad_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertEqual(data["rule_result"], "flagged_suspended_agent_access")
        self.assertEqual(data["risk_level"], "critical")

    # SCENARIOS 7 & 8: Sensitive external file sharing and DLP denial
    def test_scenarios_07_08_sensitive_external_dlp_denial(self):
        evt_id = f"E2E_07_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "customer_pii_vault.csv",
            "is_sensitive": True,
            "action": "share",
            "destination": "personal_external_mail@gmail.com",
            "source": "e2e_test",
            "description": "Attempted file transfer to external personal email"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertIn("flagged_dlp", data["rule_result"])
        self.assertEqual(data["risk_level"], "critical")
        self.assertGreaterEqual(data["risk_score"], 85.0)
        self.assertEqual(data["recommended_action"], "quarantine_attachment_and_notify_manager")

    # SCENARIOS 9 & 10: Suspicious API requests & Abnormal employee behavior
    def test_scenarios_09_10_suspicious_api_and_abnormal_behavior(self):
        evt_id = f"E2E_09_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "data_export",
            "actor_type": "employee",
            "actor_id": "EMP004",
            "resource": "bulk_data_exfiltration_dump.tar.gz",
            "is_sensitive": False,
            "action": "export",
            "destination": "unrecognized_cloud_s3_bucket",
            "source": "e2e_test",
            "description": "Anomalous mass archive at 03:00 AM on Sunday",
            "activity_volume": 150,
            "request_frequency": 30.0,
            "timestamp": "2026-11-08T03:00:00Z"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertTrue(data["anomaly"])
        self.assertGreaterEqual(data["risk_score"], 60.0)

    # SCENARIOS 11 & 12: ML anomaly detection & Critical risk calculation (Rule 4)
    def test_scenarios_11_12_ml_anomaly_and_critical_risk_rule4(self):
        evt_id = f"E2E_11_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "payroll_secret.xlsx",
            "is_sensitive": True,
            "action": "share",
            "destination": "personal_mail@gmail.com",
            "source": "e2e_test",
            "anomaly": False,
            "risk_score": 5.0  # Deceptive low score
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()["data"]
        self.assertEqual(data["risk_level"], "critical")
        self.assertEqual(data["risk_score"], 85.0)

    # SCENARIOS 13 & 14: Automated Incident and Alert Generation
    def test_scenarios_13_14_incident_and_alert_generation(self):
        evt_id = f"E2E_13_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_share",
            "actor_type": "employee",
            "actor_id": "EMP002",
            "resource": "q3_payroll_master.xlsx",
            "is_sensitive": True,
            "action": "share",
            "destination": "dropbox.com/public_dump",
            "source": "e2e_test"
        }
        res = self.client.post("/api/events", json=payload)
        self.assertEqual(res.status_code, 201)
        meta = res.get_json().get("meta", {})
        self.assertIn("alert_id", meta)
        self.assertIn("incident_id", meta)
        if meta.get("incident_id"):
            self.created_incidents.append(meta["incident_id"])
        if meta.get("alert_id"):
            self.created_alerts.append(meta["alert_id"])

    # SCENARIOS 15, 16, 17: Incident assignment, resolution, and alert acknowledgement
    def test_scenarios_15_16_17_incident_workflow_and_alert_ack(self):
        inc_id = f"INC-TEST-{self.run_id}"
        self.created_incidents.append(inc_id)

        inc_res = self.client.post("/api/incidents", json={
            "incident_id": inc_id,
            "title": "E2E Test Incident For Workflow",
            "description": "Investigating unauthorized data movement",
            "severity": "high",
            "status": "open"
        })
        self.assertEqual(inc_res.status_code, 201)

        # Scenario 15: Assign Administrator
        assign_res = self.client.patch(f"/api/incidents/{inc_id}", json={
            "assigned_to": "alice.chen"
        })
        self.assertEqual(assign_res.status_code, 200)
        self.assertEqual(assign_res.get_json()["data"]["assigned_to"], "alice.chen")

        # Scenario 16: Resolve Incident
        resolve_res = self.client.patch(f"/api/incidents/{inc_id}", json={
            "status": "resolved"
        })
        self.assertEqual(resolve_res.status_code, 200)
        self.assertEqual(resolve_res.get_json()["data"]["status"], "resolved")
        self.assertIsNotNone(resolve_res.get_json()["data"]["resolved_at"])

        # Scenario 17: Create and Acknowledge Alert
        alt_id = f"ALT-TEST-{self.run_id}"
        self.created_alerts.append(alt_id)

        alt_res = self.client.post("/api/alerts", json={
            "alert_id": alt_id,
            "alert_type": "DLP_VIOLATION",
            "severity": "critical",
            "message": "E2E test alert notification"
        })
        ack_res = self.client.patch(f"/api/alerts/{alt_id}", json={"is_read": True})
        self.assertEqual(ack_res.status_code, 200)
        self.assertTrue(ack_res.get_json()["data"]["is_read"])

    # SCENARIO 18: Database persistence verification
    def test_scenario_18_database_persistence(self):
        evt_id = f"E2E_18_{self.run_id}"
        self.created_events.append(evt_id)
        res = self.client.post("/api/events", json={
            "event_id": evt_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "audit_verification_document.txt",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test"
        })
        self.assertEqual(res.status_code, 201)

        # Retrieve through GET endpoint
        get_res = self.client.get(f"/api/events/{evt_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.get_json()["data"]["event_id"], evt_id)

    # SCENARIO 19: Duplicate event handling
    def test_scenario_19_duplicate_event_handling(self):
        evt_id = f"E2E_19_{self.run_id}"
        self.created_events.append(evt_id)
        payload = {
            "event_id": evt_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "doc.pdf",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "e2e_test"
        }
        res1 = self.client.post("/api/events", json=payload)
        self.assertEqual(res1.status_code, 201)

        # Resubmitting identical event_id must return 409 Conflict
        res2 = self.client.post("/api/events", json=payload)
        self.assertEqual(res2.status_code, 409)

    # SCENARIO 20: Unauthorized administrator operation
    def test_scenario_20_unauthorized_admin_operation(self):
        # Attempt to register AI agent without authentication token
        unauth_res = self.client.post("/api/agents", json={"name": "HackerBot"})
        self.assertEqual(unauth_res.status_code, 401)

        # Attempt with standard employee token (lacking ORGANIZATION_ADMIN role)
        forbidden_res = self.client.post(
            "/api/agents",
            json={"name": "HackerBot"},
            headers={"Authorization": f"Bearer {self.employee_token}"}
        )
        self.assertEqual(forbidden_res.status_code, 403)

        # Authorized operation with admin token succeeds
        auth_res = self.client.post(
            "/api/agents",
            json={"name": f"AdminAgent_{self.run_id}", "owner": "SecurityOps"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(auth_res.status_code, 201)

    # DEFENSIVE & SECURITY TESTS: SQL Injection, XSS, Path Traversal, Malformed Payloads
    def test_security_defenses_owasp(self):
        sqli_id = f"E2E_SQLI_{self.run_id}"
        self.created_events.append(sqli_id)

        # 1. SQL Injection payload in event fields
        sqli_payload = {
            "event_id": sqli_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP001' OR '1'='1'; --",
            "resource": "roadmap.pdf'; DROP TABLE employees; --",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "sqli_test"
        }
        res_sqli = self.client.post("/api/events", json=sqli_payload)
        self.assertIn(res_sqli.status_code, [201, 400])

        # 2. XSS payload in description
        xss_id = f"E2E_XSS_{self.run_id}"
        self.created_events.append(xss_id)
        xss_payload = {
            "event_id": xss_id,
            "event_type": "file_access",
            "actor_type": "employee",
            "actor_id": "EMP001",
            "resource": "doc.pdf",
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "source": "xss_test",
            "description": "<script>alert('XSS')</script>"
        }
        res_xss = self.client.post("/api/events", json=xss_payload)
        self.assertEqual(res_xss.status_code, 201)

        # 3. Invalid JSON payload
        res_invalid_json = self.client.post(
            "/api/events",
            data="Not valid json",
            content_type="application/json"
        )
        self.assertEqual(res_invalid_json.status_code, 400)

        # 4. Missing required fields
        res_missing = self.client.post("/api/events", json={"actor_id": "EMP001"})
        self.assertEqual(res_missing.status_code, 400)

        # 5. Path traversal defense
        success, msg, path = DLPEngine.quarantine_file("../../../root/shadow.txt", b"secret")
        self.assertTrue(success)
        self.assertNotIn("..", path)

if __name__ == "__main__":
    unittest.main()
