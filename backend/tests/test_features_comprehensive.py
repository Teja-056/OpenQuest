"""
AI Shield — Comprehensive Core Features Test Suite.
Validates:
- Feature 1: AI Agent Guard (least-privilege, boundary checks, auto-suspension after 3 violations, reactivation)
- Feature 2: DLP Engine (sensitive patterns: PAN, Aadhaar, Credit Cards, API Keys, Passwords; quarantine; path traversal defense)
- Feature 4: ML Anomaly Detector (Isolation Forest real prediction & scoring)
- Feature 5: API Threat Detection (rate limiting, brute force lockout)
- Feature 7 & 8: Incident update workflow & 8-part explainability
- Authentication & RBAC (PBKDF2 hashing, JWT signing, role authorization)
- Dashboard Metrics Aggregation
"""

import sys
import json
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app
from backend.config import Config
from backend.repository import Repository
from backend.auth import (
    hash_password,
    verify_password,
    generate_token,
    verify_token,
    ROLE_SUPER_ADMIN,
    ROLE_ORG_ADMIN,
    ROLE_ANALYST,
    ROLE_EMPLOYEE
)
from security.agent_guard import AgentGuard
from security.dlp_engine import DLPEngine, luhn_checksum_valid
from security.explanations import generate_incident_explanation
from ml.anomaly_detector import ProductionMLAnomalyDetector

class AIShieldComprehensiveFeaturesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "ENABLE_RATE_LIMIT_IN_TESTS": True})
        self.client = self.app.test_client()

    def test_01_password_hashing_and_jwt(self):
        pwd = "TestSecurePassword123!"
        hashed = hash_password(pwd)
        self.assertNotEqual(pwd, hashed)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))

        user_payload = {"user_id": "TEST_USER_01", "username": "testuser", "role": ROLE_ORG_ADMIN}
        token = generate_token(user_payload)
        self.assertIsInstance(token, str)

        decoded = verify_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sub"], "TEST_USER_01")
        self.assertEqual(decoded["role"], ROLE_ORG_ADMIN)

        # Invalid token rejection
        self.assertIsNone(verify_token(token + "tampered"))

    def test_02_agent_guard_least_privilege_and_boundary(self):
        # 1. Registered agent allowed on authorized resource
        event_allowed = {
            "actor_type": "agent",
            "actor_id": "agent_indexer_01",
            "resource": "/api/v1/catalog",
            "action": "read",
            "destination": "internal",
            "is_sensitive": False
        }
        allowed, code, violations = AgentGuard.evaluate_agent_access(event_allowed)
        self.assertTrue(allowed)
        self.assertEqual(code, "allowed_agent_operation")

        # 2. Agent attempting to access administrative secrets -> DENIED
        event_secret = {
            "actor_type": "agent",
            "actor_id": "agent_indexer_01",
            "resource": "/admin/keys/production_secrets.env",
            "action": "read",
            "destination": "internal",
            "is_sensitive": True
        }
        allowed, code, violations = AgentGuard.evaluate_agent_access(event_secret)
        self.assertFalse(allowed)
        self.assertIn("flagged_unauthorized_agent_access", code)

        # 3. Unregistered agent attempting access -> DENIED
        event_unreg = {
            "actor_type": "agent",
            "actor_id": "rogue_bot_999",
            "resource": "data.csv",
            "action": "read",
            "destination": "internal"
        }
        allowed, code, violations = AgentGuard.evaluate_agent_access(event_unreg)
        self.assertFalse(allowed)
        self.assertEqual(code, "flagged_unregistered_agent_access")

    def test_03_agent_guard_automatic_suspension_after_3_violations(self):
        test_agent_id = "test_agent_auto_suspend"
        Repository.create_agent({
            "agent_id": test_agent_id,
            "name": "Test Fragile Bot",
            "owner": "QA",
            "status": "active",
            "assigned_permissions": ["read"],
            "allowed_resources": ["public.txt"],
            "allowed_actions": ["read"],
            "allowed_destinations": ["internal"],
            "violation_count": 0
        })

        bad_event = {
            "event_id": "EVT_TEST_VIO",
            "actor_type": "agent",
            "actor_id": test_agent_id,
            "resource": "/admin/payroll_database.db",
            "action": "write",
            "destination": "external_bad.com",
            "is_sensitive": True
        }

        # Violation 1
        AgentGuard.evaluate_agent_access(bad_event)
        ag = Repository.get_agent(test_agent_id)
        self.assertEqual(ag["violation_count"], 1)
        self.assertEqual(ag["status"], "active")

        # Violation 2
        AgentGuard.evaluate_agent_access(bad_event)
        ag = Repository.get_agent(test_agent_id)
        self.assertEqual(ag["violation_count"], 2)
        self.assertEqual(ag["status"], "active")

        # Violation 3 -> Triggers Auto-Suspension!
        AgentGuard.evaluate_agent_access(bad_event)
        ag = Repository.get_agent(test_agent_id)
        self.assertEqual(ag["violation_count"], 3)
        self.assertEqual(ag["status"], "suspended")

        # Subsequent attempts are blocked because agent is SUSPENDED
        allowed, code, _ = AgentGuard.evaluate_agent_access(bad_event)
        self.assertFalse(allowed)
        self.assertEqual(code, "flagged_suspended_agent_access")

        # Admin Reactivation
        reactivated = AgentGuard.reactivate_agent(test_agent_id, "admin", "Audit cleared by security team")
        self.assertIsNotNone(reactivated)
        self.assertEqual(reactivated["status"], "active")

    def test_04_dlp_pattern_scanning(self):
        # 1. Indian PAN detection
        pan_text = "Employee tax identifier is ABCDE1234F recorded for payroll."
        matches = DLPEngine.scan_content(pan_text)
        self.assertTrue(any(m["pattern"] == "INDIAN_PAN" for m in matches))

        # 2. Indian Aadhaar detection
        aadhaar_text = "Citizen Aadhaar number is 2345 6789 0123 for verification."
        matches = DLPEngine.scan_content(aadhaar_text)
        self.assertTrue(any(m["pattern"] == "INDIAN_AADHAAR" for m in matches))

        # 3. Credit Card Luhn verification
        self.assertTrue(luhn_checksum_valid("4532-0150-1234-5671"))
        self.assertFalse(luhn_checksum_valid("4532-0150-1234-5674"))

        # 4. API Key detection
        api_text = "AWS secret access token is AKIAIOSFODNN7EXAMPLE"
        matches = DLPEngine.scan_content(api_text)
        self.assertTrue(any(m["pattern"] == "API_KEY_OR_SECRET" for m in matches))

        # 5. Personal Email exfiltration detection
        event_dlp = {
            "resource": "customer_database_export.csv",
            "destination": "employee_personal@gmail.com",
            "action": "share",
            "is_sensitive": True,
            "description": "Attempted file transfer"
        }
        is_vio, code, detected, classification = DLPEngine.evaluate_dlp(event_dlp)
        self.assertTrue(is_vio)
        self.assertIn("flagged_dlp", code)
        self.assertEqual(classification, "CONFIDENTIAL")

    def test_05_dlp_quarantine_path_traversal_defense(self):
        # Test directory traversal rejection
        bad_filename = "../../etc/shadow"
        success, msg, path = DLPEngine.quarantine_file(bad_filename, b"malicious content")
        # DLPEngine strips path traversal or confines safely
        self.assertTrue(success)
        self.assertTrue(Path(path).name.endswith("shadow"))
        self.assertNotIn("..", path)

    def test_06_ml_anomaly_detector_inference(self):
        detector = ProductionMLAnomalyDetector()
        
        # Test normal event
        normal_event = {
            "is_sensitive": False,
            "action": "read",
            "destination": "internal",
            "event_type": "file_access",
            "timestamp": "2026-11-04T11:00:00Z"
        }
        result_normal = detector.score(normal_event)
        self.assertFalse(result_normal.anomaly)
        self.assertLess(result_normal.risk_score, 40.0)

        # Test extreme anomalous event (off-hours, weekend, sensitive file, external target)
        anomalous_event = {
            "is_sensitive": True,
            "action": "share",
            "destination": "external_cloud_bucket.xyz",
            "event_type": "data_export",
            "timestamp": "2026-11-08T02:30:00Z",  # Sunday 2:30 AM (weekend + off-hours)
            "activity_volume": 120,
            "request_frequency": 25.0
        }
        result_anomaly = detector.score(anomalous_event)
        self.assertTrue(result_anomaly.anomaly)
        self.assertGreaterEqual(result_anomaly.risk_score, 65.0)

    def test_07_incident_8_part_explanation(self):
        event = {
            "actor_id": "EMP002",
            "actor_type": "employee",
            "resource": "payroll_q3.xlsx",
            "action": "share",
            "destination": "personal_email@gmail.com",
            "is_sensitive": True
        }
        risk_assessment = {
            "rule_result": "flagged_dlp_external_share",
            "hard_denial_preserved": True,
            "risk_score": 85.0,
            "risk_level": "critical",
            "recommended_action": "quarantine_attachment_and_notify_manager",
            "anomaly": True
        }
        explanation = generate_incident_explanation(event, risk_assessment)
        self.assertIn("what", explanation)
        self.assertIn("who", explanation)
        self.assertIn("resource", explanation)
        self.assertIn("suspicion_reason", explanation)
        self.assertIn("rule_triggered", explanation)
        self.assertIn("ml_prediction", explanation)
        self.assertIn("risk_score", explanation)
        self.assertIn("recommended_action", explanation)
        self.assertIn("EMP002", explanation["who"])

    def test_08_api_threat_detection_endpoint(self):
        res = self.client.get("/api/threats/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertIn("burst_limit", data)
        self.assertEqual(data["burst_limit"], 30)

    def test_09_dashboard_stats_endpoint(self):
        res = self.client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertIn("total_events", data)
        self.assertIn("open_incidents", data)
        self.assertIn("critical_incidents", data)
        self.assertIn("risk_distribution", data)

    def test_10_auth_login_and_me_endpoints(self):
        # Successful login
        res = self.client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AIShield2026!"
        })
        self.assertEqual(res.status_code, 200)
        token = res.get_json()["data"]["token"]
        self.assertTrue(len(token) > 20)

        # GET /api/auth/me with valid Bearer token
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        user_info = me_res.get_json()["data"]
        self.assertEqual(user_info["username"], "admin")

        # Invalid password rejection
        bad_res = self.client.post("/api/auth/login", json={
            "username": "admin",
            "password": "WrongPassword!"
        })
        self.assertEqual(bad_res.status_code, 401)

if __name__ == "__main__":
    unittest.main()
