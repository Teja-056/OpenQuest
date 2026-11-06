"""
AI Shield — Comprehensive SaaS Multi-Tenant & Cloud/EDR/AI Integration Tests.
Tests:
- Company registration, admin creation, and password hashing
- Strict tenant data isolation (preventing cross-company event leakage)
- AWS STS AssumeRole validation, unconfigured states, and trust policy generation
- Wazuh webhook alert ingestion, normalization, and pipeline forwarding
- TypeSafe Jev AI decision support, fallback resilience, and non-override of Rule 4
- Subscription tier limits and upgrade enforcement
"""

import os
import json
import uuid
import unittest
from unittest.mock import patch, MagicMock
from backend.app import create_app
from backend.config import Config
from backend.repository import Repository, init_local_db
from backend.auth import generate_token, hash_password, ROLE_ORG_ADMIN
from backend.integrations.aws_client import AWSIntegrationService
from backend.integrations.wazuh_client import WazuhIntegrationService
from backend.integrations.jev_client import JevClient

class AIShieldSaaSMultiTenantTestCase(unittest.TestCase):
    def setUp(self):
        Config.PERSISTENCE_MODE = "sqlite"
        Config.TESTING = True
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()
        init_local_db()

    def test_01_company_registration_success(self):
        """Test complete company registration and initial resource provisioning."""
        unique_id = uuid.uuid4().hex[:6]
        payload = {
            "company_name": f"Acme Cyber {unique_id}",
            "owner_name": "Alice Defender",
            "email": f"alice_{unique_id}@acme-cyber.com",
            "phone": "+1-555-0199",
            "industry": "FinTech",
            "country": "United States",
            "employee_count": 25,
            "password": "SecurePassword2026!",
            "subscription_tier": "STARTER"
        }

        resp = self.client.post("/api/auth/register-company", json=payload)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        # Check returned JWT token and user profile
        self.assertIn("token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], payload["email"])
        self.assertEqual(data["user"]["role"], ROLE_ORG_ADMIN)

        org_id = data["user"]["organization_id"]
        self.assertTrue(org_id.startswith("org_"))

        # Verify organization record in database
        org = Repository.get_organization(org_id)
        self.assertIsNotNone(org)
        self.assertEqual(org["name"], payload["company_name"])
        self.assertEqual(org["industry"], "FinTech")

        # Verify default subscription was created
        sub = Repository.get_subscription(org_id)
        self.assertEqual(sub["tier"], "STARTER")
        self.assertEqual(sub["max_endpoints"], 5)
        self.assertEqual(sub["max_cloud_accounts"], 1)

    def test_02_duplicate_company_registration_rejected(self):
        """Prevent duplicate company registration with the same email."""
        unique_id = uuid.uuid4().hex[:6]
        payload = {
            "company_name": f"Duplicate Corp {unique_id}",
            "owner_name": "Bob Duplicate",
            "email": f"bob_{unique_id}@duplicate.com",
            "password": "StrongPassword123!"
        }

        resp1 = self.client.post("/api/auth/register-company", json=payload)
        self.assertEqual(resp1.status_code, 201)

        # Attempt to register again with same email
        resp2 = self.client.post("/api/auth/register-company", json=payload)
        self.assertEqual(resp2.status_code, 409)

    def test_03_registration_validation(self):
        """Reject invalid inputs (short password, invalid email, missing company name)."""
        # Missing company name
        resp = self.client.post("/api/auth/register-company", json={"owner_name": "Test", "email": "t@t.com", "password": "123"})
        self.assertEqual(resp.status_code, 400)

        # Short password
        resp = self.client.post("/api/auth/register-company", json={"company_name": "Corp", "owner_name": "Test", "email": "t@t.com", "password": "short"})
        self.assertEqual(resp.status_code, 400)

        # Invalid email
        resp = self.client.post("/api/auth/register-company", json={"company_name": "Corp", "owner_name": "Test", "email": "not-an-email", "password": "ValidPassword123!"})
        self.assertEqual(resp.status_code, 400)

    def test_04_strict_tenant_isolation(self):
        """Ensure Company A cannot access Company B's security events or incidents."""
        # 1. Register Company A
        res_a = self.client.post("/api/auth/register-company", json={
            "company_name": "Alpha Defense",
            "owner_name": "Alpha Owner",
            "email": f"alpha_{uuid.uuid4().hex[:6]}@alpha.com",
            "password": "AlphaPassword123!"
        }).get_json()["data"]
        token_a = res_a["token"]
        org_a = res_a["user"]["organization_id"]

        # 2. Register Company B
        res_b = self.client.post("/api/auth/register-company", json={
            "company_name": "Beta Security",
            "owner_name": "Beta Owner",
            "email": f"beta_{uuid.uuid4().hex[:6]}@beta.com",
            "password": "BetaPassword123!"
        }).get_json()["data"]
        token_b = res_b["token"]
        org_b = res_b["user"]["organization_id"]

        # 3. Post a security event as Company A
        evt_a_id = f"EVT-ALPHA-{uuid.uuid4().hex[:6]}"
        post_evt_res = self.client.post(
            "/api/events",
            headers={"Authorization": f"Bearer {token_a}"},
            json={
                "event_id": evt_a_id,
                "event_type": "file_access",
                "actor_type": "employee",
                "actor_id": "alpha_analyst",
                "resource": "/confidential/alpha_patents.pdf",
                "is_sensitive": True,
                "action": "download",
                "source": "alpha_internal_network"
            }
        )
        self.assertEqual(post_evt_res.status_code, 201)

        # 4. Company A can see their event
        list_a = self.client.get(
            "/api/events",
            headers={"Authorization": f"Bearer {token_a}"}
        ).get_json()["data"]
        self.assertTrue(any(e["event_id"] == evt_a_id for e in list_a))

        # 5. Company B queries /api/events -> MUST NOT see Company A's event
        list_b = self.client.get(
            "/api/events",
            headers={"Authorization": f"Bearer {token_b}"}
        ).get_json()["data"]
        self.assertFalse(any(e["event_id"] == evt_a_id for e in list_b))

        # 6. Company B attempts to spoof ?organization_id=org_a -> strictly blocked!
        spoof_b = self.client.get(
            f"/api/events?organization_id={org_a}",
            headers={"Authorization": f"Bearer {token_b}"}
        ).get_json()["data"]
        self.assertFalse(any(e["event_id"] == evt_a_id for e in spoof_b))

    def test_05_aws_integration_unconfigured_and_trust_policy(self):
        """AWS integration properly reports UNCONFIGURED and provides Trust Policy."""
        reg = self.client.post("/api/auth/register-company", json={
            "company_name": "Cloud Defense Corp",
            "owner_name": "Cloud Admin",
            "email": f"cloud_{uuid.uuid4().hex[:6]}@clouddefense.io",
            "password": "Password12345!"
        }).get_json()["data"]
        token = reg["token"]

        # Check status initially
        res = self.client.get("/api/cloud/aws/status", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertFalse(data["is_connected"])
        self.assertEqual(data["integration"]["status"], "UNCONFIGURED")

        # Verify trust policy contains ExternalId
        trust_policy = data["trust_policy"]
        self.assertIn("Statement", trust_policy)
        self.assertEqual(trust_policy["Statement"][0]["Action"], "sts:AssumeRole")

        # Attempt connection with unconfigured / invalid AWS role
        conn_res = self.client.post(
            "/api/cloud/aws/connect",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "account_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/NonExistentRole",
                "regions": ["us-east-1"]
            }
        )
        self.assertEqual(conn_res.status_code, 200)
        conn_data = conn_res.get_json()["data"]
        # Must NOT fake a successful connection!
        self.assertFalse(conn_data["test_result"]["is_connected"])
        self.assertIn(conn_data["test_result"]["status"], ("AUTHENTICATION_FAILED", "ERROR"))

    def test_06_wazuh_webhook_alert_ingestion_and_normalization(self):
        """Test Wazuh JSON alert webhook ingestion, normalization, and pipeline processing."""
        # Register organization
        reg = self.client.post("/api/auth/register-company", json={
            "company_name": "EDR Fleet Corp",
            "owner_name": "EDR Admin",
            "email": f"edr_{uuid.uuid4().hex[:6]}@edrfleet.com",
            "password": "Password12345!"
        }).get_json()["data"]
        org_id = reg["user"]["organization_id"]
        token = reg["token"]

        # Get Wazuh status & enrollment script
        wazuh_status = self.client.get("/api/integrations/wazuh/status", headers={"Authorization": f"Bearer {token}"}).get_json()["data"]
        self.assertIn("enrollment_commands", wazuh_status)
        self.assertIn("linux", wazuh_status["enrollment_commands"])
        self.assertIn("windows", wazuh_status["enrollment_commands"])

        # Send raw Wazuh webhook alert
        wazuh_raw_alert = {
            "timestamp": "2026-11-06T14:30:00.000Z",
            "rule": {
                "level": 12,
                "description": "High-risk unauthorized shadow administrative process executed",
                "id": "5710",
                "groups": ["syscheck", "integrity", "privilege_escalation"]
            },
            "agent": {
                "id": "042",
                "name": "prod-database-node-01",
                "ip": "10.0.1.45"
            },
            "data": {
                "srcip": "198.51.100.22"
            },
            "full_log": "Nov 06 14:30:00 prod-database-node-01 kernel: unauthorized sudoers access attempt by UID 1002"
        }

        ingest_res = self.client.post(
            f"/api/integrations/wazuh/alert?organization_id={org_id}",
            json=wazuh_raw_alert
        )
        self.assertEqual(ingest_res.status_code, 201)
        pipeline_res = ingest_res.get_json()["data"]

        # Verify normalized event
        event = pipeline_res["event"]
        self.assertEqual(event["organization_id"], org_id)
        self.assertEqual(event["actor_id"], "prod-database-node-01")
        self.assertEqual(event["event_type"], "file_integrity_violation")
        self.assertEqual(event["risk_level"], "critical")
        self.assertGreaterEqual(event["risk_score"], 85.0)

        # Verify incident was generated
        self.assertIsNotNone(pipeline_res.get("incident"))

        # Verify Wazuh integration status is now ACTIVE
        wazuh_status_after = self.client.get("/api/integrations/wazuh/status", headers={"Authorization": f"Bearer {token}"}).get_json()["data"]
        self.assertEqual(wazuh_status_after["integration"]["status"], "ACTIVE")

    def test_07_typesafe_jev_decision_support(self):
        """Verify TypeSafe Jev assessment returns NOT_CONFIGURED gracefully when key absent and respects Rule 4."""
        # 1. When JEV_API_KEY is not set
        with patch.object(JevClient, "get_api_key", return_value=None):
            event = {
                "event_id": "EVT-TEST-001",
                "event_type": "file_access",
                "actor_id": "test_agent",
                "resource": "/etc/shadow",
                "action": "read"
            }
            res = JevClient.evaluate_security_event(event)
            self.assertEqual(res["status"], "NOT_CONFIGURED")
            self.assertIn("JEV_API_KEY", res["explanation"])

        # 2. When JEV evaluates and returns advice
        mock_response_json = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_threat": True,
                        "severity": "critical",
                        "confidence": 0.94,
                        "requires_human_review": True,
                        "reasoning": "Attempted read of critical shadow credentials file."
                    })
                }
            }]
        }
        mock_urlopen = MagicMock()
        mock_urlopen.status = 200
        mock_urlopen.read.return_value = json.dumps(mock_response_json).encode("utf-8")
        mock_urlopen.__enter__.return_value = mock_urlopen

        with patch.object(JevClient, "get_api_key", return_value="test_jev_secret_key"):
            with patch("urllib.request.urlopen", return_value=mock_urlopen):
                # Hard denial active: Jev must NOT override deterministic denial
                res2 = JevClient.evaluate_security_event(event, rule_override_applied=True)
                self.assertEqual(res2["status"], "ASSESSED")
                self.assertTrue(res2["noul_verdict"])
                self.assertEqual(res2["severity_choice"], "critical")
                self.assertTrue(res2["rule_override_active"])

    def test_08_subscription_limits_and_upgrade(self):
        """Enforce starter limits (5 endpoints, 1 cloud) and test upgrading to Professional."""
        reg = self.client.post("/api/auth/register-company", json={
            "company_name": "SaaS Tier Corp",
            "owner_name": "Tier Admin",
            "email": f"tier_{uuid.uuid4().hex[:6]}@saastier.io",
            "password": "Password12345!",
            "subscription_tier": "STARTER"
        }).get_json()["data"]
        org_id = reg["user"]["organization_id"]
        token = reg["token"]

        # Verify initial limits
        sub_res = self.client.get("/api/subscription", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(sub_res.status_code, 200)
        sub_data = sub_res.get_json()["data"]
        self.assertEqual(sub_data["subscription"]["tier"], "STARTER")
        self.assertEqual(sub_data["usage"]["endpoints"]["max"], 5)
        self.assertEqual(sub_data["usage"]["cloud_accounts"]["max"], 1)

        # Upgrade to PROFESSIONAL
        upg_res = self.client.post(
            "/api/subscription/upgrade",
            headers={"Authorization": f"Bearer {token}"},
            json={"tier": "PROFESSIONAL"}
        )
        self.assertEqual(upg_res.status_code, 200)

        # Check upgraded limits
        sub_res2 = self.client.get("/api/subscription", headers={"Authorization": f"Bearer {token}"})
        sub_data2 = sub_res2.get_json()["data"]
        self.assertEqual(sub_data2["subscription"]["tier"], "PROFESSIONAL")
        self.assertEqual(sub_data2["usage"]["endpoints"]["max"], 25)
        self.assertEqual(sub_data2["usage"]["cloud_accounts"]["max"], 3)

    def test_09_executive_report_generation(self):
        """Generate comprehensive executive cybersecurity report."""
        reg = self.client.post("/api/auth/register-company", json={
            "company_name": "Executive Posture Corp",
            "owner_name": "Chief Security Officer",
            "email": f"cso_{uuid.uuid4().hex[:6]}@execposture.com",
            "password": "Password12345!"
        }).get_json()["data"]
        token = reg["token"]

        res = self.client.get("/api/organization/report", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        report = res.get_json()["data"]
        self.assertIn("compliance_score", report)
        self.assertIn("posture_grade", report)
        self.assertIn("metrics_summary", report)
        self.assertIn("integrations", report)
        self.assertIn("recommendations", report)

if __name__ == "__main__":
    unittest.main()
