"""
AI Shield SaaS — Wazuh EDR Integration & Alert Webhook Handler.
Normalizes incoming Wazuh alerts into standard AI Shield Security Events,
performs deduplication, agent identification, and forwards them into
the unified event pipeline.
"""

import re
import json
import uuid
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("aishield.wazuh")

class WazuhIntegrationService:
    """
    Handles Wazuh manager integration, webhook verification,
    alert normalization, and agent onboarding script generation.
    """

    # Wazuh Rule Level Mapping (1 - 15) to Standard Severity & Risk Scores
    @staticmethod
    def map_rule_level_to_severity(level: int) -> Tuple[str, float]:
        """
        Maps Wazuh rule level (1 to 15) to standard risk level and initial risk score.
        Levels:
          1-4:   Low (0.0 - 39.9)
          5-8:   Medium (40.0 - 69.9)
          9-11:  High (70.0 - 84.9)
          12-15: Critical (85.0 - 100.0)
        """
        lvl = max(1, min(int(level or 1), 15))
        if lvl >= 12:
            return "critical", min(85.0 + (lvl - 12) * 5.0, 100.0)
        elif lvl >= 9:
            return "high", 70.0 + (lvl - 9) * 4.5
        elif lvl >= 5:
            return "medium", 40.0 + (lvl - 5) * 7.0
        else:
            return "low", max(10.0, lvl * 8.0)

    @classmethod
    def generate_dedup_hash(cls, alert: Dict[str, Any]) -> str:
        """Compute SHA256 deduplication fingerprint from core alert fields."""
        agent_id = str(alert.get("agent", {}).get("id", "000"))
        rule_id = str(alert.get("rule", {}).get("id", "0"))
        full_log = alert.get("full_log", "") or alert.get("rule", {}).get("description", "")
        fingerprint = f"{agent_id}:{rule_id}:{full_log[:200]}"
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    @classmethod
    def normalize_wazuh_alert(cls, raw_alert: Dict[str, Any], organization_id: str) -> Dict[str, Any]:
        """
        Convert raw Wazuh JSON webhook payload into unified AI Shield SecurityEvent schema.
        """
        now = datetime.now(timezone.utc).isoformat()
        rule = raw_alert.get("rule", {})
        agent = raw_alert.get("agent", {})
        data = raw_alert.get("data", {})
        syscheck = raw_alert.get("syscheck", {})

        level = int(rule.get("level", 3))
        severity, base_risk = cls.map_rule_level_to_severity(level)

        rule_id = str(rule.get("id", "WAZUH-001"))
        rule_desc = rule.get("description", "Wazuh EDR Security Alert")
        agent_name = agent.get("name", "endpoint-agent")
        agent_id = agent.get("id", "001")
        agent_ip = agent.get("ip", "127.0.0.1")

        # Determine target resource
        resource = (
            syscheck.get("path")
            or data.get("srcip")
            or data.get("dstip")
            or raw_alert.get("location")
            or f"endpoint://{agent_name}"
        )

        # Categorize event_type from Wazuh groups
        groups = rule.get("groups", [])
        event_type = "wazuh_endpoint_alert"
        if any(g in ("syscheck", "fim", "integrity") for g in groups):
            event_type = "file_integrity_violation"
        elif any(g in ("authentication_failed", "sshd", "login") for g in groups):
            event_type = "unauthorized_access_attempt"
        elif any(g in ("malware", "rootcheck", "virus") for g in groups):
            event_type = "malware_detection"
        elif any(g in ("pci_dss", "gdpr", "compliance") for g in groups):
            event_type = "compliance_policy_violation"

        event_id = f"EVT-WAZUH-{uuid.uuid4().hex[:8].upper()}"

        normalized_event = {
            "event_id": event_id,
            "organization_id": organization_id,
            "event_type": event_type,
            "actor_type": "employee" if "@" in agent_name else "external",
            "actor_id": agent_name,
            "resource": resource,
            "is_sensitive": level >= 10 or "sensitive" in rule_desc.lower(),
            "action": f"Wazuh Rule {rule_id}: {rule_desc}",
            "destination": agent_ip,
            "timestamp": raw_alert.get("timestamp") or now,
            "source": f"wazuh_agent_{agent_id}",
            "description": f"[Wazuh Level {level}] {rule_desc} on host {agent_name} ({agent_ip})",
            "rule_result": f"wazuh_level_{level}",
            "anomaly": level >= 7,
            "risk_score": base_risk,
            "risk_level": severity,
            "recommended_action": "Investigate affected host and isolate endpoint" if severity in ("high", "critical") else "Monitor endpoint activity",
            "action_permitted": severity != "critical",
            "metadata": {
                "wazuh_rule_id": rule_id,
                "wazuh_level": level,
                "wazuh_groups": groups,
                "agent_id": agent_id,
                "agent_ip": agent_ip,
                "full_log": raw_alert.get("full_log", "")[:500]
            }
        }

        return normalized_event

    @classmethod
    def generate_enrollment_commands(cls, organization_id: str, manager_url: str, enrollment_key: str) -> Dict[str, str]:
        """
        Generate copy-pasteable installation and registration scripts for Wazuh agents.
        """
        mgr_host = manager_url or "wazuh-manager.aishield.io"
        # Linux (Ubuntu / Debian / RHEL)
        linux_cmd = (
            f"curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add - && "
            f"echo 'deb https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list && "
            f"sudo apt-get update && "
            f"sudo WAZUH_MANAGER='{mgr_host}' WAZUH_AGENT_NAME='$(hostname)' WAZUH_REGISTRATION_KEY='{enrollment_key}' apt-get install -y wazuh-agent && "
            f"sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent"
        )

        # Windows (PowerShell Administrator)
        windows_cmd = (
            f"Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile wazuh-agent.msi; "
            f"msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='{mgr_host}' WAZUH_REGISTRATION_KEY='{enrollment_key}' WAZUH_AGENT_NAME=\"$env:COMPUTERNAME\"; "
            f"Start-Service -Name 'WazuhSvc'"
        )

        return {
            "linux": linux_cmd,
            "windows": windows_cmd,
            "webhook_endpoint": f"/api/integrations/wazuh/alert?organization_id={organization_id}"
        }
