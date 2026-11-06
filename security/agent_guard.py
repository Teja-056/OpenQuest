"""
AI Shield — AI Agent Guard Module.
Manages AI Agent registration, least-privilege permission validation,
violation auditing, automatic suspension upon repeated offenses, and admin reactivation.
"""

from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone
from backend.config import Config
from backend.repository import Repository

class AgentGuard:
    """
    Core security controller for AI agents.
    Enforces least privilege: denies unauthorized actions by default.
    """

    @classmethod
    def evaluate_agent_access(cls, event: Dict[str, Any]) -> Tuple[bool, str, List[str]]:
        """
        Evaluate if an agent's attempted operation is permitted.
        Returns: (is_allowed: bool, decision_code: str, violations: list[str])
        """
        actor_id = event.get("actor_id", "")
        resource = str(event.get("resource", "")).lower()
        action = str(event.get("action", "")).lower()
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))

        # 1. Fetch agent profile
        agent = Repository.get_agent(actor_id)
        if not agent:
            # Unregistered agent attempting access -> strict denial
            violations = [f"ACL-AGENT-001: Agent '{actor_id}' is not registered in AI-Shield registry."]
            cls._record_violation(actor_id, event, "unregistered_agent_access", "critical", violations)
            return False, "flagged_unregistered_agent_access", violations

        # 2. Check suspension status
        if agent.get("status") == "suspended":
            violations = [f"ACL-AGENT-002: Agent '{actor_id}' is currently SUSPENDED. All operations blocked."]
            cls._record_violation(actor_id, event, "suspended_agent_access_attempt", "critical", violations)
            return False, "flagged_suspended_agent_access", violations

        # 3. Check administrative boundary (agents cannot access credentials, keys, payroll)
        admin_keywords = ["admin", "secret", "payroll", "credential", "key", "token", "password", "env"]
        if is_sensitive or any(kw in resource for kw in admin_keywords):
            # Check if agent has explicit high-privilege permission
            allowed_res = [str(r).lower() for r in agent.get("allowed_resources", [])]
            if not any(ar in resource or resource in ar for ar in allowed_res):
                violations = [f"ACL-AGENT-003: Agent '{actor_id}' attempted access to restricted resource '{resource}'."]
                cls._record_violation(actor_id, event, "restricted_resource_access", "critical", violations)
                return False, "flagged_unauthorized_agent_access", violations

        # 4. Check action permissions
        allowed_actions = [str(a).lower() for a in agent.get("allowed_actions", [])]
        if allowed_actions and "*" not in allowed_actions and action not in allowed_actions:
            violations = [f"ACL-AGENT-004: Action '{action}' not permitted for agent '{actor_id}'. Allowed: {allowed_actions}."]
            cls._record_violation(actor_id, event, "unauthorized_action", "high", violations)
            return False, "flagged_agent_action_denied", violations

        # 5. Check destination permissions (agents prohibited from exfiltrating to external domains unless explicitly whitelisted)
        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "corp", "none"))
        if not is_internal:
            allowed_dest = [str(d).lower() for d in agent.get("allowed_destinations", [])]
            if not any(d in destination for d in allowed_dest):
                violations = [f"ACL-AGENT-005: Destination '{destination}' is not in allowed destinations list for agent '{actor_id}'."]
                cls._record_violation(actor_id, event, "unauthorized_destination", "critical", violations)
                return False, "flagged_agent_external_destination_violation", violations

        # Allowed
        return True, "allowed_agent_operation", []

    @classmethod
    def _record_violation(cls, agent_id: str, event: Dict[str, Any], violation_type: str, severity: str, violations: List[str]):
        """Helper to increment violation count and auto-suspend if threshold exceeded."""
        details = {
            "event_id": event.get("event_id"),
            "violation_type": violation_type,
            "action": event.get("action"),
            "resource": event.get("resource"),
            "destination": event.get("destination"),
            "details": "; ".join(violations),
            "severity": severity
        }
        v_count, was_suspended = Repository.increment_agent_violation(agent_id, details)
        if was_suspended:
            print(f"[AgentGuard] ALERT: Agent '{agent_id}' exceeded violation threshold ({v_count} violations). Status set to SUSPENDED.")

    @classmethod
    def reactivate_agent(cls, agent_id: str, admin_username: str, justification: str) -> Optional[Dict[str, Any]]:
        """Administrator-controlled reactivation of a suspended agent."""
        if not justification or not str(justification).strip():
            raise ValueError("Agent reactivation requires a non-empty administrative justification.")
        return Repository.update_agent_status(
            agent_id,
            "active",
            reason=f"Reactivated by {admin_username}. Justification: {justification.strip()}"
        )

    @classmethod
    def seed_initial_agents(cls):
        """Seed initial reference AI agents for demonstration and baseline testing."""
        initial_agents = [
            {
                "agent_id": "agent_indexer_01",
                "name": "Catalog Indexer Bot",
                "description": "Background service indexing catalog and product metadata",
                "owner": "Infrastructure",
                "status": "active",
                "assigned_permissions": ["catalog:read"],
                "allowed_resources": ["/api/v1/catalog", "catalog_assets.json", "public_documentation.md"],
                "allowed_actions": ["read", "view"],
                "allowed_destinations": ["internal"],
                "violation_count": 0
            },
            {
                "agent_id": "agent_support_bot",
                "name": "Customer Support Assistant",
                "description": "Processes customer tickets and references knowledgebase",
                "owner": "Support Operations",
                "status": "active",
                "assigned_permissions": ["tickets:read", "tickets:write", "faq:read"],
                "allowed_resources": ["/api/v1/tickets", "support_faq.md", "customer_faq.json"],
                "allowed_actions": ["read", "write", "search"],
                "allowed_destinations": ["internal"],
                "violation_count": 0
            },
            {
                "agent_id": "agent_financial_reporter",
                "name": "Quarterly Financial Aggregator",
                "description": "Aggregates end-of-month general ledgers and non-payroll reports",
                "owner": "Finance",
                "status": "active",
                "assigned_permissions": ["finance:read"],
                "allowed_resources": ["revenue_summary.csv", "general_expenses.csv"],
                "allowed_actions": ["read"],
                "allowed_destinations": ["internal"],
                "violation_count": 0
            }
        ]

        for ag in initial_agents:
            existing = Repository.get_agent(ag["agent_id"])
            if not existing:
                Repository.create_agent(ag)

    @classmethod
    def reset_initial_agents(cls):
        """Reset default seed agents back to active 0-violation state for clean test isolation."""
        from backend.repository import get_local_db_conn
        try:
            conn = get_local_db_conn()
            with conn:
                conn.execute(
                    "UPDATE ai_agents SET violation_count = 0, status = 'active' "
                    "WHERE agent_id IN ('agent_indexer_01', 'agent_support_bot', 'agent_financial_reporter')"
                )
        except Exception:
            pass

# Initialize seed agents
try:
    AgentGuard.seed_initial_agents()
except Exception as e:
    print(f"[AgentGuard] Notice: Seed agent initialization notice: {e}")
