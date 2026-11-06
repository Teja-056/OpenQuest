"""
AI Shield — Unified Security Rules Engine.
Combines AI Agent Guard access control, Data Loss Prevention inspection,
and enterprise authorization policies into standardized SecurityRuleResult outputs.
"""

from typing import Dict, Any
from backend.pipeline.security_adapter import SecurityRuleResult
from security.agent_guard import AgentGuard
from security.dlp_engine import DLPEngine

class ProductionSecurityRuleEngine:
    """
    Production-grade security rule evaluator.
    Evaluates events with least privilege, hard boundary enforcement, and DLP inspection.
    """

    def evaluate(self, event: Dict[str, Any]) -> SecurityRuleResult:
        actor_type = str(event.get("actor_type", "")).lower()
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        action = str(event.get("action", "")).lower()

        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))

        # 1. EVALUATE AI AGENTS
        if actor_type == "agent":
            is_allowed, agent_code, violations = AgentGuard.evaluate_agent_access(event)
            if not is_allowed:
                return SecurityRuleResult(
                    rule_result=agent_code,
                    hard_denial=True,
                    recommended_action="revoke_agent_token_and_isolate",
                    rule_violations=violations
                )

        # 2. EVALUATE DATA LOSS PREVENTION (DLP)
        is_dlp_violation, dlp_code, matches, classification = DLPEngine.evaluate_dlp(event)
        if is_dlp_violation:
            patterns_str = ", ".join(m["pattern"] for m in matches) if matches else "Sensitive data transfer"
            return SecurityRuleResult(
                rule_result=dlp_code,
                hard_denial=True,
                recommended_action="quarantine_attachment_and_notify_manager",
                rule_violations=[f"DLP Violation ({classification}): {patterns_str} to destination '{destination}'"]
            )

        # 3. INTERNAL SENSITIVE ACCESS (MONITORED)
        if is_sensitive and is_internal and action in ("read", "write", "download", "access", "view", "export"):
            return SecurityRuleResult(
                rule_result="allowed_with_audit",
                hard_denial=False,
                recommended_action="log_sensitive_access",
                rule_violations=[]
            )

        # 4. NOMINAL / STANDARD ACCESS
        return SecurityRuleResult(
            rule_result="allowed",
            hard_denial=False,
            recommended_action="none",
            rule_violations=[]
        )
