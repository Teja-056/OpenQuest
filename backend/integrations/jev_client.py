"""
AI Shield SaaS — TypeSafe Jev AI Decision-Support Client.
Official API: https://api.typesafe.ai/v1/systemone
Model: jev-latest

Provides structured AI event assessment, Noul yes/no verdicts, and human-in-the-loop
review recommendations. Serves as decision support without overriding deterministic
security policy denials (Rule 4 strict enforcement).
"""

import os
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("aishield.jev")

class JevClient:
    """
    Client for TypeSafe Jev SystemOne API.
    Performs AI event classification, noul binary verdicts, and explanation support.
    """

    API_URL = "https://api.typesafe.ai/v1/systemone"
    DEFAULT_MODEL = "jev-latest"
    TIMEOUT_SECONDS = 3.5

    @classmethod
    def get_api_key(cls) -> Optional[str]:
        """Read JEV_API_KEY from environment."""
        key = os.environ.get("JEV_API_KEY", "").strip()
        return key if key else None

    @classmethod
    def is_configured(cls) -> bool:
        """Check if Jev API is configured with valid key."""
        return bool(cls.get_api_key())

    @classmethod
    def sanitize_event_for_ai(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize event payload before sending to external API.
        Strips plaintext PII, document contents, and passwords to prevent data leakage.
        """
        actor = event.get("actor_id", "unknown")
        # Mask email username if employee
        if "@" in actor:
            parts = actor.split("@")
            actor = f"{parts[0][:2]}***@{parts[1]}"

        # Truncate resource path / names
        resource = str(event.get("resource", "unknown"))
        if len(resource) > 80:
            resource = resource[:40] + "..." + resource[-30:]

        return {
            "event_type": event.get("event_type", "unknown"),
            "actor_type": event.get("actor_type", "unknown"),
            "masked_actor": actor,
            "resource_summary": resource,
            "action": event.get("action", "unknown"),
            "rule_result": event.get("rule_result"),
            "risk_score": event.get("risk_score"),
            "anomaly_detected": bool(event.get("anomaly")),
            "is_sensitive": bool(event.get("is_sensitive"))
        }

    @classmethod
    def evaluate_security_event(cls, event: Dict[str, Any], rule_override_applied: bool = False) -> Dict[str, Any]:
        """
        Submit security event context to TypeSafe Jev for decision assessment.
        Returns structured verdict, choice-based severity, and review recommendation.
        If Jev is unconfigured or fails, returns graceful fallback without interrupting pipeline.
        """
        now = datetime.now(timezone.utc).isoformat()
        api_key = cls.get_api_key()

        if not api_key:
            return {
                "status": "NOT_CONFIGURED",
                "model": cls.DEFAULT_MODEL,
                "noul_verdict": None,
                "severity_choice": None,
                "confidence": 0.0,
                "human_review_required": False,
                "explanation": "TypeSafe Jev AI key (JEV_API_KEY) not configured. Using deterministic rule engine and Isolation Forest.",
                "timestamp": now,
                "rule_override_active": rule_override_applied
            }

        sanitized_ctx = cls.sanitize_event_for_ai(event)

        prompt = (
            f"Analyze this cybersecurity event for threat potential:\n"
            f"Type: {sanitized_ctx['event_type']}, Action: {sanitized_ctx['action']}, "
            f"Resource: {sanitized_ctx['resource_summary']}, Anomaly: {sanitized_ctx['anomaly_detected']}, "
            f"Rule Result: {sanitized_ctx['rule_result']}.\n"
            f"Respond with JSON format:\n"
            f'{{"is_threat": true/false, "severity": "low"/"medium"/"high"/"critical", "confidence": 0.0-1.0, "requires_human_review": true/false, "reasoning": "brief explanation"}}'
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AIShield-CyberSecurity-Pipeline/2.0"
        }

        body = {
            "model": cls.DEFAULT_MODEL,
            "messages": [
                {"role": "system", "content": "You are TypeSafe Jev SystemOne, an AI cybersecurity triage engine. Evaluate events objectively and output valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        req = urllib.request.Request(
            cls.API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=cls.TIMEOUT_SECONDS) as response:
                if response.status == 200:
                    raw_data = json.loads(response.read().decode("utf-8"))
                    content = raw_data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                    parsed = json.loads(content)

                    is_threat = bool(parsed.get("is_threat", False))
                    sev = str(parsed.get("severity", "medium")).lower()
                    if sev not in ("low", "medium", "high", "critical"):
                        sev = "medium"

                    # If Rule 4 hard denial was already triggered, enforce non-override constraint
                    if rule_override_applied and not is_threat:
                        is_threat = True
                        reasoning = f"{parsed.get('reasoning', '')} [Advisory Note: Deterministic Rule 4 denial strictly upheld]"
                    else:
                        reasoning = parsed.get("reasoning", "Jev automated assessment completed.")

                    return {
                        "status": "ASSESSED",
                        "model": cls.DEFAULT_MODEL,
                        "noul_verdict": is_threat,
                        "severity_choice": sev,
                        "confidence": float(parsed.get("confidence", 0.85)),
                        "human_review_required": bool(parsed.get("requires_human_review", sev in ("high", "critical"))),
                        "explanation": reasoning,
                        "timestamp": now,
                        "rule_override_active": rule_override_applied
                    }
                else:
                    return {
                        "status": "API_ERROR",
                        "model": cls.DEFAULT_MODEL,
                        "error": f"TypeSafe Jev HTTP {response.status}",
                        "timestamp": now,
                        "rule_override_active": rule_override_applied
                    }
        except urllib.error.HTTPError as e:
            logger.warning(f"[Jev] External API HTTP error: {e.code} - {e.reason}")
            return {
                "status": "API_ERROR",
                "model": cls.DEFAULT_MODEL,
                "error": f"TypeSafe Jev HTTP error: {e.code}",
                "timestamp": now,
                "rule_override_active": rule_override_applied
            }
        except urllib.error.URLError as e:
            logger.warning(f"[Jev] External API connection error: {e.reason}")
            return {
                "status": "UNREACHABLE",
                "model": cls.DEFAULT_MODEL,
                "error": f"TypeSafe Jev connection failed: {e.reason}",
                "timestamp": now,
                "rule_override_active": rule_override_applied
            }
        except Exception as e:
            logger.warning(f"[Jev] Unexpected assessment exception: {str(e)}")
            return {
                "status": "FALLBACK",
                "model": cls.DEFAULT_MODEL,
                "error": str(e),
                "timestamp": now,
                "rule_override_active": rule_override_applied
            }
