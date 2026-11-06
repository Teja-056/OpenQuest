"""
AI Shield — Data Loss Prevention (DLP) Engine.
Detects sensitive data patterns (PII, PAN, Aadhaar, Credit Cards, API Keys, Passwords),
validates transfer destinations, enforces classifications, and provides safe quarantine.
"""

import re
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from backend.config import Config
from backend.repository import Repository

# Data Classifications
CLASS_PUBLIC = "PUBLIC"
CLASS_INTERNAL = "INTERNAL"
CLASS_CONFIDENTIAL = "CONFIDENTIAL"
CLASS_RESTRICTED = "RESTRICTED"

# Regular Expression Patterns for Sensitive Identifiers
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
RE_PHONE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
RE_AADHAAR = re.compile(r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b")
RE_CREDIT_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
RE_API_KEY = re.compile(r"(?:AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|Bearer\s+[A-Za-z0-9\-._~+/]+=*)")
RE_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")
RE_PASSWORD_KEYWORD = re.compile(r"(?:password|passwd|secret|api_key|access_token)\s*[:=]\s*['\"]?([^'\"\s\n]{6,})['\"]?", re.IGNORECASE)

PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "proton.me", "aol.com", "zoho.com", "mail.com"
}

PUBLIC_SHARING_SERVICES = {
    "dropbox.com", "drive.google.com", "wetransfer.com", "mega.nz",
    "pastebin.com", "box.com", "onedrive.live.com", "anonfiles.com"
}

def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card number using the standard Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return (checksum % 10) == 0

class DLPEngine:
    """
    Modular Data Loss Prevention Engine.
    Scans text/metadata, validates destinations, and manages file quarantine.
    """

    @classmethod
    def scan_content(cls, content: str) -> List[Dict[str, Any]]:
        """
        Inspect text content or metadata for sensitive identifiers.
        Returns list of matched pattern types and sample matches (redacted).
        """
        matches = []
        if not content:
            return matches

        # 1. PAN Check
        for pan in RE_PAN.findall(content):
            matches.append({"pattern": "INDIAN_PAN", "value": f"{pan[:2]}***{pan[-2:]}"})

        # 2. Aadhaar Check
        for aadhaar in RE_AADHAAR.findall(content):
            clean = aadhaar.replace(" ", "")
            matches.append({"pattern": "INDIAN_AADHAAR", "value": f"XXXX-XXXX-{clean[-4:]}"})

        # 3. Credit Card Check with Luhn validation
        for cc in RE_CREDIT_CARD.findall(content):
            if luhn_checksum_valid(cc):
                clean = re.sub(r"[-\s]", "", cc)
                matches.append({"pattern": "CREDIT_CARD", "value": f"****-****-****-{clean[-4:]}"})

        # 4. API Keys & Secrets
        for key in RE_API_KEY.findall(content):
            matches.append({"pattern": "API_KEY_OR_SECRET", "value": f"{key[:6]}...[REDACTED]"})

        # 5. Private Key
        if RE_PRIVATE_KEY.search(content):
            matches.append({"pattern": "PRIVATE_KEY_HEADER", "value": "-----BEGIN PRIVATE KEY----- [DETECTED]"})

        # 6. Plaintext Passwords
        for pwd_match in RE_PASSWORD_KEYWORD.findall(content):
            matches.append({"pattern": "PLAINTEXT_CREDENTIAL", "value": "[PASSWORD_PATTERN_DETECTED]"})

        # 7. Personal Emails
        for email in RE_EMAIL.findall(content):
            domain = email.split("@")[-1].lower()
            if domain in PERSONAL_EMAIL_DOMAINS:
                matches.append({"pattern": "PERSONAL_EMAIL", "value": f"{email[:2]}***@{domain}"})

        return matches

    @classmethod
    def classify_resource(cls, resource_name: str, is_sensitive: bool = False, matches: Optional[List[Dict[str, Any]]] = None) -> str:
        """Determine data classification level."""
        res_lower = resource_name.lower()
        if matches and any(m["pattern"] in ("CREDIT_CARD", "PRIVATE_KEY_HEADER", "API_KEY_OR_SECRET") for m in matches):
            return CLASS_RESTRICTED

        if any(kw in res_lower for kw in ("payroll", "ssn", "secret", "financial_master", "credential", "salary")):
            return CLASS_RESTRICTED

        if is_sensitive or (matches and len(matches) > 0) or any(kw in res_lower for kw in ("customer", "pii", "user_records", "q3_payroll", "employee_performance")):
            return CLASS_CONFIDENTIAL

        if any(kw in res_lower for kw in ("internal", "roadmap", "architecture", "minutes", "spec")):
            return CLASS_INTERNAL

        return CLASS_PUBLIC

    @classmethod
    def evaluate_dlp(cls, event: Dict[str, Any]) -> Tuple[bool, str, List[Dict[str, Any]], str]:
        """
        Evaluate an event against DLP policies.
        Returns: (is_violation: bool, decision_code: str, detected_patterns: list, classification: str)
        """
        resource = str(event.get("resource", "")).lower()
        destination = str(event.get("destination", "")).lower()
        description = str(event.get("description", ""))
        action = str(event.get("action", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))

        # Inspect content strings for PII/secrets
        combined_text = f"{resource} {description} {destination}"
        detected_patterns = cls.scan_content(combined_text)
        classification = cls.classify_resource(resource, is_sensitive, detected_patterns)

        # Check destination properties
        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "laptop", "corp", "none"))
        is_external = bool(destination) and not is_internal

        # Specific external indicators
        is_personal_email = any(d in destination for d in PERSONAL_EMAIL_DOMAINS) or ("personal" in destination and "mail" in destination)
        is_public_share_service = any(s in destination for s in PUBLIC_SHARING_SERVICES) or "dropbox" in destination or "drive" in destination

        # DLP VIOLATION RULES:
        # Rule 1: Restricted or Confidential resource shared externally or to personal destination
        if (classification in (CLASS_RESTRICTED, CLASS_CONFIDENTIAL) or is_sensitive) and (is_external or is_personal_email or is_public_share_service):
            if is_personal_email:
                decision = "flagged_dlp_personal_email_share"
            elif is_public_share_service:
                decision = "flagged_dlp_public_cloud_share"
            else:
                decision = "flagged_dlp_external_share"

            # Record DLP Violation
            violation_record = {
                "event_id": event.get("event_id"),
                "actor_id": event.get("actor_id", "unknown"),
                "actor_type": event.get("actor_type", "employee"),
                "resource": event.get("resource", "unspecified"),
                "destination": destination,
                "classification": classification,
                "detected_patterns": detected_patterns,
                "status": "flagged",
                "action_taken": "quarantine_attachment_and_notify_manager"
            }
            Repository.record_dlp_violation(violation_record)

            return True, decision, detected_patterns, classification

        # Rule 2: Detected high-severity secrets (private keys, API credentials) regardless of destination
        if any(m["pattern"] in ("PRIVATE_KEY_HEADER", "API_KEY_OR_SECRET") for m in detected_patterns):
            decision = "flagged_dlp_credential_exposure"
            Repository.record_dlp_violation({
                "event_id": event.get("event_id"),
                "actor_id": event.get("actor_id", "unknown"),
                "actor_type": event.get("actor_type", "employee"),
                "resource": event.get("resource", "unspecified"),
                "destination": destination,
                "classification": CLASS_RESTRICTED,
                "detected_patterns": detected_patterns,
                "status": "flagged",
                "action_taken": "quarantine_attachment_and_notify_manager"
            })
            return True, decision, detected_patterns, CLASS_RESTRICTED

        # Allowed / Clean
        return False, "allowed", detected_patterns, classification

    @classmethod
    def quarantine_file(cls, filename: str, content_bytes: bytes) -> Tuple[bool, str, Optional[str]]:
        """
        Safely quarantine an uploaded or intercepted file.
        Strictly prevents path traversal and confines files to Config.QUARANTINE_PATH.
        """
        quarantine_dir = Path(Config.QUARANTINE_PATH).resolve()
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize filename
        safe_name = Path(filename).name
        if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
            return False, "Path traversal attempt detected in filename", None

        unique_id = uuid.uuid4().hex[:12]
        target_path = quarantine_dir / f"{unique_id}_{safe_name}"

        # Verify confinement
        if not target_path.resolve().is_relative_to(quarantine_dir):
            return False, "File path resolution out of bounds", None

        try:
            with open(target_path, "wb") as f:
                f.write(content_bytes)
            return True, "File quarantined successfully", str(target_path)
        except Exception as e:
            return False, f"Failed to quarantine file: {e}", None
