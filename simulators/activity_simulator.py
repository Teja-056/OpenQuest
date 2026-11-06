"""
AI Shield — Activity Simulator Module.
Generates realistic simulated security events across employees, autonomous AI agents,
DLP exfiltration vectors, and API threats for demonstration and testing.
Clearly marks simulated events in strict accordance with docs/api_contract.md.
"""

import sys
import time
import uuid
import random
import argparse
from typing import Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.pipeline.event_processor import process_security_event

SCENARIOS = [
    {
        "name": "Normal Employee Document Review",
        "event_type": "file_access",
        "actor_type": "employee",
        "actor_id": "EMP001",
        "resource": "q4_product_spec.pdf",
        "is_sensitive": False,
        "action": "read",
        "destination": "internal",
        "source": "employee_simulator",
        "description": "Routine review of product documentation"
    },
    {
        "name": "Internal Sensitive Performance Review Access",
        "event_type": "file_access",
        "actor_type": "employee",
        "actor_id": "EMP002",
        "resource": "employee_performance_q3.csv",
        "is_sensitive": True,
        "action": "read",
        "destination": "internal",
        "source": "employee_simulator",
        "description": "Internal authorized read of performance ratings"
    },
    {
        "name": "Sensitive File Download to Workstation",
        "event_type": "file_download",
        "actor_type": "employee",
        "actor_id": "EMP003",
        "resource": "financial_ledger_2026.xlsx",
        "is_sensitive": True,
        "action": "download",
        "destination": "workstation_laptop_04",
        "source": "employee_simulator",
        "description": "Authorized download of financial ledger to encrypted laptop"
    },
    {
        "name": "DLP Exfiltration Attempt: Customer PII to Personal Gmail",
        "event_type": "file_share",
        "actor_type": "employee",
        "actor_id": "EMP002",
        "resource": "customer_pii_vault.csv",
        "is_sensitive": True,
        "action": "share",
        "destination": "employee_personal@gmail.com",
        "source": "employee_simulator",
        "description": "Attempted file transfer of sensitive customer list to personal email"
    },
    {
        "name": "DLP Exfiltration Attempt: Financial Dump to Public Dropbox",
        "event_type": "file_share",
        "actor_type": "employee",
        "actor_id": "EMP004",
        "resource": "q3_payroll_master.xlsx",
        "is_sensitive": True,
        "action": "share",
        "destination": "https://dropbox.com/s/public_share_dump",
        "source": "employee_simulator",
        "description": "Attempted file sync of executive payroll to public cloud storage"
    },
    {
        "name": "Authorized AI Agent Routine Task",
        "event_type": "api_request",
        "actor_type": "agent",
        "actor_id": "agent_indexer_01",
        "resource": "/api/v1/catalog",
        "is_sensitive": False,
        "action": "read",
        "destination": "internal",
        "source": "agent_simulator",
        "description": "Catalog indexing agent querying product catalog"
    },
    {
        "name": "Unauthorized AI Agent Access Attempt to Secrets",
        "event_type": "api_request",
        "actor_type": "agent",
        "actor_id": "agent_indexer_01",
        "resource": "/admin/keys/production_secrets.env",
        "is_sensitive": True,
        "action": "read",
        "destination": "internal",
        "source": "agent_simulator",
        "description": "Catalog agent attempting to access administrative secrets file"
    },
    {
        "name": "External API Brute Force Probe",
        "event_type": "authentication",
        "actor_type": "external",
        "actor_id": "client_ip_198.51.100.44",
        "resource": "/api/auth/login",
        "is_sensitive": True,
        "action": "login",
        "destination": "internal",
        "source": "threat_simulator",
        "description": "Repeated failed authentication attempts from suspicious external subnet"
    },
    {
        "name": "Off-Hours Bulk Data Export (ML Anomaly)",
        "event_type": "data_export",
        "actor_type": "employee",
        "actor_id": "EMP004",
        "resource": "anomalous_bulk_archive.tar.gz",
        "is_sensitive": False,
        "action": "export",
        "destination": "staging_bucket_unrecognized",
        "source": "endpoint_agent",
        "description": "Extreme volume data archive created at 02:45 AM on Sunday"
    }
]

def emit_event(scenario: Dict[str, Any], verbose: bool = True) -> Dict[str, Any]:
    """Emit a single security event through the pipeline."""
    now_iso = datetime.now(timezone.utc).isoformat()
    evt_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"

    payload = dict(scenario)
    payload["event_id"] = evt_id
    payload["timestamp"] = now_iso

    success, result, status_code = process_security_event(payload)
    if verbose:
        status_tag = "[SUCCESS]" if success else "[REJECTED]"
        print(f"{status_tag} {evt_id} | Scenario: {scenario.get('name')} | Status: {status_code}")
        if success:
            event_data = result.get("event", {})
            risk = event_data.get("risk_level", "low").upper()
            score = event_data.get("risk_score", 0.0)
            rule = event_data.get("rule_result", "allowed")
            print(f"         Rule: {rule} | Risk: {risk} ({score}) | Action: {event_data.get('recommended_action')}")
            if result.get("alert"):
                print(f"         Alert: {result['alert']['alert_id']} ({result['alert']['alert_type']})")
            if result.get("incident"):
                print(f"         Incident: {result['incident']['incident_id']}")
    return result

def run_simulation(count: int = 5, delay: float = 1.0):
    """Run simulated event stream for demo."""
    print("=" * 70)
    print("AI Shield — Real-Time Telemetry Simulation")
    print(f"Streaming {count} synthetic security events...")
    print("=" * 70)

    for i in range(count):
        scenario = random.choice(SCENARIOS)
        emit_event(scenario)
        if i < count - 1 and delay > 0:
            time.sleep(delay)

    print("\n[COMPLETE] Simulation stream finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-SHIELD Activity Simulator")
    parser.add_argument("--count", type=int, default=5, help="Number of simulated events to emit")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds delay between events")
    args = parser.parse_args()
    run_simulation(count=args.count, delay=args.delay)
