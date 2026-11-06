"""
AI Shield — Machine Learning Adversarial & Stress Testing Suite.
Tests the trained Isolation Forest against:
1. Synthetic distribution leakage / artificial gap analysis.
2. Realistic boundary cases (overlapping normal & anomalous behaviors).
3. Legitimate SME high-volume activities (backup, batch reports) -> False Positive evaluation.
4. Stealthy low-profile data exfiltration -> False Negative evaluation.
5. Extreme / out-of-distribution values & robustness.
6. Missing / malformed feature dictionaries.
"""

import sys
import numpy as np
import pandas as pd
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.anomaly_detector import ProductionMLAnomalyDetector
from ml.dataset import FEATURE_NAMES, extract_features_from_event

def run_ml_audit():
    print("=" * 60)
    print("AI-SHIELD INDEPENDENT MACHINE LEARNING AUDIT")
    print("=" * 60)

    detector = ProductionMLAnomalyDetector()
    print(f"Model Path: {detector.model_path}")
    print(f"Model Loaded: {detector.model is not None}")

    # TEST 1: Synthetic Dataset Distribution Analysis (Shortcut Detection)
    print("\n--- TEST 1: SYNTHETIC DATASET DISTRIBUTION AUDIT ---")
    from ml.dataset import generate_synthetic_dataset
    df = generate_synthetic_dataset(2500, contamination=0.08)
    normal = df[df["is_anomaly"] == 0]
    anomaly = df[df["is_anomaly"] == 1]

    norm_vol_min, norm_vol_max = normal["activity_volume"].min(), normal["activity_volume"].max()
    anom_vol_min, anom_vol_max = anomaly["activity_volume"].min(), anomaly["activity_volume"].max()
    print(f"Normal Activity Volume range: [{norm_vol_min:.2f}, {norm_vol_max:.2f}]")
    print(f"Anomaly Activity Volume range: [{anom_vol_min:.2f}, {anom_vol_max:.2f}]")
    gap = anom_vol_min - norm_vol_max
    print(f"Activity Volume Artificial Gap: {gap:.2f}")

    norm_sens_max = normal["sensitive_file_access_count"].max()
    anom_sens_min = anomaly["sensitive_file_access_count"].min()
    print(f"Normal Max Sensitive Access: {norm_sens_max}, Anomaly Min Sensitive Access: {anom_sens_min}")

    if gap > 0:
        print("[AUDIT FINDING] ARTIFICIAL GAP DETECTED: The synthetic dataset has an unpopulated buffer zone between normal (max 45) and anomaly (min 60), creating an artificial decision shortcut.")

    # TEST 2: Realistic SME Scenarios (False Positives & False Negatives)
    print("\n--- TEST 2: REALISTIC AMBIGUOUS SCENARIOS ---")
    scenarios = [
        # FP Risks (Legitimate SME tasks that look heavy)
        {
            "name": "FP-1: System Administrator Nightly Backup",
            "event": {
                "activity_volume": 120.0,
                "request_frequency": 12.0,
                "sensitive_file_access_count": 0,
                "downloads_24h": 50,
                "is_off_hours": 1.0,
                "is_weekend": 0.0,
                "unusual_destination": 0.0,
                "action": "backup_archive",
                "destination": "internal_nas"
            },
            "expected": "Normal (Legitimate maintenance)"
        },
        {
            "name": "FP-2: Marketing Manager Bulk Asset Download (Working Hours)",
            "event": {
                "activity_volume": 55.0,
                "request_frequency": 8.0,
                "sensitive_file_access_count": 0,
                "downloads_24h": 40,
                "is_off_hours": 0.0,
                "is_weekend": 0.0,
                "unusual_destination": 0.0,
                "action": "bulk_download",
                "destination": "internal_share"
            },
            "expected": "Normal (Legitimate marketing job)"
        },
        # FN Risks (Stealthy insider attacks that mimic normal metrics)
        {
            "name": "FN-1: Stealthy Exfiltration (1 sensitive file, low volume, business hours)",
            "event": {
                "activity_volume": 15.0,
                "request_frequency": 1.5,
                "is_sensitive": True,
                "downloads_24h": 1,
                "external_sharing_count": 1,
                "is_off_hours": 0.0,
                "is_weekend": 0.0,
                "destination": "external_dropbox",
                "action": "share_document"
            },
            "expected": "Anomaly (Malicious data leak)"
        },
        {
            "name": "FN-2: Targeted Low-and-Slow Credential Probing",
            "event": {
                "activity_volume": 8.0,
                "request_frequency": 0.8,
                "is_sensitive": True,
                "failed_access_attempts": 2,
                "is_off_hours": 0.0,
                "is_weekend": 0.0,
                "destination": "internal_auth_service",
                "action": "failed_login"
            },
            "expected": "Anomaly (Targeted probing)"
        },
        # True Positives
        {
            "name": "TP-1: Massive Weekend Data Dumping",
            "event": {
                "activity_volume": 180.0,
                "request_frequency": 25.0,
                "is_sensitive": True,
                "downloads_24h": 70,
                "is_off_hours": 1.0,
                "is_weekend": 1.0,
                "destination": "unknown_ip",
                "action": "download"
            },
            "expected": "Anomaly (Severe exfiltration)"
        },
        # True Negatives
        {
            "name": "TN-1: Standard Employee Editing Document",
            "event": {
                "activity_volume": 12.0,
                "request_frequency": 1.0,
                "is_sensitive": False,
                "downloads_24h": 0,
                "is_off_hours": 0.0,
                "is_weekend": 0.0,
                "destination": "internal_sharepoint",
                "action": "edit_doc"
            },
            "expected": "Normal (Standard workday task)"
        }
    ]

    for sc in scenarios:
        ev = sc["event"]
        res = detector.score(ev)
        print(f"Scenario: {sc['name']}")
        print(f"  Expected: {sc['expected']}")
        print(f"  Model Result: is_anomaly={res.anomaly}, risk_score={res.risk_score:.2f}, level={res.risk_level}, factors={res.factors}")

    # TEST 3: Extreme / Out-of-Distribution Inputs
    print("\n--- TEST 3: EXTREME & OUT-OF-DISTRIBUTION ROBUSTNESS ---")
    extreme_cases = [
        {"name": "Zero/Empty Payload", "event": {}},
        {"name": "Astronomical Volume", "event": {"activity_volume": 1e9, "request_frequency": 1e6}},
        {"name": "Negative Volume", "event": {"activity_volume": -100, "request_frequency": -5}},
        {"name": "All Features Missing but is_sensitive True", "event": {"is_sensitive": True}}
    ]

    for ec in extreme_cases:
        res = detector.score(ec["event"])
        print(f"Case: {ec['name']} -> is_anomaly={res.anomaly}, score={res.risk_score:.2f}, level={res.risk_level}")

if __name__ == "__main__":
    run_ml_audit()
