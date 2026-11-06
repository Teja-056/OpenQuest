"""
AI Shield — Machine Learning Dataset Generation & Feature Engineering.
Generates a labeled, reproducible synthetic dataset of employee and AI-agent behavioral telemetry.
Provides robust feature extraction for training and real-time inference.
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Designated feature names
FEATURE_NAMES = [
    "sensitive_file_access_count",
    "downloads_24h",
    "external_sharing_count",
    "activity_volume",
    "failed_access_attempts",
    "request_frequency",
    "is_off_hours",
    "is_weekend",
    "sensitive_resource_frequency",
    "unusual_destination"
]

def extract_features_from_event(event: dict) -> np.ndarray:
    """
    Extract a 10-dimensional numerical feature vector from a single incoming security event.
    Guarantees deterministic feature ordering and prevents training-serving skew.
    """
    is_sensitive = 1.0 if event.get("is_sensitive") else 0.0
    action = str(event.get("action", "")).lower()
    destination = str(event.get("destination", "")).lower()
    event_type = str(event.get("event_type", "")).lower()

    # Destination anomaly
    if "unusual_destination" in event:
        unusual_dest = float(event["unusual_destination"])
    else:
        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "workstation", "corp", "none"))
        unusual_dest = 1.0 if not is_internal else 0.0

    # Off-hours & weekend analysis from timestamp or direct overrides
    if "is_off_hours" in event and "is_weekend" in event:
        is_off_hours = float(event["is_off_hours"])
        is_weekend = float(event["is_weekend"])
    else:
        ts_str = event.get("timestamp")
        hour = 12
        weekday = 2
        if ts_str:
            try:
                # Handle ISO string with or without Z
                clean_ts = ts_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                hour = dt.hour
                weekday = dt.weekday()
            except Exception:
                pass

        is_off_hours = float(event.get("is_off_hours", 1.0 if (hour < 7 or hour >= 19) else 0.0))
        is_weekend = float(event.get("is_weekend", 1.0 if (weekday >= 5) else 0.0))

    # Action-specific counts and upstream aggregator metrics
    if "downloads_24h" in event:
        downloads_24h = float(event["downloads_24h"])
    else:
        downloads_24h = 1.0 if ("download" in action or "download" in event_type) else 0.0

    if "external_sharing_count" in event:
        ext_sharing = float(event["external_sharing_count"])
    else:
        ext_sharing = 1.0 if ("share" in action and unusual_dest == 1.0) else 0.0

    if "failed_access_attempts" in event:
        failed_attempts = float(event["failed_access_attempts"])
    else:
        failed_attempts = 1.0 if ("fail" in action or "denied" in str(event.get("rule_result", "")).lower()) else 0.0

    # In single-event inference, base volume is 1; upstream telemetry aggregators can supply higher
    activity_volume = float(event.get("activity_volume", 1.0))
    request_frequency = float(event.get("request_frequency", 1.0))

    if "sensitive_file_access_count" in event:
        sensitive_access_count = float(event["sensitive_file_access_count"])
    else:
        sensitive_access_count = is_sensitive
    sensitive_freq = sensitive_access_count / max(activity_volume, 1.0)

    vector = np.array([
        sensitive_access_count,
        downloads_24h,
        ext_sharing,
        activity_volume,
        failed_attempts,
        request_frequency,
        is_off_hours,
        is_weekend,
        sensitive_freq,
        unusual_dest
    ], dtype=np.float32)

    return vector

def generate_synthetic_dataset(n_samples: int = 2500, contamination: float = 0.08, random_state: int = 42) -> pd.DataFrame:
    """
    Generate clearly labeled synthetic dataset representing SME enterprise security behaviors.
    Includes nominal work activity (normal) and anomalous activity (anomalous).
    """
    np.random.seed(random_state)
    random.seed(random_state)

    n_anomalies = int(n_samples * contamination)
    n_normal = n_samples - n_anomalies

    # 1. NOMINAL WORK ACTIVITY (Standard business operations)
    normal_data = {
        "sensitive_file_access_count": np.random.poisson(lam=0.5, size=n_normal),
        "downloads_24h": np.random.poisson(lam=0.8, size=n_normal),
        "external_sharing_count": np.zeros(n_normal, dtype=float),
        "activity_volume": np.random.uniform(5, 45, size=n_normal),
        "failed_access_attempts": np.random.choice([0, 1], p=[0.94, 0.06], size=n_normal),
        "request_frequency": np.random.uniform(0.5, 3.5, size=n_normal),
        "is_off_hours": np.random.choice([0, 1], p=[0.92, 0.08], size=n_normal),
        "is_weekend": np.random.choice([0, 1], p=[0.96, 0.04], size=n_normal),
        "sensitive_resource_frequency": np.random.uniform(0.0, 0.15, size=n_normal),
        "unusual_destination": np.zeros(n_normal, dtype=float),
        "is_anomaly": np.zeros(n_normal, dtype=int)  # 0 = Normal
    }

    # 2. ANOMALOUS ACTIVITY (Data exfiltration, brute force, mass exports, off-hours spikes)
    anomaly_data = {
        "sensitive_file_access_count": np.random.uniform(5, 25, size=n_anomalies),
        "downloads_24h": np.random.uniform(10, 80, size=n_anomalies),
        "external_sharing_count": np.random.choice([1, 2, 3, 5], p=[0.4, 0.3, 0.2, 0.1], size=n_anomalies),
        "activity_volume": np.random.uniform(60, 250, size=n_anomalies),
        "failed_access_attempts": np.random.choice([3, 5, 10, 20], size=n_anomalies),
        "request_frequency": np.random.uniform(8.0, 40.0, size=n_anomalies),
        "is_off_hours": np.random.choice([0, 1], p=[0.15, 0.85], size=n_anomalies),
        "is_weekend": np.random.choice([0, 1], p=[0.35, 0.65], size=n_anomalies),
        "sensitive_resource_frequency": np.random.uniform(0.60, 1.0, size=n_anomalies),
        "unusual_destination": np.random.choice([0, 1], p=[0.10, 0.90], size=n_anomalies),
        "is_anomaly": np.ones(n_anomalies, dtype=int)  # 1 = Anomaly
    }

    df_normal = pd.DataFrame(normal_data)
    df_anomaly = pd.DataFrame(anomaly_data)

    df = pd.concat([df_normal, df_anomaly], ignore_index=True)
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return df

if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "synthetic_activity_dataset.csv"
    dataset = generate_synthetic_dataset(2500, 0.08)
    dataset.to_csv(out_path, index=False)
    print(f"Generated synthetic training dataset with {len(dataset)} records at {out_path}")
