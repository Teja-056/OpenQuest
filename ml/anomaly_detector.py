"""
AI Shield — Machine Learning Anomaly Detector (Inference Pipeline).
Loads the trained Scikit-learn IsolationForest artifact and scores security events in real-time.
Gracefully handles missing or uninitialized models with fail-safe heuristics.
"""

import os
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, List
from backend.config import Config
from backend.pipeline.ml_adapter import MLAnomalyResult
from ml.dataset import extract_features_from_event, FEATURE_NAMES

class ProductionMLAnomalyDetector:
    """
    Production inference engine for real-time behavioral anomaly scoring.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or Config.ML_MODEL_PATH
        self.model = None
        self._load_model()

    def _load_model(self):
        """Safely load the serialized IsolationForest artifact."""
        try:
            if os.path.isfile(self.model_path):
                self.model = joblib.load(self.model_path)
                # print(f"[MLAnomalyDetector] Successfully loaded IsolationForest model from {self.model_path}")
            else:
                print(f"[MLAnomalyDetector] Notice: Model artifact not found at {self.model_path}. Using baseline heuristics.")
        except Exception as e:
            print(f"[MLAnomalyDetector] Warning: Failed to deserialize model at {self.model_path}: {e}")
            self.model = None

    def score(self, event: Dict[str, Any]) -> MLAnomalyResult:
        """
        Extract features and compute statistical anomaly score (0.0 to 100.0).
        """
        # If incoming event already has upstream explicit score, preserve it
        if event.get("risk_score") is not None and event.get("anomaly") is not None:
            score = float(event["risk_score"])
            level = "critical" if score >= 80.0 else ("high" if score >= 60.0 else ("medium" if score >= 30.0 else "low"))
            return MLAnomalyResult(
                anomaly=bool(event["anomaly"]),
                risk_score=score,
                risk_level=level,
                confidence=0.92,
                factors=["Explicit upstream telemetry score preserved"]
            )

        features = extract_features_from_event(event)

        # 1. Inference via trained IsolationForest
        if self.model is not None:
            try:
                X = features.reshape(1, -1)
                # raw_score: positive for inliers, negative for outliers
                decision = float(self.model.decision_function(X)[0])
                pred = int(self.model.predict(X)[0])  # -1 = anomaly, 1 = normal

                is_anomaly = (pred == -1)

                # Sigmoid mapping from decision score to 0 - 100 risk score
                # If decision is negative, outlier probability rises sharply
                # typical decision range is -0.3 to +0.3
                anomaly_prob = 1.0 / (1.0 + np.exp(decision * 12.0))
                normalized_score = round(float(anomaly_prob * 100.0), 2)

                # Ensure anomalies have minimum high risk score
                if is_anomaly:
                    normalized_score = max(normalized_score, 65.0)

                risk_level = "critical" if normalized_score >= 80.0 else (
                    "high" if normalized_score >= 60.0 else (
                        "medium" if normalized_score >= 30.0 else "low"
                    )
                )

                # Factor analysis
                factors = []
                if features[0] > 0:  # sensitive_file_access_count
                    factors.append("Sensitive asset access")
                if features[2] > 0:  # external_sharing_count
                    factors.append("External destination sharing attempt")
                if features[6] > 0:  # is_off_hours
                    factors.append("Off-hours operation detected")
                if features[7] > 0:  # is_weekend
                    factors.append("Weekend activity")
                if features[9] > 0:  # unusual_destination
                    factors.append("Non-standard external destination")

                if not factors:
                    factors.append("Nominal behavioral pattern")

                return MLAnomalyResult(
                    anomaly=is_anomaly,
                    risk_score=normalized_score,
                    risk_level=risk_level,
                    confidence=0.94,
                    factors=factors
                )
            except Exception as inf_err:
                print(f"[MLAnomalyDetector] Inference error: {inf_err}. Falling back to baseline heuristics.")

        # 2. Fallback Heuristic Scoring (if model unavailable)
        destination = str(event.get("destination", "")).lower()
        is_sensitive = bool(event.get("is_sensitive", False))
        is_internal = not destination or any(kw in destination for kw in ("internal", "local", "intranet", "corp", "none"))

        if is_sensitive and not is_internal:
            return MLAnomalyResult(
                anomaly=True,
                risk_score=85.0,
                risk_level="critical",
                confidence=0.88,
                factors=["Heuristic: Sensitive resource directed to external target"]
            )
        elif is_sensitive:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=35.0,
                risk_level="medium",
                confidence=0.80,
                factors=["Heuristic: Sensitive resource internal access"]
            )
        else:
            return MLAnomalyResult(
                anomaly=False,
                risk_score=10.0,
                risk_level="low",
                confidence=0.90,
                factors=["Heuristic: Nominal routine activity"]
            )
