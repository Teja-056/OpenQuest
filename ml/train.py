"""
AI Shield — Machine Learning Model Training & Evaluation Pipeline.
Trains a Scikit-learn IsolationForest model on behavioral security telemetry,
evaluates precision, recall, F1, and ROC-AUC, and serializes the model artifact.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report
)

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Config
from backend.repository import Repository
from ml.dataset import FEATURE_NAMES, generate_synthetic_dataset

def train_isolation_forest(
    n_samples: int = 3000,
    contamination: float = 0.08,
    random_state: int = 42
) -> dict:
    print("=" * 70)
    print("AI Shield — Machine Learning Anomaly Detection Model Training")
    print("=" * 70)

    # 1. Dataset Generation
    print(f"\n[Step 1] Preparing dataset ({n_samples} samples, contamination={contamination})...")
    df = generate_synthetic_dataset(n_samples=n_samples, contamination=contamination, random_state=random_state)
    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(data_dir / "synthetic_activity_dataset.csv", index=False)
    print(f"Dataset persisted to {data_dir / 'synthetic_activity_dataset.csv'}")

    X = df[FEATURE_NAMES].values
    y = df["is_anomaly"].values

    # 2. Train / Test Split
    print("\n[Step 2] Splitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )
    print(f"Training samples: {len(X_train)} | Test samples: {len(X_test)}")

    # 3. Model Training
    print("\n[Step 3] Training Scikit-learn IsolationForest...")
    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        max_samples="auto",
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train)

    # 4. Evaluation on Held-Out Test Set
    print("\n[Step 4] Evaluating model on held-out test data...")
    # IsolationForest outputs: -1 for outlier, 1 for inlier
    raw_preds = model.predict(X_test)
    y_pred = np.where(raw_preds == -1, 1, 0)

    # Score samples: lower score indicates greater anomaly
    raw_scores = model.decision_function(X_test)
    # Convert decision score to an anomaly likelihood score (0.0 to 1.0)
    # decision_function: positive for inliers, negative for outliers
    anomaly_probs = 1.0 / (1.0 + np.exp(raw_scores * 3.0))

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    roc_auc = float(roc_auc_score(y_test, anomaly_probs))

    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"Confusion Matrix (TN, FP / FN, TP):\n  {cm[0]}\n  {cm[1]}")

    # 5. Serialization
    print("\n[Step 5] Serializing model and metadata...")
    model_dir = Path(Config.ML_MODEL_PATH).parent
    model_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, Config.ML_MODEL_PATH)
    print(f"Model serialized to {Config.ML_MODEL_PATH}")

    metadata = {
        "model_name": "IsolationForest-BehavioralAnomaly",
        "algorithm": "IsolationForest",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "features": FEATURE_NAMES,
        "contamination": contamination,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm,
        "artifact_path": str(Config.ML_MODEL_PATH),
        "training_date": str(pd.Timestamp.now(tz="UTC"))
    }

    with open(Config.ML_METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata persisted to {Config.ML_METADATA_PATH}")

    # 6. Database Registration
    print("\n[Step 6] Registering model in database...")
    version_rec = {
        "model_name": "IsolationForest-BehavioralAnomaly",
        "algorithm": "IsolationForest",
        "training_samples": len(X_train),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "artifact_path": str(Config.ML_MODEL_PATH),
        "is_active": True,
        "features": FEATURE_NAMES
    }
    saved_version = Repository.register_model_version(version_rec)
    print(f"Model version registered with ID: {saved_version.get('version_id')}")

    print("\n[SUCCESS] Model training and evaluation complete.")
    return metadata

if __name__ == "__main__":
    train_isolation_forest()
