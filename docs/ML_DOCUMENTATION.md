# AI-SHIELD — Machine Learning Pipeline & Adversarial Validation Report

## 1. Executive Summary

AI-SHIELD deploys an unsupervised statistical machine learning pipeline powered by Scikit-learn's `IsolationForest` algorithm. The system continuously evaluates employee and AI agent behavioral telemetry, flags statistical outliers, and calculates continuous risk scores between 0.0 and 100.0.

In strict adherence to Contract Rule 4 (`docs/api_contract.md`), the machine learning pipeline functions purely as an anomaly indicator and **never overrides, reduces, or downgrades a hard security denial**.

---

## 2. Feature Engineering Pipeline

Incoming events are transformed into 10-dimensional numerical vectors by `ml/dataset.py:extract_features_from_event()`:

| Feature Index | Feature Name | Representation & Type | Description |
|---|---|---|---|
| 0 | `sensitive_file_access_count` | `float` (0.0 or 1.0) | Indicator of sensitive resource involvement |
| 1 | `downloads_24h` | `float` (0.0 or 1.0) | High-volume download action indicator |
| 2 | `external_sharing_count` | `float` (0.0 or 1.0) | File share directed to external target |
| 3 | `activity_volume` | `float` (&ge; 1.0) | Telemetry throughput volume count |
| 4 | `failed_access_attempts` | `float` (&ge; 0.0) | Authentication failures or denied actions |
| 5 | `request_frequency` | `float` (&ge; 0.5) | Normalized requests per minute rate |
| 6 | `is_off_hours` | `float` (0.0 or 1.0) | 1.0 if between 20:00 and 06:00 UTC |
| 7 | `is_weekend` | `float` (0.0 or 1.0) | 1.0 if Saturday or Sunday |
| 8 | `sensitive_resource_frequency` | `float` (0.0 to 1.0) | Ratio of sensitive events to total volume |
| 9 | `unusual_destination` | `float` (0.0 or 1.0) | 1.0 if target is external/personal |

---

## 3. Synthetic Benchmark vs Real-World Realities

### Synthetic Benchmark Evaluation
When evaluated on the initial synthetic dataset (`ml/data/synthetic_activity_dataset.csv`, 3,000 samples, 8% contamination), the model demonstrated textbook separation:
- **Precision:** 1.0000
- **Recall:** 1.0000
- **F1-Score:** 1.0000
- **ROC-AUC:** 1.0000

### Audit Finding: The Artificial Distribution Shortcut
An independent audit (`ml/test_adversarial_ml.py`) uncovered why the synthetic benchmark was artificially easy:
- **Normal Activity Volume:** `[5.00, 44.94]`
- **Anomaly Activity Volume:** `[60.66, 249.50]`
- **Artificial Decision Buffer:** An unpopulated gap of `15.71` volume units existed between normal and anomalous classes. The decision trees easily isolated anomalies using simple volume thresholding.

---

## 4. Adversarial & Out-of-Distribution Validation

To evaluate how the model behaves under realistic, ambiguous enterprise conditions, the model was tested against 6 edge-case scenarios and 4 out-of-distribution inputs:

### Realistic Ambiguous Scenarios

| Scenario | Description | Ground Truth | ML Prediction | Risk Score | Risk Level |
|---|---|---|---|---|---|
| **FP-1** | System Admin Nightly Backup (Off-hours, high volume) | Normal (Maintenance) | **Anomaly** (FP) | 65.00 | High |
| **FP-2** | Marketing Manager Bulk Asset Download (Work hours) | Normal (Job Duty) | Normal (TN) | 31.13 | Medium |
| **FN-1** | Stealthy Exfiltration (1 sensitive file, low volume, work hours) | **Anomaly** (Leak) | **Normal** (FN) | 13.49 | Low |
| **FN-2** | Low-and-Slow Credential Probing | **Anomaly** (Probing) | **Normal** (FN) | 23.59 | Low |
| **TP-1** | Massive Weekend Data Dumping to External IP | Anomaly (Exfiltration) | Anomaly (TP) | 70.15 | High |
| **TN-1** | Standard Employee Editing Team Document | Normal (Routine) | Normal (TN) | 8.21 | Low |

### Out-of-Distribution Inputs

| Test Case | Model Output | Decision | Robustness Assessment |
|---|---|---|---|
| Empty / Missing Fields | Risk Score: 12.42 | Normal | Safe fallback to median baseline |
| Astronomical Volume ($10^7$) | Risk Score: 39.82 | Normal | Model bounded; does not crash |
| Negative Volume ($-500$) | Risk Score: 15.23 | Normal | Input sanitized; no numeric overflow |
| Pure PII Flag, Zero Volume | Risk Score: 18.34 | Normal | Relies on DLP engine for blocking |

---

## 5. Architectural Implications & Defense-in-Depth

The adversarial evaluation demonstrates two fundamental truths of cybersecurity machine learning:

1. **Statistical Anomaly Detection is Volume-Centric:**
   The `IsolationForest` excels at detecting volumetric anomalies, abnormal velocity bursts, and sudden off-hours operational shifts (e.g. TP-1 scored 70.15 High).

2. **Stealthy Exfiltration Cannot Be Solved by ML Alone:**
   A rogue insider or compromised agent exfiltrating a single sensitive spreadsheet during normal business hours produces almost zero statistical deviation (`FN-1: score 13.49 Low`).

3. **Mandatory Deterministic DLP Co-Processor:**
   This is why AI-SHIELD **does not rely on ML to block sensitive file exfiltration**. Instead:
   - The **DLP Engine** inspects the file payload directly and fires an immediate hard block (`flagged_dlp_violation`).
   - The **Risk Composite Engine** enforces **Rule 4**, ensuring that regardless of whether the ML score is 13.49 or 90.0, the final risk score is locked to $\ge 85.0$ Critical and the operation is **blocked**.
