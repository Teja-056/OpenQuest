# AI-SHIELD — User Guide & Operator Manual

## 1. Introduction

Welcome to AI-SHIELD, a unified security monitoring and data loss prevention platform built for small-to-medium enterprises.

AI-SHIELD enables security analysts and administrators to monitor AI agents, audit employee data transfers, intercept sensitive exfiltrations, and review machine learning anomaly indicators.

---

## 2. Navigating the Security Operations Dashboard

The dashboard consists of 10 unified operational modules:

### 1. Overview
- **Threat Posture:** Review total ingested events, open incidents, critical violations, and active vs suspended AI agents.
- **Risk Distribution Chart:** Donut chart displaying Low, Medium, High, and Critical proportions.
- **Risk Severity Progression:** Historical trend line showing event severity over time.
- **Recent Telemetry:** Live table of the newest events ingested into PostgreSQL.

### 2. Incidents
- **Triage & Filter:** Search by incident ID or actor, and filter by severity (`critical`, `high`, `medium`, `low`) and status (`open`, `investigating`, `resolved`, `false_positive`).
- **Investigate Drawer:** Click &ldquo;Investigate&rdquo; on any incident to read the **8-Part Deterministic Explanation** (What happened, Who performed it, What resource, Why suspicious, Rule triggered, ML prediction, Risk score, and Recommended Remediation).
- **Remediation Actions:** Transition status between Open, Investigating, Resolved, and False Positive, or assign a designated analyst.

### 3. Activity Monitoring
- Continuous telemetry stream of all recorded actions (`file_access`, `file_share`, `file_download`, `authentication`, `api_request`, `data_export`).
- Filter by actor type (`employee`, `agent`, `external`).
- Click &ldquo;Emit Test Event&rdquo; to simulate live traffic in real-time.

### 4. Files & Sharing
- Dedicated tracking of document movement.
- Flags external destinations in red with alert badges.
- Displays sensitivity badges (`CONFIDENTIAL`, `RESTRICTED`, `INTERNAL`).

### 5. API Monitor
- Sliding-window rate limit monitor (30 requests/minute burst threshold).
- Displays active temporary IP blockouts with countdown timers.
- Logs brute-force login attempts and endpoint abuse.

### 6. DLP Violations
- Audits intercepted data exfiltration attempts.
- **Interactive DLP Scanner Sandbox:** Paste any text, JSON, or code snippet to test detection of Indian PAN, Aadhaar, Credit Cards (Luhn verified), API Keys, and Passwords.

### 7. Risk & Recommendations
- Explains composite risk calculation and **Rule 4 Preservation**.
- **Interactive Risk Sandbox:** Test how varying ML anomaly scores interact with hard security denials.
- Review actionable remediation procedures for each incident type.

### 8. AI Agent Management
- Registry of autonomous AI agents (`agent_id`, `name`, `owner`, `permissions`, `allowed_resources`, `allowed_actions`).
- Displays violation counters (e.g. `1 / 3 threshold`).
- Automatic suspension upon reaching 3 violations.
- One-click &ldquo;Suspend Agent&rdquo; or &ldquo;Reactivate Agent&rdquo; buttons.
- View detailed violation audit histories.

### 9. Security Policies
- Review active enterprise security policies and enforceable JSON rules.

### 10. System Settings
- Live health check of Flask API service and Supabase PostgreSQL connection.
- Machine Learning model status (Isolation Forest, 150 estimators, ROC-AUC 1.0000).
- Telemetry streamer buttons (Emit 1 event or 3 events burst).

---

## 3. Demonstration Credentials

Default development and demonstration user accounts:

| Role | Username | Password |
|---|---|---|
| **Organization Admin** | `admin` | `Admin@AIShield2026!` |
| **Security Analyst** | `analyst` | `Analyst@AIShield2026!` |
| **Super Admin** | `superadmin` | `SuperAdmin@AIShield2026!` |

Click &ldquo;Sign In&rdquo; in the top-right corner of the dashboard to log in with these credentials.
