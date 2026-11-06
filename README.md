# AI-SHIELD — Unified AI Security & Data Protection Platform

[![Backend Test Suite](https://img.shields.io/badge/Backend%20Tests-70%2F70%20Passing-brightgreen)](file:///docs/FINAL_TEST_RESULTS.md)
[![TypeScript / Vite Build](https://img.shields.io/badge/Frontend%20Build-Passing-brightgreen)](file:///frontend)
[![Multi-Tenant Architecture](https://img.shields.io/badge/Multi--Tenant-Isolated-blue)](file:///docs/SECURITY_DESIGN.md)
[![Database Persistence](https://img.shields.io/badge/Persistence-Supabase%20%2B%20SQLite%20Failover-blueviolet)](file:///docs/DATABASE_DESIGN.md)

**AI-SHIELD** is an enterprise-grade AI security monitoring, agent governance, and Data Loss Prevention (DLP) platform engineered specifically for Small and Medium Enterprises (SMEs). It delivers comprehensive visibility, deterministic policy enforcement, machine learning anomaly detection, multi-tenant organization isolation, and explainable incident response.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |     React 19 Security Operations UI   |
                      |   (Vite, TailwindCSS, Lucide, Charts)  |
                      +-------------------+-------------------+
                                          | REST API / JWT
                                          v
                      +---------------------------------------+
                      |    Flask Enterprise API Gateway       |
                      |   (Tenant Isolation, RBAC, Rate-Limit)|
                      +-------------------+-------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+----------------+               +-----------------+               +----------------+
|  Agent Guard   |               |   DLP Engine    |               |  ML Anomaly    |
| Atomic Counter |               | PII / Secrets   |               | IsolationForest|
| ACL Enforcer   |               | Quarantine Isol |               | Risk Scorer    |
+-------+--------+               +--------+--------+               +--------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Unified Data Repository Layer     |
                      | (Multi-Tenant, Atomic Concurrency)    |
                      +-------------------+-------------------+
                                          |
                +-------------------------+-------------------------+
                | Primary                                           | Failover / Resilient
                v                                                   v
+-------------------------------+                   +-------------------------------+
|    Supabase PostgreSQL RLS    |                   |  Local SQLite Persistent DB   |
|   (Cloud Multi-Tenant DB)     |                   | (PRAGMA WAL, Atomic Trx)      |
+-------------------------------+                   +-------------------------------+
```

---

## Core Capabilities

1. **AI Agent Guard:**
   - Identity registry and least-privilege matrix per agent (`allowed_resources`, `allowed_actions`, `allowed_destinations`).
   - Atomic database-level concurrency counter (`UPDATE ai_agents SET violation_count = violation_count + 1...`).
   - Automatic perimeter isolation upon 3 violations.
   - Mandatory non-empty administrative justification required for agent reactivation.

2. **Data Loss Prevention (DLP):**
   - Deterministic regex and checksum scanning for PII (PAN, Aadhaar, phone numbers, emails) and secrets (AWS keys, OpenAI keys, private keys, passwords).
   - Autonomous file quarantining into an isolated directory with SHA-256 integrity verification.

3. **Machine Learning Anomaly Detection:**
   - Trained Scikit-Learn `IsolationForest` model for behavioral anomaly detection.
   - Preserves deterministic hard security denials (Contract Rule 4: ML never overrides explicit policy violations).
   - Documented empirical boundaries and limitations against stealthy exfiltration.

4. **Multi-Tenant Isolation:**
   - Strict `organization_id` partitioning across all 10 schema entities.
   - Server-enforced tenant boundaries derived from cryptographically verified JWT tokens.
   - Cross-organization access attempts return HTTP 404/403.

5. **API Threat Detection & Rate Limiting:**
   - Sliding-window IP rate limiter and brute-force mitigation middleware.
   - Client IP sanitization preventing `X-Forwarded-For` header spoofing.

6. **Unified Dual-Mode Persistence:**
   - Supabase PostgreSQL primary storage with full migration schemas (`003_multi_tenant_production_schema.sql`).
   - High-performance local SQLite fallback ensuring 100% operational survival during network or database outages.

---

## Quick Start & Run Commands

### 1. Prerequisites
- **Python:** 3.10+ (Tested on Python 3.14.3)
- **Node.js:** 18+ (Tested on Node 24.20.0 with npm 11.x)
- **Virtual Environment:** Recommended

### 2. Backend Initialization

```bash
# Navigate to project root
cd "c:\Users\tejaj\OneDrive\Documents\ChatGPT\Open Quest"

# Install backend dependencies
pip install -r backend/requirements.txt

# Bootstrap production administrator account
python backend/cli.py init-admin --username admin --email admin@aishield.local --password "ProductionSecurePass2026!" --org-id org_default

# Verify database connectivity and schema consistency
python backend/cli.py check-db

# Launch Flask API Server (Port 5000)
python backend/app.py
```

### 3. Frontend Dashboard Initialization

```bash
# In a separate terminal, navigate to frontend
cd frontend

# Install Node dependencies
npm.cmd install

# Compile TypeScript and build production bundle
npm.cmd run build

# Start development dashboard server (Port 5173)
npm.cmd run dev
```

---

## Test Verification

Run all regression and production readiness test suites:

```bash
# Run complete backend test suite (70 tests)
pytest backend/tests

# Run adversarial ML evaluation
python ml/test_adversarial_ml.py

# Run frontend production build
cd frontend && npm.cmd run build
```

**Verification Results:**
- **Backend Tests:** 70 passed / 0 failed (100% pass rate)
- **Frontend Build:** 0 errors (Vite production bundle compiled)
- **Adversarial ML:** Empirical evaluation and boundary detection verified

---

## Documentation Directory

| Document | Purpose |
|---|---|
| [Final Production Readiness Report](docs/FINAL_PRODUCTION_READINESS_REPORT.md) | Architectural audit, multi-tenancy verification, and production sign-off |
| [Final Security Verification](docs/FINAL_SECURITY_VERIFICATION.md) | Penetration testing, attack vector defense, and threat analysis |
| [Database Migration Verification](docs/DATABASE_MIGRATION_VERIFICATION.md) | Supabase schema status, SQLite fallback, and migration instructions |
| [Final Test Results](docs/FINAL_TEST_RESULTS.md) | Exhaustive test suite execution metrics and evidence |
| [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | SME deployment instructions, Docker/cloud setup, and secrets management |
| [Security Design](docs/SECURITY_DESIGN.md) | Threat model, RBAC policies, and multi-tenant security architecture |
| [Database Design](docs/DATABASE_DESIGN.md) | Entity relationships, indexes, foreign keys, and RLS policies |
| [API Documentation](docs/API_DOCUMENTATION.md) | Complete OpenAPI/REST endpoint specifications |
| [ML Documentation](docs/ML_DOCUMENTATION.md) | IsolationForest pipeline, feature engineering, and empirical limitations |
| [Implementation Status](docs/IMPLEMENTATION_STATUS.md) | Detailed ledger of implemented, verified, and future roadmap capabilities |
