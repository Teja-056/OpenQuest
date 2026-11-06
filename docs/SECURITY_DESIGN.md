# AI-SHIELD — Security Architecture & Threat Model

## 1. Threat Model & Security Objectives

AI-SHIELD operates as a zero-trust enterprise security layer. The platform assumes that internal actors (employees and autonomous AI agents) may possess valid credentials but attempt actions that violate organizational policy or exceed least-privilege boundaries.

### Threats Mitigated:
1. **Autonomous AI Agent Misconfiguration / Jailbreak:** Agents querying administrative secrets, environment files, or payroll tables.
2. **Data Exfiltration:** Internal confidential files or customer PII transmitted to unauthorized personal storage or external URLs.
3. **Cross-Tenant Data Tampering / Leaks:** Multi-tenant attacks where one organization attempts to access or alter another organization's telemetry, incidents, or employee profiles.
4. **API Abuse & Credential Stuffing:** Automated brute-force attacks against authentication endpoints.
5. **Privilege Escalation:** Non-admin users attempting to reactivate suspended AI agents or modify security policies.
6. **Telemetry Spoofing:** Attackers attempting to spoof source IP headers or submit fabricated organization IDs.

---

## 2. Multi-Tenant Organization Isolation

### Never Trust Frontend-Supplied Tenant Identifiers
The AI-SHIELD backend enforces an ironclad rule: **`organization_id` is never trusted from frontend request bodies or URL parameters for authorization.**

1. **Cryptographic JWT Extraction:**
   When an authenticated request arrives, the middleware verifies the JWT signature and extracts the authorized `organization_id` stored within the token payload:
   ```python
   # backend/auth.py
   def get_tenant_organization_id() -> str:
       auth_header = request.headers.get("Authorization")
       if auth_header and auth_header.startswith("Bearer "):
           payload = verify_token(auth_header.split(" ", 1)[1])
           if payload and payload.get("organization_id"):
               return payload["organization_id"]
       return "org_default"
   ```
2. **Backend Query Partitioning:**
   Every database query filters strictly by the authenticated `organization_id`:
   ```sql
   SELECT * FROM employees WHERE employee_id = ? AND organization_id = ?
   ```
3. **Cross-Tenant 404/403 Responses:**
   If a user from `org_alpha` requests an employee, event, incident, or alert belonging to `org_beta`, the backend returns `404 Not Found`, denying the existence of the foreign tenant's record and preventing tenant enumeration attacks.

---

## 3. Authentication & Secrets Hardening

### Secure Administrator Initialization
In development environments, default accounts are seeded for convenience. In production environments (`ENV=production`), hardcoded default passwords are strictly disabled:

- **Seeding Disabled:** `seed_default_users()` checks `Config.is_production()` and refuses to create default credentials.
- **Dedicated Admin CLI:** Production administrator accounts must be explicitly initialized via the secure CLI command:
  ```bash
  python backend/cli.py init-admin --username secops_admin --email admin@enterprise.com --password "SecureSecretPhrase2026!" --org-id org_corp
  ```
- **Password Security:** Passwords are hashed using salted PBKDF2 with SHA-256 (600,000 iterations). Plaintext passwords are never logged or stored.
- **Constant-Time Comparison:** Password verification uses `hmac.compare_digest` to prevent timing attacks.

### JWT Cryptographic Integrity
- Signed with HMAC-SHA256 using `JWT_SECRET_KEY` (minimum 32 cryptographically random bytes).
- Standard token expiration is enforced (24 hours). Expired or tampered tokens return HTTP 401.

---

## 4. AI Agent Guard Concurrency & Justification

### Atomic Database-Level Concurrency
Process-only locks (such as Python `threading.Lock`) fail when multiple worker processes (Gunicorn/uWSGI) run concurrently.

AI-SHIELD executes an atomic SQL update directly against the database:
```sql
UPDATE ai_agents
SET violation_count = violation_count + 1,
    status = CASE WHEN violation_count + 1 >= 3 THEN 'suspended' ELSE status END,
    last_activity = ?,
    updated_at = ?
WHERE agent_id = ?
```
- Eliminates race conditions across multiple workers.
- Guarantees immediate suspension upon reaching the threshold (`Config.AGENT_VIOLATION_THRESHOLD = 3`).

### Mandatory Non-Empty Reactivation Justification
Suspended agents cannot be silently reactivated by administrators without leaving an auditable paper trail.
- The `AgentGuard.reactivate_agent` API and `PATCH /api/agents/<agent_id>/status` endpoint require a non-empty `reason`:
  ```python
  if not justification or not str(justification).strip():
      return error_response("Reactivating a suspended agent requires a mandatory non-empty administrative justification", 400)
  ```
- Reactivations are logged in `suspension_history` with the admin username, ISO timestamp, and full justification text.

---

## 5. Event Ingestion vs Access Enforcement

In security monitoring systems, telemetry ingestion must be distinguished from authorization enforcement:
- **Telemetry Ingestion:** Always returns HTTP `201 Created` because the telemetry record was successfully captured and audited for digital forensics.
- **Access Enforcement:** The response payload clearly communicates whether the underlying action was permitted or blocked:
  ```json
  {
    "success": true,
    "status_code": 201,
    "message": "Event recorded: Operation BLOCKED by security policy (flagged_unauthorized_agent_access)",
    "meta": {
      "action_permitted": false,
      "enforcement_status": "blocked",
      "alert_id": "ALT-A1B2C3D4",
      "incident_id": "INC-E5F6G7H8",
      "risk_level": "critical",
      "risk_score": 85.0
    }
  }
  ```

---

## 6. Client IP Spoofing & Threat Detection

To prevent attackers from bypassing the rate limiter by forging `X-Forwarded-For` HTTP headers:
- `backend/middleware/threat_detector.py` validates the client IP address.
- Comma-separated `X-Forwarded-For` chains are parsed safely, extracting only the outermost untrusted proxy client IP while stripping whitespace and invalid characters.
- Sliding-window rate limiting tracks IP request frequencies, blocking burst attacks (&gt; 120 req/min) with HTTP 429.

---

## 7. Attack Vector Defense Matrix

| Attack Vector | Defense Mechanism | Test Verification |
|---|---|---|
| **SQL Injection** | Strict parameterized SQLite / Supabase query builders; regex sanitization of query parameters | `test_sql_injection_defense` (Pass) |
| **Path Traversal** | Quarantine module verifies canonical paths with `os.path.commonpath`; rejects `../` and `%2e%2e` | `test_path_traversal_defense` (Pass) |
| **Cross-Site Scripting (XSS)** | Input sanitization rejects `<script>`, `javascript:`, and HTML injection | `test_xss_input_sanitization` (Pass) |
| **Cross-Tenant Access** | Tenant ID bound to server JWT claims; all database queries partitioned | `test_multi_tenant_employee_isolation` (Pass) |
| **Concurrent Race Conditions** | Atomic database-level SQL updates on violation counters | `test_atomic_agent_violation_concurrency` (Pass) |
| **Brute Force / DoS** | Sliding-window IP rate limiter returning HTTP 429 | `test_rate_limiter_burst_protection` (Pass) |
| **Rule 4 Overwrite** | ML anomaly score composite calculator enforces hard denials | `test_rule_4_hard_denial_preservation` (Pass) |
