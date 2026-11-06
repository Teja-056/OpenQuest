# AI-SHIELD — API Documentation

## 1. Overview & Standard Conventions

AI-SHIELD provides a RESTful HTTP/JSON API. All endpoints enforce multi-tenant isolation, cryptographic JWT authentication (where required), parameterized input validation, and standardized JSON envelopes.

### Standard Success Envelope
```json
{
  "success": true,
  "status_code": 200,
  "message": "Human readable status message",
  "data": { ... },
  "meta": {
    "total": 100,
    "limit": 50,
    "offset": 0,
    "returned": 50
  }
}
```

### Standard Error Envelope
```json
{
  "success": false,
  "status_code": 400,
  "error": "Descriptive error message",
  "details": { ... }
}
```

---

## 2. System & Health Check Endpoints

### `GET /api/health`
Inspects backend server operation, database persistence status, and multi-tenant operational mode.
- **Authentication:** None required.
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "status_code": 200,
    "message": "System and Supabase database are operational",
    "data": {
      "status": "healthy",
      "database": "connected",
      "database_type": "supabase_postgresql",
      "persistence_mode": "dual",
      "active_backend": "supabase",
      "multi_tenant_enabled": true,
      "service": "AI Shield Backend API",
      "version": "1.0.0",
      "python_version": "3.14.3",
      "timestamp": "2026-11-06T01:30:00Z"
    }
  }
  ```
- **Failover Response (503 Service Unavailable):**
  Returned if strict Supabase persistence mode is enforced but remote connectivity fails.

---

## 3. Authentication & Account Management

### `POST /api/auth/login`
Authenticate an administrator or security analyst.
- **Request Body:**
  ```json
  {
    "username": "admin",
    "password": "ProductionSecurePass2026!"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "status_code": 200,
    "message": "Authentication successful",
    "data": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "user": {
        "user_id": "USR-ADMIN-01",
        "username": "admin",
        "role": "ORGANIZATION_ADMIN",
        "organization_id": "org_default"
      }
    }
  }
  ```

### `GET /api/auth/me`
Return the authenticated user's profile and active organization context.
- **Headers:** `Authorization: Bearer <token>`
- **Response (200 OK):** Current user object.

---

## 4. Security Events & Telemetry Ingestion

### `POST /api/events`
Ingest security events from employees, autonomous agents, or third-party cloud integrations.
- **Telemetry Ingestion vs Access Enforcement:**
  Always returns HTTP `201 Created` upon successful logging. The response envelope explicitly distinguishes whether the requested action was permitted or blocked.
- **Request Body:**
  ```json
  {
    "event_id": "EVT-2026-001",
    "event_type": "file_share",
    "actor_type": "employee",
    "actor_id": "EMP002",
    "resource": "payroll_q3.xlsx",
    "is_sensitive": true,
    "action": "share",
    "destination": "external_personal@gmail.com",
    "source": "employee_simulator",
    "description": "Attempted file transfer of sensitive customer list to external personal email"
  }
  ```
- **Response (201 Created - Operation Blocked):**
  ```json
  {
    "success": true,
    "status_code": 201,
    "message": "Event recorded: Operation BLOCKED by security policy (flagged_dlp_external_share)",
    "data": {
      "event_id": "EVT-2026-001",
      "rule_result": "flagged_dlp_external_share",
      "anomaly": true,
      "risk_score": 85.0,
      "risk_level": "critical",
      "recommended_action": "quarantine_attachment_and_notify_manager",
      "action_permitted": false
    },
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

### `GET /api/events`
List security events partitioned by tenant organization.
- **Query Parameters:** `limit` (max 200), `offset`, `event_type`, `actor_type`, `actor_id`, `risk_level`, `is_sensitive`.
- **Response (200 OK):** Array of event objects with pagination metadata.

### `GET /api/events/<event_id>`
Retrieve a single event by ID.
- **Multi-Tenant Protection:** Returns 404 if event belongs to another tenant.

---

## 5. Employee Directory

### `GET /api/employees`
List employees partitioned by caller's organization.
- **Query Parameters:** `department`, `status`, `limit`, `offset`.

### `POST /api/employees`
Register an employee profile into caller's organization.
- **Conflict Handling:** Returns HTTP 409 if `employee_id` or `email` already exists in organization.

### `PATCH /api/employees/<employee_id>`
Update employee details (`name`, `department`, `role`, `status`, `risk_score`).

### `DELETE /api/employees/<employee_id>`
Remove an employee record from the organization directory.

---

## 6. AI Agent Guard API

### `GET /api/agents`
List registered AI agents, permission sets, allowed resources, and current violation counts.

### `POST /api/agents`
Register an autonomous AI agent into the least-privilege matrix.
- **Body:**
  ```json
  {
    "agent_id": "agent_crawler_02",
    "name": "Knowledgebase Crawler",
    "owner": "Search Engineering",
    "assigned_permissions": ["search:read"],
    "allowed_resources": ["/api/v1/kb", "public_faq.json"],
    "allowed_actions": ["read", "search"],
    "allowed_destinations": ["internal"]
  }
  ```

### `PATCH /api/agents/<agent_id>/status`
Admin endpoint to activate, suspend, or reactivate an AI agent.
- **Mandatory Justification Rule:**
  Reactivating a suspended agent (`status: "active"`) requires a non-empty administrative `reason`.
- **Request Body:**
  ```json
  {
    "status": "active",
    "reason": "Security review completed and model boundaries updated to exclude admin credentials"
  }
  ```
- **Error Response (400 Bad Request):** If `reason` is empty or whitespace.

---

## 7. Incidents & Alerts Management

### `GET /api/incidents`
List security incidents with filtering by `severity` and `status`.

### `PATCH /api/incidents/<incident_id>`
Update incident status (`investigating`, `resolved`, `closed`), assign investigation lead, or append resolution notes.

### `GET /api/alerts`
List security alerts with filtering by `severity` and `is_read`.

### `PATCH /api/alerts/<alert_id>`
Acknowledge alert (`{ "is_read": true }`).

---

## 8. Data Loss Prevention (DLP) API

### `GET /api/dlp/violations`
Retrieve audit history of sensitive data leak attempts and quarantine status.

### `POST /api/dlp/inspect`
Inspect file or payload text for PII/credentials without persisting.

---

## 9. Dashboard Analytics

### `GET /api/dashboard/stats`
Aggregated tenant statistics: total events, open incidents, critical violations, active/suspended agents, DLP violation count, and risk breakdown.
