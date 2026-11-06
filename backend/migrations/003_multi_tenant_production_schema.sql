-- =============================================================================
-- AI Shield Platform — Production Multi-Tenant Schema Migration
-- Migration: 003_multi_tenant_production_schema.sql
-- Description: Unifies all 10 core tables with strict organization-level isolation
--              (organization_id), primary/foreign keys, check constraints,
--              performance indexes, and Row Level Security (RLS) policies.
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- 1. ORGANIZATIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.organizations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'enterprise' CHECK (plan IN ('starter', 'professional', 'enterprise')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed baseline default organization
INSERT INTO public.organizations (organization_id, name, plan)
VALUES ('org_default', 'Default SME Enterprise', 'enterprise')
ON CONFLICT (organization_id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 2. USERS & RBAC TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'SECURITY_ANALYST' 
        CHECK (role IN ('SUPER_ADMIN', 'ORGANIZATION_ADMIN', 'SECURITY_ANALYST', 'EMPLOYEE')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deactivated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. EMPLOYEES TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.employees (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    risk_score NUMERIC(5,2) DEFAULT 0.00 CHECK (risk_score >= 0.00 AND risk_score <= 100.00),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'under_investigation', 'terminated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_employee_org_email UNIQUE (organization_id, email)
);

-- -----------------------------------------------------------------------------
-- 4. SECURITY EVENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('employee', 'agent', 'external')),
    actor_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    action TEXT NOT NULL,
    destination TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source TEXT NOT NULL,
    description TEXT,
    rule_result TEXT,
    anomaly BOOLEAN,
    risk_score NUMERIC(5,2) CHECK (risk_score IS NULL OR (risk_score >= 0.00 AND risk_score <= 100.00)),
    risk_level TEXT CHECK (risk_level IS NULL OR risk_level IN ('low', 'medium', 'high', 'critical')),
    recommended_action TEXT,
    action_permitted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 5. SECURITY INCIDENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_incidents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed', 'false_positive')),
    actor_id TEXT,
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE SET NULL,
    assigned_to TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. ALERTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE CASCADE,
    incident_id TEXT REFERENCES public.security_incidents(incident_id) ON DELETE SET NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 7. AI AGENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.ai_agents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    name TEXT NOT NULL,
    description TEXT,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'under_investigation', 'revoked')),
    assigned_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_destinations JSONB NOT NULL DEFAULT '[]'::jsonb,
    violation_count INT NOT NULL DEFAULT 0 CHECK (violation_count >= 0),
    suspension_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_activity TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 8. AGENT VIOLATIONS AUDIT TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.agent_violations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    violation_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    agent_id TEXT NOT NULL REFERENCES public.ai_agents(agent_id) ON DELETE CASCADE,
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE SET NULL,
    violation_type TEXT NOT NULL,
    action_attempted TEXT,
    resource_attempted TEXT,
    destination_attempted TEXT,
    details TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 9. SECURITY & DLP POLICIES TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.security_policies (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    policy_name TEXT NOT NULL,
    policy_type TEXT NOT NULL CHECK (policy_type IN ('DLP', 'AGENT_ACCESS', 'API_RATE_LIMIT', 'DATA_CLASSIFICATION')),
    description TEXT,
    rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    severity TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 10. DLP VIOLATIONS & QUARANTINE TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.dlp_violations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    violation_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE SET NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    resource TEXT NOT NULL,
    destination TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    detected_patterns JSONB NOT NULL DEFAULT '[]'::jsonb,
    quarantine_path TEXT,
    status TEXT NOT NULL DEFAULT 'flagged' CHECK (status IN ('flagged', 'quarantined', 'released', 'blocked')),
    action_taken TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 11. API THREAT LOGS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_threat_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE DEFAULT 'org_default',
    client_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    threat_type TEXT NOT NULL CHECK (threat_type IN ('rate_limit_exceeded', 'brute_force', 'suspicious_client', 'abnormal_burst', 'unauthorized_access')),
    threat_score NUMERIC(5,2) NOT NULL DEFAULT 50.00 CHECK (threat_score >= 0.00 AND threat_score <= 100.00),
    request_count INT DEFAULT 1,
    details TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 12. MODEL VERSIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.model_versions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id TEXT UNIQUE NOT NULL,
    model_name TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'IsolationForest',
    training_samples INT NOT NULL,
    precision NUMERIC(5,4),
    recall NUMERIC(5,4),
    f1_score NUMERIC(5,4),
    roc_auc NUMERIC(5,4),
    artifact_path TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    features JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PERFORMANCE & MULTI-TENANT QUERY INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_users_org ON public.users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users(username);

CREATE INDEX IF NOT EXISTS idx_employees_org ON public.employees(organization_id);
CREATE INDEX IF NOT EXISTS idx_employees_emp_id ON public.employees(employee_id);
CREATE INDEX IF NOT EXISTS idx_employees_dept ON public.employees(department);

CREATE INDEX IF NOT EXISTS idx_events_org ON public.security_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_events_actor ON public.security_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON public.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON public.security_events(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_org ON public.security_incidents(organization_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON public.security_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_alerts_org ON public.alerts(organization_id);
CREATE INDEX IF NOT EXISTS idx_alerts_read ON public.alerts(is_read);

CREATE INDEX IF NOT EXISTS idx_ai_agents_org ON public.ai_agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_status ON public.ai_agents(status);

CREATE INDEX IF NOT EXISTS idx_agent_violations_org ON public.agent_violations(organization_id);
CREATE INDEX IF NOT EXISTS idx_agent_violations_agent ON public.agent_violations(agent_id);

CREATE INDEX IF NOT EXISTS idx_dlp_violations_org ON public.dlp_violations(organization_id);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_actor ON public.dlp_violations(actor_id);

CREATE INDEX IF NOT EXISTS idx_threat_logs_org ON public.api_threat_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_threat_logs_ip ON public.api_threat_logs(client_ip);

-- =============================================================================
-- MULTI-TENANT ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_threat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.model_versions ENABLE ROW LEVEL SECURITY;

-- 1. Service Role Policies (Full Backend Access)
CREATE POLICY "service_role_orgs" ON public.organizations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_users" ON public.users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_employees" ON public.employees FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_events" ON public.security_events FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_incidents" ON public.security_incidents FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_alerts" ON public.alerts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_agents" ON public.ai_agents FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_agent_vios" ON public.agent_violations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_policies" ON public.security_policies FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_dlp_vios" ON public.dlp_violations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_threat_logs" ON public.api_threat_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_models" ON public.model_versions FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 2. Authenticated End-User Multi-Tenant Isolation Policies
-- (Enforces that a user JWT claiming app_metadata->>'organization_id' can ONLY read/write their organization's data)
CREATE POLICY "tenant_isolation_employees" ON public.employees
    FOR ALL TO authenticated
    USING (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'))
    WITH CHECK (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'));

CREATE POLICY "tenant_isolation_events" ON public.security_events
    FOR ALL TO authenticated
    USING (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'))
    WITH CHECK (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'));

CREATE POLICY "tenant_isolation_incidents" ON public.security_incidents
    FOR ALL TO authenticated
    USING (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'))
    WITH CHECK (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'));

CREATE POLICY "tenant_isolation_alerts" ON public.alerts
    FOR ALL TO authenticated
    USING (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'))
    WITH CHECK (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'));

CREATE POLICY "tenant_isolation_agents" ON public.ai_agents
    FOR ALL TO authenticated
    USING (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'))
    WITH CHECK (organization_id = (auth.jwt() -> 'app_metadata' ->> 'organization_id'));
