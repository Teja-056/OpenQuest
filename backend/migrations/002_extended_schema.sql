-- =============================================================================
-- AI Shield Platform — Supabase PostgreSQL Schema Migration 002
-- Migration: 002_extended_schema.sql
-- Description: Extends schema with AI Agent registry, agent permissions & violations,
--              DLP policies & violations, API threat logs, ML model versioning,
--              and users / RBAC authentication.
-- =============================================================================

-- 1. USERS & RBAC TABLE
CREATE TABLE IF NOT EXISTS public.users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'SECURITY_ANALYST' 
        CHECK (role IN ('SUPER_ADMIN', 'ORGANIZATION_ADMIN', 'SECURITY_ANALYST', 'EMPLOYEE')),
    organization_id TEXT NOT NULL DEFAULT 'org_default',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deactivated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. AI AGENTS TABLE
CREATE TABLE IF NOT EXISTS public.ai_agents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'under_investigation', 'revoked')),
    assigned_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_destinations JSONB NOT NULL DEFAULT '[]'::jsonb,
    violation_count INT NOT NULL DEFAULT 0,
    suspension_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_activity TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. AGENT VIOLATIONS AUDIT TABLE
CREATE TABLE IF NOT EXISTS public.agent_violations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    violation_id TEXT UNIQUE NOT NULL,
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

-- 4. SECURITY & DLP POLICIES TABLE
CREATE TABLE IF NOT EXISTS public.security_policies (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id TEXT UNIQUE NOT NULL,
    policy_name TEXT NOT NULL,
    policy_type TEXT NOT NULL CHECK (policy_type IN ('DLP', 'AGENT_ACCESS', 'API_RATE_LIMIT', 'DATA_CLASSIFICATION')),
    description TEXT,
    rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    severity TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. DLP VIOLATIONS & QUARANTINE TABLE
CREATE TABLE IF NOT EXISTS public.dlp_violations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    violation_id TEXT UNIQUE NOT NULL,
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

-- 6. API THREAT LOGS TABLE
CREATE TABLE IF NOT EXISTS public.api_threat_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_id TEXT UNIQUE NOT NULL,
    client_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    threat_type TEXT NOT NULL CHECK (threat_type IN ('rate_limit_exceeded', 'brute_force', 'suspicious_client', 'abnormal_burst', 'unauthorized_access')),
    threat_score NUMERIC(5,2) NOT NULL DEFAULT 50.00,
    request_count INT DEFAULT 1,
    details TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. MODEL VERSIONS TABLE
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
-- PERFORMANCE & QUERY INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);

CREATE INDEX IF NOT EXISTS idx_ai_agents_agent_id ON public.ai_agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_status ON public.ai_agents(status);

CREATE INDEX IF NOT EXISTS idx_agent_violations_agent_id ON public.agent_violations(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_violations_timestamp ON public.agent_violations(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_policies_type ON public.security_policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_security_policies_active ON public.security_policies(is_active);

CREATE INDEX IF NOT EXISTS idx_dlp_violations_actor ON public.dlp_violations(actor_id);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_timestamp ON public.dlp_violations(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_api_threat_logs_ip ON public.api_threat_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_api_threat_logs_timestamp ON public.api_threat_logs(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_model_versions_active ON public.model_versions(is_active);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_threat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.model_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on users" ON public.users
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on ai_agents" ON public.ai_agents
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on agent_violations" ON public.agent_violations
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on security_policies" ON public.security_policies
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on dlp_violations" ON public.dlp_violations
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on api_threat_logs" ON public.api_threat_logs
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on model_versions" ON public.model_versions
    FOR ALL TO service_role USING (true) WITH CHECK (true);
