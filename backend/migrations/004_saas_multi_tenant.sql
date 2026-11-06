-- =============================================================================
-- AI Shield Platform — SaaS Multi-Tenant & Cloud/Endpoint Integration Schema
-- Migration: 004_saas_multi_tenant.sql
-- Description: Extends schema for multi-tenant company onboarding, AWS cloud
--              connections, Wazuh endpoint integrations, subscription tiers,
--              and audit logging with PostgreSQL Row Level Security (RLS).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. EXTEND ORGANIZATIONS FOR SAAS ONBOARDING
-- -----------------------------------------------------------------------------
ALTER TABLE public.organizations 
    ADD COLUMN IF NOT EXISTS owner_name TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS phone TEXT,
    ADD COLUMN IF NOT EXISTS industry TEXT DEFAULT 'Technology',
    ADD COLUMN IF NOT EXISTS country TEXT DEFAULT 'United States',
    ADD COLUMN IF NOT EXISTS employee_count INTEGER DEFAULT 10,
    ADD COLUMN IF NOT EXISTS subscription_tier TEXT NOT NULL DEFAULT 'STARTER' 
        CHECK (subscription_tier IN ('STARTER', 'PROFESSIONAL', 'ENTERPRISE')),
    ADD COLUMN IF NOT EXISTS cloud_provider TEXT DEFAULT 'AWS',
    ADD COLUMN IF NOT EXISTS cloud_status TEXT NOT NULL DEFAULT 'UNCONFIGURED'
        CHECK (cloud_status IN ('UNCONFIGURED', 'CONNECTING', 'CONNECTED', 'ERROR')),
    ADD COLUMN IF NOT EXISTS wazuh_status TEXT NOT NULL DEFAULT 'UNCONFIGURED'
        CHECK (wazuh_status IN ('UNCONFIGURED', 'LISTENING', 'ACTIVE', 'ERROR')),
    ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS onboarding_step INTEGER NOT NULL DEFAULT 1;

-- -----------------------------------------------------------------------------
-- 2. CLOUD INTEGRATIONS TABLE (AWS STS ASSUMEROLE)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cloud_integrations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    integration_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    provider TEXT NOT NULL DEFAULT 'AWS' CHECK (provider IN ('AWS', 'GCP', 'AZURE')),
    account_id TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    external_id TEXT NOT NULL,
    regions TEXT NOT NULL DEFAULT '["us-east-1"]',
    status TEXT NOT NULL DEFAULT 'UNCONFIGURED' 
        CHECK (status IN ('UNCONFIGURED', 'PENDING', 'CONNECTED', 'ERROR')),
    last_tested_at TIMESTAMPTZ,
    last_sync_at TIMESTAMPTZ,
    findings_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    config_details TEXT DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cloud_org_provider UNIQUE (organization_id, provider)
);

-- -----------------------------------------------------------------------------
-- 3. WAZUH INTEGRATIONS TABLE (WEBHOOK & AGENTS)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.wazuh_integrations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    integration_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    webhook_secret TEXT NOT NULL,
    manager_url TEXT,
    status TEXT NOT NULL DEFAULT 'UNCONFIGURED'
        CHECK (status IN ('UNCONFIGURED', 'LISTENING', 'ACTIVE', 'ERROR')),
    agent_count INTEGER NOT NULL DEFAULT 0,
    last_alert_at TIMESTAMPTZ,
    error_message TEXT,
    api_config TEXT DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_wazuh_org UNIQUE (organization_id)
);

-- -----------------------------------------------------------------------------
-- 4. SUBSCRIPTIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id TEXT UNIQUE NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    tier TEXT NOT NULL DEFAULT 'STARTER' CHECK (tier IN ('STARTER', 'PROFESSIONAL', 'ENTERPRISE')),
    max_endpoints INTEGER NOT NULL DEFAULT 5,
    max_cloud_accounts INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    current_endpoints_count INTEGER NOT NULL DEFAULT 0,
    current_cloud_accounts_count INTEGER NOT NULL DEFAULT 0,
    features TEXT NOT NULL DEFAULT '["basic_monitoring", "incident_management"]',
    billing_period TEXT NOT NULL DEFAULT 'monthly',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed initial subscription for default organization
INSERT INTO public.subscriptions (organization_id, tier, max_endpoints, max_cloud_accounts, is_active)
VALUES ('org_default', 'ENTERPRISE', 1000, 50, TRUE)
ON CONFLICT (organization_id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 5. AUDIT LOGS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_id TEXT UNIQUE NOT NULL,
    organization_id TEXT NOT NULL REFERENCES public.organizations(organization_id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    actor_email TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. INDEXES & RLS POLICIES FOR SAAS EXTENSIONS
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cloud_org ON public.cloud_integrations(organization_id);
CREATE INDEX IF NOT EXISTS idx_wazuh_org ON public.wazuh_integrations(organization_id);
CREATE INDEX IF NOT EXISTS idx_subs_org ON public.subscriptions(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_org ON public.audit_logs(organization_id);

ALTER TABLE public.cloud_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.wazuh_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY cloud_integrations_tenant_isolation ON public.cloud_integrations
    FOR ALL
    USING (organization_id = NULLIF(current_setting('app.current_tenant', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant', true), ''));

CREATE POLICY wazuh_integrations_tenant_isolation ON public.wazuh_integrations
    FOR ALL
    USING (organization_id = NULLIF(current_setting('app.current_tenant', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant', true), ''));

CREATE POLICY subscriptions_tenant_isolation ON public.subscriptions
    FOR ALL
    USING (organization_id = NULLIF(current_setting('app.current_tenant', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant', true), ''));

CREATE POLICY audit_logs_tenant_isolation ON public.audit_logs
    FOR ALL
    USING (organization_id = NULLIF(current_setting('app.current_tenant', true), ''))
    WITH CHECK (organization_id = NULLIF(current_setting('app.current_tenant', true), ''));
