export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  id?: number;
  event_id: string;
  event_type: string;
  actor_type: 'employee' | 'agent' | 'external';
  actor_id: string;
  resource: string;
  is_sensitive: boolean;
  action: string;
  destination?: string;
  timestamp: string;
  source: string;
  description?: string;
  rule_result?: string;
  anomaly?: boolean;
  risk_score?: number;
  risk_level?: Severity;
  recommended_action?: string;
  created_at?: string;
}

export interface SecurityIncident {
  id?: number;
  incident_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive' | 'closed';
  actor_id?: string;
  event_id?: string;
  assigned_to?: string | null;
  resolved_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityAlert {
  id?: number;
  alert_id: string;
  event_id?: string;
  incident_id?: string;
  alert_type: string;
  severity: Severity;
  message: string;
  is_read: boolean;
  created_at: string;
}

export interface AIAgent {
  id?: number;
  agent_id: string;
  name: string;
  description?: string;
  owner: string;
  status: 'active' | 'suspended' | 'under_investigation' | 'revoked';
  assigned_permissions: string[];
  allowed_resources: string[];
  allowed_actions: string[];
  allowed_destinations: string[];
  violation_count: number;
  suspension_history?: Array<{ suspended_at: string; reason: string }>;
  last_activity?: string;
  created_at: string;
  updated_at: string;
}

export interface AgentViolation {
  id?: number;
  violation_id: string;
  agent_id: string;
  event_id?: string;
  violation_type: string;
  action_attempted?: string;
  resource_attempted?: string;
  destination_attempted?: string;
  details?: string;
  severity: Severity;
  timestamp: string;
}

export interface DLPViolation {
  id?: number;
  violation_id: string;
  event_id?: string;
  actor_id: string;
  actor_type: string;
  resource: string;
  destination: string;
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  detected_patterns: Array<{ pattern: string; value: string }>;
  quarantine_path?: string;
  status: 'flagged' | 'quarantined' | 'released' | 'blocked';
  action_taken: string;
  timestamp: string;
}

export interface SecurityPolicy {
  id?: number;
  policy_id: string;
  policy_name: string;
  policy_type: 'DLP' | 'AGENT_ACCESS' | 'API_RATE_LIMIT' | 'DATA_CLASSIFICATION' | 'RULE_ENFORCEMENT' | string;
  description?: string;
  rules: Record<string, any>;
  is_active: boolean;
  severity: Severity;
  created_at?: string;
  updated_at?: string;
}

export interface APIThreatLog {
  id?: number;
  log_id: string;
  client_ip: string;
  endpoint: string;
  method: string;
  threat_type: string;
  threat_score: number;
  request_count: number;
  details?: string;
  timestamp: string;
}

export interface DashboardStats {
  total_events: number;
  open_incidents: number;
  critical_incidents: number;
  resolved_incidents: number;
  total_incidents: number;
  total_alerts: number;
  unread_alerts: number;
  active_agents: number;
  suspended_agents: number;
  total_agents: number;
  dlp_violations: number;
  api_threats: number;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  event_types_distribution: Record<string, number>;
  recent_events: SecurityEvent[];
}

export interface UserSession {
  user_id: string;
  username: string;
  email: string;
  role: 'SUPER_ADMIN' | 'ORGANIZATION_ADMIN' | 'SECURITY_ANALYST' | 'EMPLOYEE';
  organization_id: string;
  organization_name?: string;
  onboarding_completed?: boolean;
}

export interface OrganizationProfile {
  id?: number;
  organization_id: string;
  name: string;
  owner_name?: string;
  email?: string;
  phone?: string;
  industry?: string;
  country?: string;
  employee_count?: number;
  subscription_tier: 'STARTER' | 'PROFESSIONAL' | 'ENTERPRISE';
  cloud_provider: string;
  cloud_status: 'UNCONFIGURED' | 'CONNECTING' | 'CONNECTED' | 'ERROR';
  wazuh_status: 'UNCONFIGURED' | 'LISTENING' | 'ACTIVE' | 'ERROR';
  onboarding_completed: boolean;
  onboarding_step: number;
  plan: string;
  created_at: string;
  updated_at: string;
}

export interface CloudIntegration {
  integration_id: string;
  organization_id: string;
  provider: 'AWS' | 'GCP' | 'AZURE';
  account_id: string;
  role_arn: string;
  external_id: string;
  regions: string[];
  status: 'UNCONFIGURED' | 'PENDING' | 'CONNECTED' | 'ERROR';
  last_tested_at?: string;
  last_sync_at?: string;
  findings_count: number;
  error_message?: string;
}

export interface WazuhIntegration {
  integration_id: string;
  organization_id: string;
  webhook_secret: string;
  manager_url?: string;
  status: 'UNCONFIGURED' | 'LISTENING' | 'ACTIVE' | 'ERROR';
  agent_count: number;
  last_alert_at?: string;
  error_message?: string;
}

export interface SubscriptionStatus {
  subscription: {
    organization_id: string;
    tier: 'STARTER' | 'PROFESSIONAL' | 'ENTERPRISE';
    max_endpoints: number;
    max_cloud_accounts: number;
    is_active: boolean;
    current_endpoints_count: number;
    current_cloud_accounts_count: number;
    features: string[];
    billing_period: string;
  };
  tier_spec: {
    tier: string;
    name: string;
    price_monthly: number;
    max_endpoints: number;
    max_cloud_accounts: number;
    description: string;
    features: string[];
  };
  usage: {
    endpoints: {
      current: number;
      max: number;
      percentage: number;
      at_limit: boolean;
    };
    cloud_accounts: {
      current: number;
      max: number;
      percentage: number;
      at_limit: boolean;
    };
  };
}

export interface AuditLog {
  id?: number;
  log_id: string;
  organization_id: string;
  actor_id: string;
  actor_email: string;
  action: string;
  resource: string;
  details?: string;
  ip_address?: string;
  timestamp: string;
}

export interface ExecutiveReport {
  organization_id: string;
  company_name: string;
  generated_at: string;
  compliance_score: number;
  posture_grade: string;
  metrics_summary: {
    total_security_events: number;
    open_incidents: number;
    critical_incidents: number;
    resolved_incidents: number;
    dlp_violations: number;
    api_threats_blocked: number;
    active_ai_agents: number;
  };
  integrations: {
    cloud_provider: string;
    cloud_status: string;
    cloud_findings: number;
    wazuh_status: string;
    wazuh_agents: number;
  };
  subscription_tier: string;
  recommendations: string[];
}

export interface Employee {
  id?: number;
  employee_id: string;
  organization_id: string;
  name: string;
  email: string;
  department: string;
  role: string;
  risk_score: number;
  status: 'active' | 'suspended' | 'under_investigation' | 'terminated';
  created_at: string;
  updated_at: string;
}
