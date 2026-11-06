import {
  DashboardStats,
  SecurityEvent,
  SecurityIncident,
  SecurityAlert,
  AIAgent,
  AgentViolation,
  DLPViolation,
  SecurityPolicy,
  APIThreatLog,
  UserSession,
  OrganizationProfile,
  CloudIntegration,
  WazuhIntegration,
  SubscriptionStatus,
  AuditLog,
  ExecutiveReport,
  Employee
} from '../types';

const BASE_URL = '/api';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('ai_shield_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(endpoint: string, options: RequestInit = {}, retries = 1): Promise<T> {
  const headers = {
    'Content-Type': 'application/json',
    ...getAuthHeader(),
    ...options.headers,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);

  try {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers,
      signal: options.signal || controller.signal,
    });

    const json = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (endpoint === '/health' && json.details) {
        return json.details as T;
      }
      if (response.status === 429 && retries > 0) {
        await new Promise(r => setTimeout(r, 1000));
        return request<T>(endpoint, options, retries - 1);
      }
      const errorMsg = json.error || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(errorMsg);
    }

    return (json.data !== undefined ? json.data : []) as T;
  } catch (err: any) {
    if (retries > 0 && (err.name === 'AbortError' || err.message?.includes('Failed to fetch'))) {
      await new Promise(r => setTimeout(r, 600));
      return request<T>(endpoint, options, retries - 1);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

export const api = {
  // Authentication
  login: async (username: string, password: string): Promise<{ token: string; user: UserSession }> => {
    const data = await request<{ token: string; user: UserSession }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    localStorage.setItem('ai_shield_token', data.token);
    localStorage.setItem('ai_shield_user', JSON.stringify(data.user));
    return data;
  },

  logout: () => {
    localStorage.removeItem('ai_shield_token');
    localStorage.removeItem('ai_shield_user');
  },

  getMe: (): Promise<UserSession> => request<UserSession>('/auth/me'),

  // Dashboard Stats
  getDashboardStats: (): Promise<DashboardStats> => request<DashboardStats>('/dashboard/stats'),

  // Health
  getHealth: () => request<any>('/health'),

  // Events
  getEvents: (params?: { limit?: number; offset?: number; event_type?: string; actor_type?: string; risk_level?: string }): Promise<SecurityEvent[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.event_type) query.set('event_type', params.event_type);
    if (params?.actor_type) query.set('actor_type', params.actor_type);
    if (params?.risk_level) query.set('risk_level', params.risk_level);
    return request<SecurityEvent[]>(`/events?${query.toString()}`);
  },

  createEvent: (payload: Partial<SecurityEvent>): Promise<SecurityEvent> => {
    return request<SecurityEvent>('/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Incidents
  getIncidents: (params?: { severity?: string; status?: string }): Promise<SecurityIncident[]> => {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    return request<SecurityIncident[]>(`/incidents?${query.toString()}`);
  },

  updateIncident: (incidentId: string, updates: { status?: string; assigned_to?: string; description?: string }): Promise<SecurityIncident> => {
    return request<SecurityIncident>(`/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  },

  // Alerts
  getAlerts: (params?: { severity?: string; is_read?: boolean; limit?: number; offset?: number }): Promise<SecurityAlert[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.severity) query.set('severity', params.severity);
    if (params?.is_read !== undefined) query.set('is_read', String(params.is_read));
    return request<SecurityAlert[]>(`/alerts?${query.toString()}`);
  },

  updateAlert: (alertId: string, updates: { is_read: boolean }): Promise<SecurityAlert> => {
    return request<SecurityAlert>(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  },

  acknowledgeAllAlerts: (): Promise<{ acknowledged_count: number }> => {
    return request<{ acknowledged_count: number }>('/alerts/acknowledge-all', {
      method: 'POST',
    });
  },

  // AI Agents
  getAgents: (status?: string): Promise<AIAgent[]> => {
    const query = status ? `?status=${status}` : '';
    return request<AIAgent[]>(`/agents${query}`);
  },

  updateAgentStatus: (agentId: string, status: string, reason?: string): Promise<AIAgent> => {
    return request<AIAgent>(`/agents/${agentId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, reason }),
    });
  },

  getAgentViolations: (agentId: string): Promise<AgentViolation[]> => {
    return request<AgentViolation[]>(`/agents/${agentId}/violations`);
  },

  // DLP
  getDlpViolations: (): Promise<DLPViolation[]> => request<DLPViolation[]>('/dlp/violations'),

  inspectContent: (content: string, resourceName?: string) => {
    return request<{ classification: string; sensitive_patterns_found: boolean; matches_count: number; matches: Array<{ pattern: string; value: string }> }>('/dlp/inspect', {
      method: 'POST',
      body: JSON.stringify({ content, resource_name: resourceName }),
    });
  },

  getPolicies: (): Promise<SecurityPolicy[]> => request<SecurityPolicy[]>('/dlp/policies'),

  // Threats
  getThreats: (limit: number = 50): Promise<APIThreatLog[]> => request<APIThreatLog[]>(`/threats?limit=${limit}`),

  getThreatStatus: () => request<{ blocked_clients: Array<{ client_ip: string; remaining_seconds: number }>; blocked_count: number; burst_limit: number; window_seconds: number }>('/threats/status'),

  // SaaS Multi-Tenant Registration & Onboarding
  registerCompany: async (payload: {
    company_name: string;
    owner_name: string;
    email: string;
    phone?: string;
    industry?: string;
    country?: string;
    employee_count?: number;
    password: string;
    subscription_tier?: string;
  }): Promise<{ token: string; user: UserSession; organization: OrganizationProfile }> => {
    const data = await request<{ token: string; user: UserSession; organization: OrganizationProfile }>('/auth/register-company', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    localStorage.setItem('ai_shield_token', data.token);
    localStorage.setItem('ai_shield_user', JSON.stringify(data.user));
    return data;
  },

  updateOnboarding: (data: {
    step: number;
    completed?: boolean;
    industry?: string;
    country?: string;
    employee_count?: number;
    cloud?: { account_id: string; role_arn: string; regions: string[] };
    endpoint?: { manager_url: string };
    subscription_tier?: string;
  }) => {
    return request<{ organization: OrganizationProfile; step: number; completed: boolean }>('/auth/onboarding', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  getOnboardingStatus: () => request<{
    organization: OrganizationProfile;
    cloud_integration: CloudIntegration;
    wazuh_integration: WazuhIntegration;
    subscription: any;
    onboarding_completed: boolean;
    current_step: number;
  }>('/auth/onboarding-status'),

  // AWS Cloud Integration
  getAwsStatus: () => request<{ integration: CloudIntegration; is_connected: boolean; trust_policy: any }>('/cloud/aws/status'),

  connectAws: (data: { account_id: string; role_arn: string; regions: string[] }) => {
    return request<{ integration: CloudIntegration; test_result: any }>('/cloud/aws/connect', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  syncAws: () => request<{
    cloudtrail_events_count: number;
    security_hub_findings_count: number;
    ingested_into_pipeline: number;
    cloudtrail_events: any[];
    security_hub_findings: any[];
  }>('/cloud/aws/sync', { method: 'POST' }),

  getAwsTrustPolicy: () => request<{ trust_policy: any; external_id: string }>('/cloud/aws/trust-policy'),

  // Wazuh Endpoint Integration
  getWazuhStatus: () => request<{
    integration: WazuhIntegration;
    is_connected: boolean;
    enrollment_commands: { linux: string; windows: string; webhook_endpoint: string };
  }>('/integrations/wazuh/status'),

  configureWazuh: (data: { manager_url: string }) => {
    return request<WazuhIntegration>('/integrations/wazuh/configure', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Subscription Management
  getSubscription: (): Promise<SubscriptionStatus> => request<SubscriptionStatus>('/subscription'),

  getSubscriptionTiers: () => request<any[]>('/subscription/tiers'),

  upgradeSubscription: (tier: string) => {
    return request<any>('/subscription/upgrade', {
      method: 'POST',
      body: JSON.stringify({ tier }),
    });
  },

  // Organization & Executive Reports
  getOrgProfile: (): Promise<OrganizationProfile> => request<OrganizationProfile>('/organization/profile'),

  updateOrgProfile: (data: Partial<OrganizationProfile>): Promise<OrganizationProfile> => {
    return request<OrganizationProfile>('/organization/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  getOrgAuditLogs: (limit: number = 50): Promise<AuditLog[]> => request<AuditLog[]>(`/organization/audit-logs?limit=${limit}`),

  getOrgExecutiveReport: (): Promise<ExecutiveReport> => request<ExecutiveReport>('/organization/report'),

  // Employees Management
  getEmployees: (params?: { limit?: number; offset?: number; department?: string; status?: string }): Promise<Employee[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.department) query.set('department', params.department);
    if (params?.status) query.set('status', params.status);
    return request<Employee[]>(`/employees?${query.toString()}`);
  },
};
