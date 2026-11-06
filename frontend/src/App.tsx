import React, { useState, useEffect } from 'react';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavSection } from './components/layout/Sidebar';
import { Overview } from './pages/Overview';
import { CloudSecurity } from './pages/CloudSecurity';
import { EndpointMonitoring } from './pages/EndpointMonitoring';
import { ThreatDetection } from './pages/ThreatDetection';
import { AiDecisionAnalysis } from './pages/AiDecisionAnalysis';
import { Incidents } from './pages/Incidents';
import { DlpViolations } from './pages/DlpViolations';
import { EmployeesManagement } from './pages/EmployeesManagement';
import { ExecutiveReports } from './pages/ExecutiveReports';
import { IntegrationsHub } from './pages/IntegrationsHub';
import { SubscriptionManagement } from './pages/SubscriptionManagement';
import { OrganizationSettings } from './pages/OrganizationSettings';

// Extended existing modules
import { ActivityMonitoring } from './pages/ActivityMonitoring';
import { FilesSharing } from './pages/FilesSharing';
import { ApiMonitor } from './pages/ApiMonitor';
import { RiskRecommendations } from './pages/RiskRecommendations';
import { AiAgents } from './pages/AiAgents';
import { SecurityPolicies } from './pages/SecurityPolicies';
import { SystemSettings } from './pages/SystemSettings';

// Authentication & Onboarding
import { CyberLoginPage } from './pages/CyberLoginPage';
import { CompanyRegistration } from './pages/CompanyRegistration';
import { CompanyOnboarding } from './pages/CompanyOnboarding';
import { LoginModal } from './pages/LoginModal';

import { api } from './services/api';
import { DashboardStats, SecurityAlert, UserSession, OrganizationProfile } from './types';

export const App: React.FC = () => {
  const [currentSection, setCurrentSection] = useState<NavSection>('overview');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [user, setUser] = useState<UserSession | null>(null);
  const [organization, setOrganization] = useState<OrganizationProfile | null>(null);
  const [authView, setAuthView] = useState<'login' | 'register' | 'onboarding' | 'dashboard'>('login');
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [targetIncidentId, setTargetIncidentId] = useState<string | null>(null);

  const fetchGlobalData = async () => {
    setIsRefreshing(true);
    try {
      const [statsData, alertsData] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getAlerts({ limit: 30 }).catch(() => []),
      ]);
      if (statsData) {
        setStats(statsData);
        try {
          localStorage.setItem('ai_shield_stats', JSON.stringify(statsData));
        } catch (e) {
          // ignore
        }
      }
      setAlerts(alertsData || []);
    } catch (err) {
      console.error('Failed to fetch global security telemetry:', err);
    } finally {
      setIsLoadingStats(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    // Check local storage session
    const storedUser = localStorage.getItem('ai_shield_user');
    if (storedUser) {
      try {
        const parsed = JSON.parse(storedUser);
        setUser(parsed);
        setAuthView('dashboard');
      } catch (e) {
        localStorage.removeItem('ai_shield_user');
      }
    }

    // Restore cached stats if available for instant render
    const cachedStats = localStorage.getItem('ai_shield_stats');
    if (cachedStats) {
      try {
        setStats(JSON.parse(cachedStats));
        setIsLoadingStats(false);
      } catch (e) {
        // ignore
      }
    }

    fetchGlobalData();
  }, []);

  const handleLogout = () => {
    api.logout();
    setUser(null);
    setOrganization(null);
    setAuthView('login');
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await api.updateAlert(alertId, { is_read: true });
      setAlerts(prev => prev.map(a => a.alert_id === alertId ? { ...a, is_read: true } : a));
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  const handleAcknowledgeAll = async () => {
    try {
      await api.acknowledgeAllAlerts();
      setAlerts(prev => prev.map(a => ({ ...a, is_read: true })));
    } catch (err) {
      console.error('Failed to acknowledge all alerts:', err);
    }
  };

  const handleSelectIncidentFromAlert = (incidentId: string) => {
    setTargetIncidentId(incidentId);
    setCurrentSection('incidents');
  };

  // 1. Unauthenticated: Show Registration
  if (!user && authView === 'register') {
    return (
      <CompanyRegistration
        onRegistrationSuccess={(registeredUser, registeredOrg) => {
          setUser(registeredUser);
          setOrganization(registeredOrg);
          setAuthView('onboarding');
        }}
        onNavigateToLogin={() => setAuthView('login')}
      />
    );
  }

  // 2. Unauthenticated: Show Cyber Login
  if (!user) {
    return (
      <CyberLoginPage
        onLoginSuccess={(loggedInUser) => {
          setUser(loggedInUser);
          setAuthView('dashboard');
          fetchGlobalData();
        }}
        onNavigateToRegister={() => setAuthView('register')}
      />
    );
  }

  // 3. Authenticated: Multi-Step Onboarding View
  if (authView === 'onboarding') {
    return (
      <CompanyOnboarding
        organization={organization || {
          organization_id: user.organization_id || 'org_default',
          name: user.organization_name || 'Organization',
          subscription_tier: 'STARTER',
          cloud_provider: 'AWS',
          cloud_status: 'UNCONFIGURED',
          wazuh_status: 'UNCONFIGURED',
          onboarding_completed: false,
          onboarding_step: 1,
          plan: 'starter',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }}
        onComplete={() => {
          setAuthView('dashboard');
          fetchGlobalData();
        }}
      />
    );
  }

  // 4. Authenticated: 12-Section Organization Dashboard Workspace
  return (
    <div className="min-h-screen bg-shield-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        statsRefresh={fetchGlobalData}
        isRefreshing={isRefreshing}
        alerts={alerts}
        user={user}
        onOpenLogin={() => setIsLoginOpen(true)}
        onLogout={handleLogout}
        onSelectIncident={handleSelectIncidentFromAlert}
        onAcknowledgeAlert={handleAcknowledgeAlert}
        onAcknowledgeAll={handleAcknowledgeAll}
      />

      {/* Main Workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentSection={currentSection}
          onSelectSection={(sec) => {
            setCurrentSection(sec);
            setTargetIncidentId(null);
          }}
          openIncidentsCount={stats?.open_incidents || 0}
          unreadAlertsCount={alerts.filter(a => !a.is_read).length}
        />

        {/* Dynamic Page Content for 12 Sections */}
        <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-b from-shield-950 via-shield-900/40 to-shield-950">
          <div className="max-w-7xl mx-auto pb-12">
            {/* Section 1: Security Overview */}
            {currentSection === 'overview' && (
              <Overview
                stats={stats}
                isLoading={isLoadingStats}
                onNavigateToIncidents={() => setCurrentSection('incidents')}
                onNavigateToAgents={() => setCurrentSection('agents')}
              />
            )}

            {/* Section 2: Cloud Security (AWS STS AssumeRole) */}
            {currentSection === 'cloud' && (
              <CloudSecurity />
            )}

            {/* Section 3: Endpoint Monitoring (Wazuh EDR) */}
            {currentSection === 'endpoints' && (
              <EndpointMonitoring />
            )}

            {/* Section 4: Threat Detection (Isolation Forest & Rate Limiter) */}
            {currentSection === 'threats' && (
              <ThreatDetection />
            )}

            {/* Section 5: AI Decision Analysis (TypeSafe Jev + RLCD) */}
            {currentSection === 'ai_decision' && (
              <AiDecisionAnalysis />
            )}

            {/* Section 6: Security Incidents */}
            {currentSection === 'incidents' && (
              <Incidents initialIncidentId={targetIncidentId} />
            )}

            {/* Section 7: Data Protection (DLP) */}
            {currentSection === 'dlp' && (
              <DlpViolations />
            )}

            {/* Section 8: Employees & Identity Access */}
            {currentSection === 'employees' && (
              <EmployeesManagement />
            )}

            {/* Section 9: Executive Reports */}
            {currentSection === 'reports' && (
              <ExecutiveReports />
            )}

            {/* Section 10: Integrations Hub */}
            {currentSection === 'integrations' && (
              <IntegrationsHub />
            )}

            {/* Section 11: Subscription & Quota Limits */}
            {currentSection === 'subscription' && (
              <SubscriptionManagement />
            )}

            {/* Section 12: Organization Settings */}
            {currentSection === 'settings' && (
              <OrganizationSettings />
            )}

            {/* Legacy Module Aliases */}
            {currentSection === 'activity' && <ActivityMonitoring />}
            {currentSection === 'files' && <FilesSharing />}
            {currentSection === 'api_monitor' && <ApiMonitor />}
            {currentSection === 'risk' && <RiskRecommendations />}
            {currentSection === 'agents' && <AiAgents />}
            {currentSection === 'policies' && <SecurityPolicies />}
          </div>
        </main>
      </div>

      {/* Authentication Modal */}
      <LoginModal
        isOpen={isLoginOpen}
        onClose={() => setIsLoginOpen(false)}
        onLoginSuccess={(loggedInUser) => setUser(loggedInUser)}
      />
    </div>
  );
};
