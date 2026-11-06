import React, { useState, useEffect } from 'react';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavSection } from './components/layout/Sidebar';
import { Overview } from './pages/Overview';
import { Incidents } from './pages/Incidents';
import { ActivityMonitoring } from './pages/ActivityMonitoring';
import { FilesSharing } from './pages/FilesSharing';
import { ApiMonitor } from './pages/ApiMonitor';
import { DlpViolations } from './pages/DlpViolations';
import { RiskRecommendations } from './pages/RiskRecommendations';
import { AiAgents } from './pages/AiAgents';
import { SecurityPolicies } from './pages/SecurityPolicies';
import { SystemSettings } from './pages/SystemSettings';
import { LoginModal } from './pages/LoginModal';
import { CyberLoginPage } from './pages/CyberLoginPage';
import { api } from './services/api';
import { DashboardStats, SecurityAlert, UserSession } from './types';

export const App: React.FC = () => {
  const [currentSection, setCurrentSection] = useState<NavSection>('overview');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [user, setUser] = useState<UserSession | null>(null);
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [targetIncidentId, setTargetIncidentId] = useState<string | null>(null);

  const fetchGlobalData = async () => {
    setIsRefreshing(true);
    try {
      const [statsData, alertsData] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getAlerts({ limit: 30 }).catch(() => [])
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
        setUser(JSON.parse(storedUser));
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

  if (!user) {
    return (
      <CyberLoginPage
        onLoginSuccess={(loggedInUser) => {
          setUser(loggedInUser);
          setCurrentSection('overview');
          fetchGlobalData();
        }}
      />
    );
  }

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

        {/* Dynamic Page Content */}
        <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-b from-shield-950 via-shield-900/40 to-shield-950">
          <div className="max-w-7xl mx-auto pb-12">
            {currentSection === 'overview' && (
              <Overview
                stats={stats}
                isLoading={isLoadingStats}
                onNavigateToIncidents={() => setCurrentSection('incidents')}
                onNavigateToAgents={() => setCurrentSection('agents')}
              />
            )}

            {currentSection === 'incidents' && (
              <Incidents initialIncidentId={targetIncidentId} />
            )}

            {currentSection === 'activity' && (
              <ActivityMonitoring />
            )}

            {currentSection === 'files' && (
              <FilesSharing />
            )}

            {currentSection === 'api_monitor' && (
              <ApiMonitor />
            )}

            {currentSection === 'dlp' && (
              <DlpViolations />
            )}

            {currentSection === 'risk' && (
              <RiskRecommendations />
            )}

            {currentSection === 'agents' && (
              <AiAgents />
            )}

            {currentSection === 'policies' && (
              <SecurityPolicies />
            )}

            {currentSection === 'settings' && (
              <SystemSettings />
            )}
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
