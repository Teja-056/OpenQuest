import React, { useState } from 'react';
import {
  Shield,
  Bell,
  RefreshCw,
  User,
  CheckCircle2,
  AlertOctagon,
  LogOut,
  LogIn
} from 'lucide-react';
import { SecurityAlert, UserSession } from '../../types';

interface NavbarProps {
  statsRefresh: () => void;
  isRefreshing: boolean;
  alerts: SecurityAlert[];
  user: UserSession | null;
  onOpenLogin: () => void;
  onLogout: () => void;
  onSelectIncident?: (incidentId: string) => void;
  onAcknowledgeAlert?: (alertId: string) => void;
  onAcknowledgeAll?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  statsRefresh,
  isRefreshing,
  alerts,
  user,
  onOpenLogin,
  onLogout,
  onSelectIncident,
  onAcknowledgeAlert,
  onAcknowledgeAll,
}) => {
  const [showAlertsDropdown, setShowAlertsDropdown] = useState(false);
  const unreadAlerts = alerts.filter(a => !a.is_read);

  return (
    <header className="h-16 border-b border-red-950/40 bg-shield-950/90 backdrop-blur sticky top-0 z-30 px-6 flex items-center justify-between">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-red-600 via-rose-600 to-red-500 flex items-center justify-center shadow-lg shadow-red-600/30 border border-red-500/40">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-lg text-slate-100 tracking-tight">AI-SHIELD</h1>
            <span className="text-[10px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
              Enterprise
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Unified AI Security & Data Loss Prevention</p>
        </div>
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-4">
        {/* Backend / Supabase status */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-carbon-800/80 border border-red-950/60 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-slate-300 font-medium">Supabase PostgreSQL Connected</span>
        </div>

        {/* Manual Refresh Button */}
        <button
          onClick={statsRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg bg-carbon-800 border border-carbon-700 text-slate-300 hover:text-red-400 hover:border-red-500/50 transition-all disabled:opacity-50"
          title="Refresh Telemetry Data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-red-400' : ''}`} />
        </button>

        {/* Alerts Bell */}
        <div className="relative">
          <button
            onClick={() => setShowAlertsDropdown(!showAlertsDropdown)}
            className="p-2 rounded-lg bg-carbon-800 border border-carbon-700 text-slate-300 hover:text-red-400 hover:border-red-500/50 transition-all relative"
            title="Active Security Alerts"
          >
            <Bell className="w-4 h-4" />
            {unreadAlerts.length > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-600 text-white text-[10px] font-bold flex items-center justify-center animate-bounce shadow-md shadow-red-500/50">
                {unreadAlerts.length}
              </span>
            )}
          </button>

          {/* Alerts Dropdown */}
          {showAlertsDropdown && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl bg-shield-900 border border-red-950/80 shadow-2xl p-4 z-50">
              <div className="flex items-center justify-between pb-3 border-b border-carbon-800">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Security Alerts ({unreadAlerts.length} Unread)
                </span>
                {onAcknowledgeAll && unreadAlerts.length > 0 && (
                  <button
                    onClick={() => {
                      onAcknowledgeAll();
                      setShowAlertsDropdown(false);
                    }}
                    className="text-xs text-red-400 hover:underline"
                  >
                    Acknowledge All
                  </button>
                )}
              </div>

              <div className="mt-3 space-y-2 max-h-72 overflow-y-auto">
                {alerts.length === 0 ? (
                  <p className="text-xs text-slate-500 text-center py-4">No alerts recorded.</p>
                ) : (
                  alerts.slice(0, 10).map((alert) => (
                    <div
                      key={alert.alert_id}
                      className={`p-2.5 rounded-lg border text-xs ${
                        alert.is_read
                          ? 'bg-carbon-900/40 border-carbon-800 text-slate-400'
                          : 'bg-red-500/10 border-red-500/30 text-slate-200 shadow-sm shadow-red-950/40'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-carbon-800 text-red-400 border border-red-950/50">
                          {alert.alert_type}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(alert.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-300 line-clamp-2">{alert.message}</p>
                      <div className="mt-2 flex items-center justify-between">
                        {alert.incident_id && onSelectIncident ? (
                          <button
                            onClick={() => {
                              onSelectIncident(alert.incident_id!);
                              setShowAlertsDropdown(false);
                            }}
                            className="text-[10px] text-red-400 hover:text-red-300 hover:underline"
                          >
                            View Incident &rarr;
                          </button>
                        ) : <span />}
                        {!alert.is_read && onAcknowledgeAlert && (
                          <button
                            onClick={() => onAcknowledgeAlert(alert.alert_id)}
                            className="text-[10px] text-slate-400 hover:text-emerald-400"
                          >
                            Mark Read
                          </button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Session */}
        {user ? (
          <div className="flex items-center gap-3 pl-3 border-l border-carbon-800">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-semibold text-slate-200">{user.username}</p>
              <p className="text-[10px] text-red-400 font-mono uppercase font-bold">{user.role}</p>
            </div>
            <button
              onClick={onLogout}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-carbon-800 border border-red-950/70 hover:border-red-500/50 text-slate-300 hover:text-red-400 text-xs font-semibold transition-all shadow-sm"
              title="Logout & Return to AI-SHIELD Portal"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Portal</span>
            </button>
          </div>
        ) : (
          <button
            onClick={onOpenLogin}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-medium text-xs transition-all shadow-lg shadow-red-600/30 border border-red-500/40"
          >
            <LogIn className="w-4 h-4" />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
};
