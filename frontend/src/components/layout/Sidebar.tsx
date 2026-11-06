import React from 'react';
import {
  ShieldCheck,
  Cloud,
  Server,
  Network,
  Brain,
  AlertTriangle,
  FolderLock,
  Users,
  FileText,
  Layers,
  CreditCard,
  Settings,
  Bot,
  Activity,
  FileCode
} from 'lucide-react';

export type NavSection =
  | 'overview'
  | 'cloud'
  | 'endpoints'
  | 'threats'
  | 'ai_decision'
  | 'incidents'
  | 'dlp'
  | 'employees'
  | 'reports'
  | 'integrations'
  | 'subscription'
  | 'settings'
  // Existing module aliases
  | 'activity'
  | 'files'
  | 'api_monitor'
  | 'risk'
  | 'agents'
  | 'policies';

interface SidebarProps {
  currentSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  openIncidentsCount?: number;
  unreadAlertsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentSection,
  onSelectSection,
  openIncidentsCount = 0,
}) => {
  const primaryMenuItems = [
    { id: 'overview', label: '1. Security Overview', icon: ShieldCheck },
    { id: 'cloud', label: '2. Cloud Security', icon: Cloud },
    { id: 'endpoints', label: '3. Endpoint Monitoring', icon: Server },
    { id: 'threats', label: '4. Threat Detection', icon: Network },
    { id: 'ai_decision', label: '5. AI Decision Analysis', icon: Brain },
    { id: 'incidents', label: '6. Security Incidents', icon: AlertTriangle, badge: openIncidentsCount > 0 ? openIncidentsCount : undefined },
    { id: 'dlp', label: '7. Data Protection (DLP)', icon: FolderLock },
    { id: 'employees', label: '8. Employees & Access', icon: Users },
    { id: 'reports', label: '9. Executive Reports', icon: FileText },
    { id: 'integrations', label: '10. Integrations Hub', icon: Layers },
    { id: 'subscription', label: '11. Subscription', icon: CreditCard },
    { id: 'settings', label: '12. Organization Settings', icon: Settings },
  ];

  const extendedMenuItems = [
    { id: 'agents', label: 'AI Autonomous Agents', icon: Bot },
    { id: 'policies', label: 'Security Rule Policies', icon: FileCode },
  ];

  return (
    <aside className="w-64 border-r border-red-950/40 bg-shield-950/80 backdrop-blur flex flex-col justify-between p-3.5 shrink-0 overflow-y-auto">
      <div className="space-y-4">
        {/* 12 Core SaaS Sections */}
        <nav className="space-y-1">
          <p className="px-2.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 flex items-center justify-between">
            <span>SaaS Defense (12 Modules)</span>
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
          </p>
          {primaryMenuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectSection(item.id as NavSection)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-red-600/25 via-red-950/30 to-transparent text-red-400 border border-red-500/40 shadow-sm shadow-red-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-red-950/20 hover:border-red-950/40 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-red-400' : 'text-slate-500'}`} />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Extended Security Controls */}
        <nav className="space-y-1 pt-2 border-t border-slate-900">
          <p className="px-2.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
            <span>Autonomous AI Controls</span>
          </p>
          {extendedMenuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectSection(item.id as NavSection)}
                className={`w-full flex items-center justify-between px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  isActive
                    ? 'bg-red-600/20 text-red-400 border border-red-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-red-950/15 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-red-400' : 'text-slate-500'}`} />
                  <span className="truncate">{item.label}</span>
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Engine Status Tag */}
      <div className="mt-4 p-3 rounded-xl bg-carbon-900 border border-red-950/60 text-[11px] text-slate-400 space-y-1 shadow-sm">
        <div className="flex items-center justify-between text-slate-300 font-semibold text-[10px]">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
            Rule 4 Enforcement
          </span>
          <span className="text-red-400 font-mono font-bold">LOCKED</span>
        </div>
        <p className="text-[10px] text-slate-500 leading-tight">
          Hard security denials override ML risk downgrades.
        </p>
      </div>
    </aside>
  );
};
