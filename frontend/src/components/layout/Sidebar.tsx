import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Activity,
  FolderLock,
  Network,
  EyeOff,
  Cpu,
  Bot,
  FileCode,
  Settings
} from 'lucide-react';

export type NavSection =
  | 'overview'
  | 'incidents'
  | 'activity'
  | 'files'
  | 'api_monitor'
  | 'dlp'
  | 'risk'
  | 'agents'
  | 'policies'
  | 'settings';

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
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: ShieldCheck },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle, badge: openIncidentsCount > 0 ? openIncidentsCount : undefined },
    { id: 'activity', label: 'Activity Monitoring', icon: Activity },
    { id: 'files', label: 'Files & Sharing', icon: FolderLock },
    { id: 'api_monitor', label: 'API Monitor', icon: Network },
    { id: 'dlp', label: 'DLP Violations', icon: EyeOff },
    { id: 'risk', label: 'Risk & Recommendations', icon: Cpu },
    { id: 'agents', label: 'AI Agent Management', icon: Bot },
    { id: 'policies', label: 'Security Policies', icon: FileCode },
    { id: 'settings', label: 'System Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-red-950/40 bg-shield-950/70 backdrop-blur flex flex-col justify-between p-4 shrink-0">
      <nav className="space-y-1.5">
        <p className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center justify-between">
          <span>Security Controls</span>
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
        </p>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentSection === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectSection(item.id as NavSection)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-gradient-to-r from-red-600/25 via-red-950/30 to-transparent text-red-400 border border-red-500/40 shadow-md shadow-red-500/10'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-red-950/20 hover:border-red-950/40 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-red-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 shadow-sm shadow-red-500/20">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine Status Tag */}
      <div className="p-3.5 rounded-xl bg-carbon-900 border border-red-950/60 text-[11px] text-slate-400 space-y-1.5 shadow-sm shadow-red-950/30">
        <div className="flex items-center justify-between text-slate-300 font-semibold">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            Rule 4 Enforcement
          </span>
          <span className="text-red-400 font-mono font-bold">ACTIVE</span>
        </div>
        <p className="text-[10px] text-slate-500 leading-relaxed">
          Hard security denials strictly override machine learning risk downgrades.
        </p>
      </div>
    </aside>
  );
};
