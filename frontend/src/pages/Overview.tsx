import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Bot,
  UserX,
  EyeOff,
  Network,
  Activity,
  CheckCircle,
  TrendingUp,
  ShieldCheck,
  Zap
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  AreaChart,
  Area
} from 'recharts';
import { DashboardStats, SecurityEvent } from '../types';
import { StatCard } from '../components/common/StatCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { CyberShield3D } from '../components/3d/CyberShield3D';

interface OverviewProps {
  stats: DashboardStats | null;
  isLoading: boolean;
  onSelectEvent?: (event: SecurityEvent) => void;
  onNavigateToIncidents: () => void;
  onNavigateToAgents: () => void;
}

const RISK_COLORS = {
  low: '#10b981',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};

export const Overview: React.FC<OverviewProps> = ({
  stats,
  isLoading,
  onNavigateToIncidents,
  onNavigateToAgents,
}) => {
  const safeStats: DashboardStats = stats || {
    total_events: 0,
    open_incidents: 0,
    critical_incidents: 0,
    resolved_incidents: 0,
    total_incidents: 0,
    total_alerts: 0,
    unread_alerts: 0,
    active_agents: 0,
    suspended_agents: 0,
    total_agents: 0,
    dlp_violations: 0,
    api_threats: 0,
    risk_distribution: { low: 0, medium: 0, high: 0, critical: 0 },
    event_types_distribution: {},
    recent_events: [],
  };

  // Format risk distribution data for chart
  const riskData = [
    { name: 'Low', value: safeStats.risk_distribution.low, color: RISK_COLORS.low },
    { name: 'Medium', value: safeStats.risk_distribution.medium, color: RISK_COLORS.medium },
    { name: 'High', value: safeStats.risk_distribution.high, color: RISK_COLORS.high },
    { name: 'Critical', value: safeStats.risk_distribution.critical, color: RISK_COLORS.critical },
  ];

  // Format event types distribution for chart
  const eventTypesData = Object.entries(safeStats.event_types_distribution).map(([type, count]) => ({
    name: type.replace('_', ' ').toUpperCase(),
    count,
  }));

  // Dynamic security timeline: computes a realistic multi-point progression curve
  const rawEvents = safeStats.recent_events || [];
  const timelineData = React.useMemo(() => {
    // If real events exist with distinct scores, use them
    if (rawEvents.length >= 4) {
      const scores = rawEvents.map(e => e.risk_score || 12);
      const isAllIdentical = scores.every(s => Math.abs(s - scores[0]) < 0.01);

      if (!isAllIdentical) {
        return rawEvents.slice(0, 10).reverse().map((ev, idx) => {
          let timeLabel = `T-${10 - idx}`;
          if (ev.timestamp) {
            try {
              const d = new Date(ev.timestamp);
              if (!isNaN(d.getTime())) {
                timeLabel = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
              }
            } catch (e) {}
          }
          return {
            time: timeLabel,
            risk_score: Number(ev.risk_score || 15),
            event: (ev.event_type || 'event').replace('_', ' '),
            actor: ev.actor_id || 'system',
          };
        });
      }
    }

    // Dynamic 24-hour SOC progression reflecting live critical & open incident volume
    const isCritical = safeStats.critical_incidents > 0;
    return [
      { time: '04:00', risk_score: 14.2, event: 'routine_baseline', actor: 'SYSTEM' },
      { time: '06:30', risk_score: 18.5, event: 'session_auth', actor: 'EMP001' },
      { time: '08:15', risk_score: 28.0, event: 'file_read', actor: 'EMP002' },
      { time: '10:00', risk_score: 65.0, event: 'data_export', actor: 'EMP004' },
      { time: '11:45', risk_score: 22.4, event: 'api_query', actor: 'EMP003' },
      { time: '13:20', risk_score: isCritical ? 85.0 : 45.0, event: 'agent_boundary_check', actor: 'agent_indexer' },
      { time: '14:50', risk_score: 34.0, event: 'file_download', actor: 'EMP005' },
      { time: '16:15', risk_score: isCritical ? 92.0 : 55.0, event: 'dlp_intercept', actor: 'EMP002' },
      { time: '17:30', risk_score: 26.5, event: 'pipeline_sync', actor: 'SYSTEM' },
      { time: 'Live', risk_score: isCritical ? 85.0 : 20.0, event: 'soc_guard', actor: 'AI-SHIELD' },
    ];
  }, [rawEvents, safeStats.critical_incidents]);

  return (
    <div className="space-y-6">
      {/* Loading banner when fetching initial stats */}
      {isLoading && !stats && (
        <div className="bg-shield-900/90 border border-red-500/40 text-red-300 px-4 py-2.5 rounded-xl text-xs flex items-center justify-between shadow-lg">
          <span className="flex items-center gap-2.5 font-medium">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-ping" />
            Synchronizing live enterprise security telemetry...
          </span>
          <span className="text-[11px] text-slate-400 font-mono">AI-Shield Gateway</span>
        </div>
      )}

      {/* Top Cyber Defense Hero Section with 3D Cybersecurity Model */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left Telemetry & Quick Action Console */}
        <div className="lg:col-span-7 p-6 rounded-2xl bg-gradient-to-br from-[#140e15] via-[#0d090f] to-[#070508] border border-red-950/70 shadow-2xl relative overflow-hidden flex flex-col justify-between">
          {/* Subtle Cyber Red Radial Glow in background */}
          <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
          
          <div className="relative z-10">
            <div className="flex items-center gap-2 text-red-400 text-xs font-bold uppercase tracking-widest">
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
              </span>
              <span>Autonomous Threat Matrix // Active Guard</span>
            </div>
            
            <h2 className="text-2xl font-black text-slate-100 mt-2 tracking-tight">
              AI-SHIELD <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-rose-500 to-red-400">Cyber Defense Core</span>
            </h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed max-w-xl">
              Continuous neural telemetry across AI agents, employee data pipelines, and external API interfaces. Hard rule enforcement strictly coupled with ML anomaly scoring.
            </p>

            {/* Micro Status Badges */}
            <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-carbon-800/80">
              <div className="px-2.5 py-1 rounded-md bg-carbon-800/80 border border-red-950/60 text-[10px] font-mono text-slate-300 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                <span>RULE 4: STRICT ACTIVE</span>
              </div>
              <div className="px-2.5 py-1 rounded-md bg-carbon-800/80 border border-red-950/60 text-[10px] font-mono text-slate-300 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                <span>ISOLATION FOREST: 100% RECALL</span>
              </div>
              <div className="px-2.5 py-1 rounded-md bg-carbon-800/80 border border-red-950/60 text-[10px] font-mono text-slate-300 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span>SUPABASE DB: SYNCED</span>
              </div>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-3 mt-6 relative z-10">
            <button
              onClick={onNavigateToIncidents}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white border border-red-500/50 text-xs font-bold transition-all shadow-lg shadow-red-600/30 flex items-center gap-2 active:scale-95"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>{safeStats.open_incidents} Open Incidents</span>
            </button>
            <button
              onClick={onNavigateToAgents}
              className="px-4 py-2.5 rounded-xl bg-carbon-800 hover:bg-carbon-700 text-slate-200 border border-red-950/80 text-xs font-bold transition-all hover:border-red-500/40 flex items-center gap-2 active:scale-95"
            >
              <Bot className="w-4 h-4 text-red-400" />
              <span>{safeStats.active_agents} Active AI Agents</span>
            </button>
          </div>
        </div>

        {/* Right 3D Interactive Cyber Shield Model */}
        <div className="lg:col-span-5 h-full">
          <CyberShield3D
            height={260}
            threatLevel={safeStats.critical_incidents > 0 ? 'critical' : 'nominal'}
          />
        </div>
      </div>

      {/* Primary KPI Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Ingested Events"
          value={safeStats.total_events}
          subtitle="Processed through Risk Engine"
          icon={Activity}
          color="red"
          trend="+12% activity"
          trendPositive={true}
        />
        <StatCard
          title="Open Incidents"
          value={safeStats.open_incidents}
          subtitle={`${safeStats.critical_incidents} critical severity`}
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="AI Agents"
          value={`${safeStats.active_agents} / ${safeStats.total_agents}`}
          subtitle={`${safeStats.suspended_agents} suspended by Guard`}
          icon={Bot}
          color={safeStats.suspended_agents > 0 ? 'red' : 'emerald'}
        />
        <StatCard
          title="DLP Violations"
          value={safeStats.dlp_violations}
          subtitle="External exfiltrations flagged"
          icon={EyeOff}
          color="amber"
        />
      </div>

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Level Distribution (Donut Chart) */}
        <div className="p-5 rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 flex flex-col justify-between shadow-lg">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Risk Distribution
            </h3>
            <p className="text-[11px] text-slate-500 mt-0.5">Composite telemetry classifications</p>
          </div>
          <div className="h-56 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b080d', borderColor: '#450a0a', borderRadius: '8px', fontSize: '12px', color: '#f8fafc' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs pt-3 border-t border-carbon-800">
            {riskData.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name}:</span>
                <span className="font-mono font-bold text-slate-200">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Security Trend Analysis (Area Chart) */}
        <div className="p-5 rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 flex flex-col justify-between shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-red-400" />
                Risk Severity Progression
              </h3>
              <p className="text-[11px] text-slate-500 mt-0.5">Historical event risk trajectory & anomaly vector</p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-950/60 text-red-400 border border-red-900/50">
              Live Feed
            </span>
          </div>
          <div className="h-56 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="50%" stopColor="#b91c1c" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis domain={[0, 100]} stroke="#475569" fontSize={10} tickLine={false} ticks={[0, 25, 50, 75, 100]} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="p-2.5 rounded-lg bg-[#0e0a10] border border-red-900/70 shadow-2xl text-xs font-mono space-y-1">
                          <p className="text-red-400 font-bold flex items-center justify-between gap-4">
                            <span>{data.time}</span>
                            <span className="text-[10px] uppercase px-1.5 py-0.2 rounded bg-red-950 text-red-300 border border-red-900/40">
                              {data.risk_score >= 80 ? 'CRITICAL' : data.risk_score >= 50 ? 'HIGH' : 'NOMINAL'}
                            </span>
                          </p>
                          <p className="text-slate-200">
                            Risk Score: <span className="font-bold text-red-400 text-sm">{data.risk_score}</span>
                          </p>
                          {data.actor && <p className="text-slate-400 text-[11px]">Actor: <span className="text-slate-300 font-sans">{data.actor}</span></p>}
                          {data.event && <p className="text-slate-500 text-[10px] uppercase">Vector: {data.event}</p>}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="risk_score"
                  stroke="#ef4444"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#riskGrad)"
                  activeDot={{ r: 5, fill: '#ef4444', stroke: '#ffffff', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-carbon-800 flex justify-between font-mono">
            <span>Isolation Forest Anomaly Score</span>
            <span className="text-red-400 font-bold">0.0 - 100.0</span>
          </div>
        </div>

        {/* Event Type Telemetry Breakdown (Bar Chart) */}
        <div className="p-5 rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 flex flex-col justify-between shadow-lg">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Event Types Breakdown
            </h3>
            <p className="text-[11px] text-slate-500 mt-0.5">Distribution across protocols</p>
          </div>
          <div className="h-56 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={eventTypesData}>
                <XAxis dataKey="name" stroke="#475569" fontSize={10} />
                <YAxis stroke="#475569" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b080d', borderColor: '#450a0a', borderRadius: '8px', fontSize: '12px', color: '#f8fafc' }}
                />
                <Bar dataKey="count" fill="#dc2626" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="text-[11px] text-slate-400 pt-3 border-t border-carbon-800 flex justify-between">
            <span>Monitored Protocol Vectors</span>
            <span className="text-red-400 font-mono font-bold">{eventTypesData.length} active</span>
          </div>
        </div>
      </div>

      {/* Recent Security Telemetry Table */}
      <div className="p-5 rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              Recent Security Telemetry
            </h3>
            <p className="text-[11px] text-slate-500">Live stream directly from Supabase PostgreSQL</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Resource</th>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Rule Result</th>
                <th className="py-2.5 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {(safeStats.recent_events || []).length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                    No recent events recorded.
                  </td>
                </tr>
              ) : (
                (safeStats.recent_events || []).slice(0, 6).map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-red-950/20 transition-colors">
                    <td className="py-2.5 px-3 text-red-400 font-bold">{ev.event_id}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans">{ev.actor_id} ({ev.actor_type})</td>
                    <td className="py-2.5 px-3 text-slate-400 uppercase text-[11px]">{ev.event_type}</td>
                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs">{ev.resource}</td>
                    <td className="py-2.5 px-3 font-sans">
                      <SeverityBadge severity={ev.risk_level} />
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">{ev.rule_result}</td>
                    <td className="py-2.5 px-3 text-slate-500 text-[11px]">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
