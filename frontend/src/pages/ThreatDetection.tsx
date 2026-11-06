import React, { useState, useEffect } from 'react';
import {
  Network,
  ShieldAlert,
  Activity,
  Cpu,
  RefreshCw,
  AlertTriangle,
  Lock,
  Unlock
} from 'lucide-react';
import { api } from '../services/api';
import { APIThreatLog } from '../types';

export const ThreatDetection: React.FC = () => {
  const [threatLogs, setThreatLogs] = useState<APIThreatLog[]>([]);
  const [threatStatus, setThreatStatus] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [logs, status] = await Promise.all([
        api.getThreats(50).catch(() => []),
        api.getThreatStatus().catch(() => null),
      ]);
      setThreatLogs(logs);
      setThreatStatus(status);
    } catch (err) {
      console.error('Failed to load threat detection data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-red-400" />
            <span>Threat Detection & ML Anomaly Telemetry</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time sliding-window API threat mitigation, automated brute-force IP lockout, and Isolation Forest ML.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-2 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Top Threat Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Currently Blocked IPs</span>
          <div className="text-xl font-bold text-red-400 mt-1 font-mono">
            {threatStatus?.blocked_count || 0}
          </div>
          <span className="text-[11px] text-slate-400">Locked out by rate limiter</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Sliding Burst Limit</span>
          <div className="text-xl font-bold text-white mt-1 font-mono">
            {threatStatus?.burst_limit || 30} <span className="text-xs font-normal text-slate-500">req/min</span>
          </div>
          <span className="text-[11px] text-slate-400">Sliding window protection</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">ML Model Engine</span>
          <div className="text-lg font-bold text-green-400 mt-1">Isolation Forest</div>
          <span className="text-[11px] text-slate-400">Unsupervised anomaly scoring</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Rule 4 Priority Lock</span>
          <div className="text-lg font-bold text-red-400 mt-1 font-mono">Floor &ge; 85.0</div>
          <span className="text-[11px] text-slate-400">Strict policy override</span>
        </div>
      </div>

      {/* Currently Blocked IPs Panel */}
      {threatStatus?.blocked_clients?.length > 0 && (
        <div className="p-6 rounded-2xl bg-red-950/20 border border-red-500/40 shadow-xl space-y-3">
          <h2 className="text-sm font-bold text-red-400 flex items-center gap-2">
            <Lock className="w-4 h-4" />
            <span>Active Automated IP Lockouts</span>
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {threatStatus.blocked_clients.map((c: any, i: number) => (
              <div key={i} className="p-3 bg-carbon-950 border border-red-500/30 rounded-xl flex items-center justify-between text-xs">
                <span className="font-mono font-bold text-white">{c.client_ip}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400">
                  {Math.round(c.remaining_seconds)}s remaining
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Logs Stream Table */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Activity className="w-4 h-4 text-red-400" />
          <span>Ingested Threat Events & Automated Mitigations</span>
        </h2>

        {threatLogs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No API threat logs detected. System is operating under normal traffic baseline.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                  <th className="pb-3">Timestamp</th>
                  <th className="pb-3">Client IP</th>
                  <th className="pb-3">Endpoint Target</th>
                  <th className="pb-3">Threat Classification</th>
                  <th className="pb-3">Calculated Threat Score</th>
                  <th className="pb-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {threatLogs.map((t) => (
                  <tr key={t.log_id} className="hover:bg-carbon-950/60 transition-colors">
                    <td className="py-3 text-slate-400">{t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : 'now'}</td>
                    <td className="py-3 text-white font-bold">{t.client_ip}</td>
                    <td className="py-3 text-slate-300">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] mr-1.5 text-slate-400">{t.method}</span>
                      {t.endpoint}
                    </td>
                    <td className="py-3 text-slate-300 font-sans">{t.threat_type}</td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                        t.threat_score >= 80 ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                      }`}>
                        {t.threat_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="py-3 font-sans">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30">
                        BLOCKED (429)
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
