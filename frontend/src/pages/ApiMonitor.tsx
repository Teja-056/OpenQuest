import React, { useState, useEffect } from 'react';
import {
  Network,
  ShieldAlert,
  Lock,
  Clock,
  Activity,
  AlertOctagon,
  RefreshCw,
  Search,
  Zap
} from 'lucide-react';
import { APIThreatLog } from '../types';
import { api } from '../services/api';

export const ApiMonitor: React.FC = () => {
  const [threats, setThreats] = useState<APIThreatLog[]>([]);
  const [status, setStatus] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [threatsData, statusData] = await Promise.all([
        api.getThreats(100),
        api.getThreatStatus()
      ]);
      setThreats(Array.isArray(threatsData) ? threatsData : []);
      setStatus(statusData);
    } catch (err) {
      console.error('Failed to load API threat data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const filteredThreats = (threats || []).filter(t =>
    (t.client_ip || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.endpoint || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.threat_type || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-red-500" />
            API Threat & Traffic Monitor
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Sliding-window rate limiting, brute force lockout, and suspicious client endpoint inspection.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-carbon-800 hover:bg-carbon-700 text-slate-300 text-xs font-semibold border border-red-950/60 hover:border-red-500/40 transition-all shadow-sm"
        >
          <RefreshCw className="w-3.5 h-3.5 text-red-400" />
          <span>Refresh Threats</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Configured Burst Limit</p>
            <h4 className="text-xl font-bold text-slate-100 font-mono mt-0.5">
              {status?.burst_limit || 30} req / {status?.window_seconds || 60}s
            </h4>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-red-600/15 text-red-400 border border-red-500/30">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Active Blocked Client IPs</p>
            <h4 className="text-xl font-bold text-red-400 font-mono mt-0.5">
              {status?.blocked_count || 0} Clients
            </h4>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Total Threat Detections</p>
            <h4 className="text-xl font-bold text-amber-400 font-mono mt-0.5">{threats.length}</h4>
          </div>
        </div>
      </div>

      {/* Blocked Clients Banner */}
      {status?.blocked_clients && status.blocked_clients.length > 0 && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs shadow-md">
          <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider mb-2">
            <AlertOctagon className="w-4 h-4" />
            Currently Restricted Threat Sources
          </div>
          <div className="flex flex-wrap gap-2">
            {status.blocked_clients.map((item: any, i: number) => (
              <span key={i} className="px-2.5 py-1 rounded bg-shield-900 border border-red-500/40 text-red-300 font-mono flex items-center gap-2">
                <span>{item.client_ip}</span>
                <span className="text-[10px] text-slate-400">({item.remaining_seconds}s lockout remaining)</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Threats Table */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-red-950/60 flex items-center justify-between bg-[#180f1a]">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Security Incident Telemetry & API Threat Log
          </h3>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP or threat type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1 rounded bg-carbon-800 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-52"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-3 px-4">Log ID</th>
                <th className="py-3 px-4">Client IP</th>
                <th className="py-3 px-4">Threat Type</th>
                <th className="py-3 px-4">Target Endpoint</th>
                <th className="py-3 px-4">Threat Score</th>
                <th className="py-3 px-4">Details</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    Loading API threat logs...
                  </td>
                </tr>
              ) : filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No active API threat violations recorded.
                  </td>
                </tr>
              ) : (
                filteredThreats.map((threat) => (
                  <tr key={threat.log_id} className="hover:bg-red-950/20 transition-colors">
                    <td className="py-3 px-4 text-red-400 font-bold">{threat.log_id}</td>
                    <td className="py-3 px-4 text-slate-200 font-bold">{threat.client_ip}</td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        threat.threat_type.includes('rate_limit') ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        threat.threat_type.includes('brute') ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      }`}>
                        {threat.threat_type.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      <span className="text-[10px] text-red-400 mr-1.5 uppercase font-bold">{threat.method}</span>
                      {threat.endpoint}
                    </td>
                    <td className="py-3 px-4 font-bold text-red-400">
                      {threat.threat_score} / 100.0
                    </td>
                    <td className="py-3 px-4 font-sans text-slate-400 text-xs max-w-xs truncate">
                      {threat.details || 'Threat threshold exceeded'}
                    </td>
                    <td className="py-3 px-4 text-slate-500 text-[11px]">
                      {new Date(threat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
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
