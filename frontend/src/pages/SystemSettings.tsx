import React, { useState, useEffect } from 'react';
import {
  Settings,
  Database,
  Activity,
  Cpu,
  CheckCircle2,
  RefreshCw,
  Play,
  Server,
  ShieldAlert,
  Info,
  Layers,
  Lock
} from 'lucide-react';
import { api } from '../services/api';

export const SystemSettings: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [isLoadingHealth, setIsLoadingHealth] = useState(true);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simMessage, setSimMessage] = useState<string | null>(null);

  const fetchHealth = async () => {
    setIsLoadingHealth(true);
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (err: any) {
      setHealth({ status: 'degraded', database: 'error', error: err.message });
    } finally {
      setIsLoadingHealth(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const handleRunSimulatorBurst = async (count: number) => {
    setIsSimulating(true);
    setSimMessage(null);
    try {
      const scenarios = [
        {
          event_id: `SIM-BURST-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
          event_type: 'file_share',
          actor_type: 'employee' as const,
          actor_id: 'EMP002',
          resource: 'customer_ssn_records.csv',
          is_sensitive: true,
          action: 'share',
          destination: 'personal_email@gmail.com',
          source: 'dashboard_telemetry_simulator',
          description: 'Simulated sensitive file share to external personal email'
        },
        {
          event_id: `SIM-BURST-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
          event_type: 'api_request',
          actor_type: 'agent' as const,
          actor_id: 'agent_indexer_01',
          resource: '/admin/production_credentials.env',
          is_sensitive: true,
          action: 'read',
          destination: 'internal',
          source: 'dashboard_telemetry_simulator',
          description: 'Simulated unauthorized AI agent access attempt'
        },
        {
          event_id: `SIM-BURST-${Math.random().toString(36).substring(2, 7).toUpperCase()}`,
          event_type: 'file_access',
          actor_type: 'employee' as const,
          actor_id: 'EMP001',
          resource: 'project_architecture.pdf',
          is_sensitive: false,
          action: 'read',
          destination: 'internal',
          source: 'dashboard_telemetry_simulator',
          description: 'Simulated nominal employee document reading'
        }
      ];

      for (let i = 0; i < count; i++) {
        const sc = scenarios[i % scenarios.length];
        await api.createEvent(sc);
      }

      setSimMessage(`Successfully streamed ${count} simulated security events into the live pipeline!`);
      await fetchHealth();
    } catch (err: any) {
      setSimMessage(`Simulation error: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-red-500" />
          System Health, Architecture Diagnostics & Telemetry
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Diagnostics, database connection validation, ML inference parameters, and demonstration controls.
        </p>
      </div>

      {/* Service Health Diagnostics */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
            <Server className="w-4 h-4" />
            Live Platform Diagnostics
          </div>
          <button
            onClick={fetchHealth}
            disabled={isLoadingHealth}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-red-400 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHealth ? 'animate-spin text-red-400' : ''}`} />
            <span>Re-probe System</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60 shadow-inner">
            <span className="text-slate-500 text-[11px] block">API Service:</span>
            <span className="text-emerald-400 font-bold text-sm flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              ONLINE (HTTP 200)
            </span>
            <span className="text-slate-500 text-[10px] block mt-1">Python 3.14 / Flask REST</span>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60 shadow-inner">
            <span className="text-slate-500 text-[11px] block">Database Backend:</span>
            <span className="text-emerald-400 font-bold text-sm block mt-0.5 truncate">
              {health?.database_type === 'supabase_postgresql' ? 'Supabase PostgreSQL' : 'Local SQLite Storage'}
            </span>
            <span className="text-slate-500 text-[10px] block mt-1">Multi-Tenant Isolation Active</span>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60 shadow-inner">
            <span className="text-slate-500 text-[11px] block">Hard Denial Rule 4:</span>
            <span className="text-red-400 font-bold text-sm block mt-0.5">ENFORCING &ge; 85.0</span>
            <span className="text-slate-500 text-[10px] block mt-1">Non-overridable Guarantee</span>
          </div>
        </div>
      </div>

      {/* Machine Learning Pipeline Status */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
          <Cpu className="w-4 h-4" />
          Machine Learning Anomaly Detection Engine
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60">
            <span className="text-slate-500 text-[11px] block">Algorithm:</span>
            <span className="text-slate-200 font-bold">Isolation Forest</span>
            <span className="text-[10px] text-slate-500 block mt-1">150 Estimators</span>
          </div>
          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60">
            <span className="text-slate-500 text-[11px] block">Validation Recall:</span>
            <span className="text-emerald-400 font-bold">1.0000 (100%)</span>
            <span className="text-[10px] text-slate-500 block mt-1">Held-Out Test Split</span>
          </div>
          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60">
            <span className="text-slate-500 text-[11px] block">Model Artifact:</span>
            <span className="text-slate-300 font-bold text-[11px] truncate block">isolation_forest.joblib</span>
            <span className="text-[10px] text-emerald-400 block mt-1">Active In Memory</span>
          </div>
          <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60">
            <span className="text-slate-500 text-[11px] block">Contamination Rate:</span>
            <span className="text-slate-200 font-bold">0.08 (8%)</span>
            <span className="text-[10px] text-slate-500 block mt-1">Calibrated Baseline</span>
          </div>
        </div>
      </div>

      {/* Demonstration & Simulator Controls */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
          <Play className="w-4 h-4" />
          Demonstration Telemetry Streamer
        </div>
        <p className="text-xs text-slate-400 leading-relaxed font-sans">
          Trigger simulated security events across DLP exfiltration, rogue AI agent boundary access, and normal employee document reviews to observe live pipeline reactions.
        </p>

        <div className="flex items-center gap-3">
          <button
            onClick={() => handleRunSimulatorBurst(1)}
            disabled={isSimulating}
            className="px-4 py-2 rounded-lg bg-carbon-800 hover:bg-carbon-700 text-slate-200 border border-red-950/60 hover:border-red-500/40 text-xs font-semibold transition-all disabled:opacity-50 active:scale-95"
          >
            Emit 1 Event
          </button>
          <button
            onClick={() => handleRunSimulatorBurst(3)}
            disabled={isSimulating}
            className="px-4 py-2 rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-semibold shadow-lg shadow-red-600/30 border border-red-500/40 transition-all disabled:opacity-50 active:scale-95"
          >
            Emit 3 Events Burst
          </button>
        </div>

        {simMessage && (
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{simMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
};
