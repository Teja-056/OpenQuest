import React, { useState, useEffect } from 'react';
import {
  Layers,
  Cloud,
  Server,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  KeyRound,
  Terminal,
  Copy,
  Check
} from 'lucide-react';
import { api } from '../services/api';
import { CloudIntegration, WazuhIntegration } from '../types';

export const IntegrationsHub: React.FC = () => {
  const [cloud, setCloud] = useState<CloudIntegration | null>(null);
  const [wazuh, setWazuh] = useState<WazuhIntegration | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchIntegrations = async () => {
    setIsLoading(true);
    try {
      const [cloudRes, wazuhRes] = await Promise.all([
        api.getAwsStatus().catch(() => null),
        api.getWazuhStatus().catch(() => null),
      ]);
      if (cloudRes?.integration) setCloud(cloudRes.integration);
      if (wazuhRes?.integration) setWazuh(wazuhRes.integration);
    } catch (err) {
      console.error('Failed to load integrations:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const isAwsConnected = cloud?.status === 'CONNECTED';
  const isWazuhConnected = wazuh?.status === 'ACTIVE' || wazuh?.status === 'LISTENING';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-red-400" />
            <span>Infrastructure Integrations Hub</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Connect your cloud perimeter and endpoint detection agents. Real live connectivity verified via backend APIs.
          </p>
        </div>

        <button
          onClick={fetchIntegrations}
          className="p-2 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Integration Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* AWS Card */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                  <Cloud className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">Amazon Web Services (AWS)</h2>
                  <span className="text-[11px] text-slate-400">CloudTrail & Security Hub Telemetry</span>
                </div>
              </div>

              {isAwsConnected ? (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> CONNECTED
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> NOT CONNECTED
                </span>
              )}
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Monitors AWS management calls via CloudTrail, surfaces high-severity Security Hub findings, and inspects identity boundaries using least-privilege STS AssumeRole.
            </p>

            <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Account ID:</span>
                <span className="font-mono text-white font-bold">{cloud?.account_id || 'Not Configured'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Security Hub Findings:</span>
                <span className="font-mono text-red-400 font-bold">{cloud?.findings_count || 0}</span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/80">
            <a
              href="#cloud"
              className="w-full py-2 px-3 rounded-xl bg-carbon-950 border border-slate-800 hover:border-red-500/40 text-xs font-semibold text-slate-300 hover:text-white flex items-center justify-center gap-1.5"
            >
              <span>Manage AWS Settings & IAM Role</span>
              <ExternalLink className="w-3.5 h-3.5 text-red-400" />
            </a>
          </div>
        </div>

        {/* Wazuh EDR Card */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">Wazuh EDR Endpoint Fleet</h2>
                  <span className="text-[11px] text-slate-400">Host Intrusion & File Integrity</span>
                </div>
              </div>

              {isWazuhConnected ? (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> {wazuh?.status}
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> NOT CONNECTED
                </span>
              )}
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Streams raw endpoint security alerts from Wazuh agents directly into the AI Shield unified event pipeline. Normalizes rule levels 1-15 and triggers automated incidents.
            </p>

            <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Active Sensor Agents:</span>
                <span className="font-mono text-white font-bold">{wazuh?.agent_count || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Webhook Status:</span>
                <span className="font-mono text-red-400 font-bold">{wazuh?.status || 'UNCONFIGURED'}</span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/80">
            <a
              href="#endpoints"
              className="w-full py-2 px-3 rounded-xl bg-carbon-950 border border-slate-800 hover:border-red-500/40 text-xs font-semibold text-slate-300 hover:text-white flex items-center justify-center gap-1.5"
            >
              <span>Manage EDR Agents & Enrollment</span>
              <ExternalLink className="w-3.5 h-3.5 text-red-400" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};
