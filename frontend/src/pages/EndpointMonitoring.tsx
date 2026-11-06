import React, { useState, useEffect } from 'react';
import {
  Server,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Check,
  Terminal,
  ShieldAlert,
  HardDrive
} from 'lucide-react';
import { api } from '../services/api';
import { WazuhIntegration, SecurityEvent } from '../types';

export const EndpointMonitoring: React.FC = () => {
  const [integration, setIntegration] = useState<WazuhIntegration | null>(null);
  const [enrollment, setEnrollment] = useState<{ linux: string; windows: string; webhook_endpoint: string } | null>(null);
  const [endpointAlerts, setEndpointAlerts] = useState<SecurityEvent[]>([]);
  const [managerUrl, setManagerUrl] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    setIsLoading(true);
    try {
      const res = await api.getWazuhStatus();
      if (res?.integration) {
        setIntegration(res.integration);
        setManagerUrl(res.integration.manager_url || '');
      }
      if (res?.enrollment_commands) {
        setEnrollment(res.enrollment_commands);
      }

      // Fetch recent endpoint alerts
      const events = await api.getEvents({ limit: 20 });
      const wazuhEvts = events.filter(e => e.source?.includes('wazuh') || e.event_type?.includes('integrity') || e.event_type?.includes('endpoint'));
      setEndpointAlerts(wazuhEvts);
    } catch (err) {
      console.error('Failed to load Wazuh status:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const updated = await api.configureWazuh({ manager_url: managerUrl });
      setIntegration(updated);
      setSuccessMessage('Wazuh manager configuration updated.');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      console.error('Failed to update Wazuh manager:', err);
    }
  };

  const isConnected = integration?.status === 'ACTIVE' || integration?.status === 'LISTENING';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-tight">Endpoint Monitoring & Wazuh EDR</h1>
            {isConnected ? (
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> {integration?.status}
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> NOT CONNECTED / READY FOR ENROLLMENT
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Host intrusion detection, file integrity monitoring, rootkit audits, and automated agent sensors.
          </p>
        </div>

        <button
          onClick={fetchStatus}
          className="p-2 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {successMessage && (
        <div className="p-4 rounded-xl bg-green-500/10 border border-green-500/30 text-green-400 text-xs flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Connected Sensors</span>
          <div className="text-lg font-bold text-white mt-1 font-mono">{integration?.agent_count || 0}</div>
          <span className="text-[11px] text-slate-400">Active Wazuh agents</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">EDR Engine Status</span>
          <div className="text-lg font-bold text-red-400 mt-1">{integration?.status || 'UNCONFIGURED'}</div>
          <span className="text-[11px] text-slate-400">Webhook listener</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Last Host Alert</span>
          <div className="text-sm font-semibold text-slate-300 mt-1 font-mono truncate">
            {integration?.last_alert_at ? new Date(integration.last_alert_at).toLocaleTimeString() : 'No alerts yet'}
          </div>
          <span className="text-[11px] text-slate-400">Real-time syslog ingestion</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Security Rule Engine</span>
          <div className="text-lg font-bold text-green-400 mt-1">Rule 4 Hard Lock</div>
          <span className="text-[11px] text-slate-400">Levels 12-15 = Critical</span>
        </div>
      </div>

      {/* Installation & Agent Enrollment Scripts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Linux Enrollment Command */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-red-400" />
              <span>Linux Endpoint Agent Install (Ubuntu / Debian / RHEL)</span>
            </h2>
            <button
              onClick={() => copyToClipboard(enrollment?.linux || '', 'linux_script')}
              className="px-2.5 py-1 rounded-lg bg-carbon-950 border border-slate-800 text-xs text-slate-300 hover:text-white flex items-center gap-1.5"
            >
              {copiedKey === 'linux_script' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'linux_script' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          <p className="text-xs text-slate-400">
            Run on any Linux server to install the Wazuh agent and register it under your organization's tenant token:
          </p>

          <pre className="p-4 bg-carbon-950 border border-slate-800 rounded-xl text-[11px] font-mono text-red-300 overflow-x-auto select-all">
            {enrollment?.linux || 'Loading script...'}
          </pre>
        </div>

        {/* Windows PowerShell Enrollment Command */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-red-400" />
              <span>Windows PowerShell Enrollment Command</span>
            </h2>
            <button
              onClick={() => copyToClipboard(enrollment?.windows || '', 'win_script')}
              className="px-2.5 py-1 rounded-lg bg-carbon-950 border border-slate-800 text-xs text-slate-300 hover:text-white flex items-center gap-1.5"
            >
              {copiedKey === 'win_script' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'win_script' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          <p className="text-xs text-slate-400">
            Run in an elevated PowerShell Administrator terminal on Windows workstations or Windows Server:
          </p>

          <pre className="p-4 bg-carbon-950 border border-slate-800 rounded-xl text-[11px] font-mono text-red-300 overflow-x-auto select-all">
            {enrollment?.windows || 'Loading script...'}
          </pre>
        </div>
      </div>

      {/* Webhook Secret & Manager URL */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Server className="w-4 h-4 text-red-400" />
          <span>Wazuh Webhook Ingestion Configuration</span>
        </h2>

        <form onSubmit={handleSaveConfig} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Wazuh Manager Host / URL
            </label>
            <input
              type="text"
              placeholder="e.g. wazuh-manager.acme.corp"
              value={managerUrl}
              onChange={(e) => setManagerUrl(e.target.value)}
              className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-white"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Organization Webhook Secret (HMAC)
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                readOnly
                value={integration?.webhook_secret || ''}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-400 select-all"
              />
              <button
                type="button"
                onClick={() => copyToClipboard(integration?.webhook_secret || '', 'whsecret')}
                className="px-3 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-slate-300 hover:text-white"
              >
                {copiedKey === 'whsecret' ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <div className="sm:col-span-2 flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white transition-all cursor-pointer"
            >
              Save Wazuh Manager Settings
            </button>
          </div>
        </form>
      </div>

      {/* Recent Endpoint Security Alerts */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span>Recent Endpoint Security Alerts Ingested</span>
        </h2>

        {endpointAlerts.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No endpoint security alerts received yet. Run the enrollment command above on a server to stream host alerts.
          </div>
        ) : (
          <div className="space-y-2">
            {endpointAlerts.map((evt, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-carbon-950 border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <div className="flex items-center gap-2 font-semibold text-white">
                    <span>{evt.action}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      evt.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {evt.risk_level?.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Host: <span className="font-mono text-slate-300">{evt.actor_id}</span> • Resource: <span className="font-mono text-slate-300">{evt.resource}</span>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono font-bold text-red-400">{evt.risk_score?.toFixed(1)}</span>
                  <span className="text-[10px] text-slate-500 block font-mono">{evt.timestamp?.slice(11, 19)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
