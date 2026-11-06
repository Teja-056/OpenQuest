import React, { useState, useEffect } from 'react';
import {
  Cloud,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  KeyRound,
  ShieldAlert,
  Copy,
  Check,
  ExternalLink,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { CloudIntegration } from '../types';

export const CloudSecurity: React.FC = () => {
  const [integration, setIntegration] = useState<CloudIntegration | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<any>(null);
  const [accountId, setAccountId] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [regions, setRegions] = useState<string[]>(['us-east-1']);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [trustPolicy, setTrustPolicy] = useState<any>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    setIsLoading(true);
    try {
      const res = await api.getAwsStatus();
      if (res?.integration) {
        setIntegration(res.integration);
        setAccountId(res.integration.account_id || '');
        setRoleArn(res.integration.role_arn || '');
        setRegions(res.integration.regions || ['us-east-1']);
      }
      if (res?.trust_policy) {
        setTrustPolicy(res.trust_policy);
      }
    } catch (err: any) {
      console.error('Failed to load AWS status:', err);
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

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await api.connectAws({
        account_id: accountId,
        role_arn: roleArn,
        regions,
      });
      setIntegration(res.integration);
      if (res.test_result?.is_connected) {
        setSuccessMessage('AWS connection verified and active via STS AssumeRole!');
      } else {
        setErrorMessage(res.test_result?.error || 'AWS STS AssumeRole requires configuration. Verify trust policy.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to connect AWS account.');
    }
  };

  const handleSync = async () => {
    setIsSyncing(true);
    setErrorMessage(null);
    try {
      const res = await api.syncAws();
      setSyncResult(res);
      setSuccessMessage(`Sync complete: ${res.cloudtrail_events_count} CloudTrail events and ${res.security_hub_findings_count} Security Hub findings evaluated.`);
      fetchStatus();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to sync AWS telemetry.');
    } finally {
      setIsSyncing(false);
    }
  };

  const isConnected = integration?.status === 'CONNECTED';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-tight">AWS Cloud Security</h1>
            {isConnected ? (
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> CONNECTED
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> NOT CONNECTED / CONFIGURATION REQUIRED
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-account AWS posture, CloudTrail management telemetry, and Security Hub findings ingestion.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isConnected && (
            <button
              onClick={handleSync}
              disabled={isSyncing}
              className="px-3.5 py-2 rounded-xl bg-red-600/20 border border-red-500/40 text-red-400 hover:bg-red-500/30 text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>{isSyncing ? 'Syncing...' : 'Sync AWS Findings'}</span>
            </button>
          )}
          <button
            onClick={fetchStatus}
            className="p-2 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Messages */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}
      {successMessage && (
        <div className="p-4 rounded-xl bg-green-500/10 border border-green-500/30 text-green-400 text-xs flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Top Posture Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Cloud Provider</span>
          <div className="text-lg font-bold text-white mt-1">Amazon Web Services</div>
          <span className="text-[11px] text-slate-400">STS AssumeRole</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Security Hub Findings</span>
          <div className="text-lg font-bold text-red-400 mt-1 font-mono">{integration?.findings_count || 0}</div>
          <span className="text-[11px] text-slate-400">Tracked security alerts</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Audited Regions</span>
          <div className="text-lg font-bold text-white mt-1 font-mono">{regions.length}</div>
          <span className="text-[11px] text-slate-400">{regions.join(', ')}</span>
        </div>

        <div className="p-4 rounded-xl bg-carbon-900 border border-red-950/60 shadow-sm">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Least-Privilege Mode</span>
          <div className="text-lg font-bold text-green-400 mt-1">Read-Only Audit</div>
          <span className="text-[11px] text-slate-400">No write credentials</span>
        </div>
      </div>

      {/* AWS Connection & IAM Configuration Card */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Cloud className="w-4 h-4 text-red-400" />
            <span>AWS Account Connection Wizard</span>
          </h2>
          <p className="text-xs text-slate-400">
            Configure cross-account IAM role trust using AWS STS. This enables secure, temporary credential rotation without storing static keys.
          </p>

          <form onSubmit={handleConnect} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                AWS Account ID *
              </label>
              <input
                type="text"
                placeholder="12-digit AWS Account ID"
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                IAM Role ARN *
              </label>
              <input
                type="text"
                placeholder="arn:aws:iam::123456789012:role/AIShieldSecurityAuditRole"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-white"
              />
            </div>

            <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl">
              <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider block">
                Required External ID (STS Boundary Condition)
              </span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-xs font-mono text-white select-all">{integration?.external_id || 'Generating...'}</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(integration?.external_id || '', 'extid')}
                  className="px-2 py-1 bg-carbon-900 border border-slate-800 rounded text-[11px] text-slate-300 hover:text-white"
                >
                  {copiedKey === 'extid' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-xs shadow-md shadow-red-600/30 transition-all cursor-pointer"
            >
              Verify & Save AWS Connection
            </button>
          </form>
        </div>

        {/* IAM Trust Policy Preview */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-red-400" />
              <span>Customer IAM Role Trust Policy</span>
            </h2>
            <button
              onClick={() => copyToClipboard(JSON.stringify(trustPolicy, null, 2), 'policy')}
              className="px-2.5 py-1 rounded-lg bg-carbon-950 border border-slate-800 text-xs text-slate-300 hover:text-white flex items-center gap-1.5"
            >
              {copiedKey === 'policy' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'policy' ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          <p className="text-xs text-slate-400">
            Paste this Trust Policy into your AWS IAM Role in the AWS Console to authorize AI Shield:
          </p>

          <pre className="p-4 bg-carbon-950 border border-slate-800 rounded-xl text-[11px] font-mono text-red-300 overflow-x-auto max-h-64 select-all">
            {trustPolicy ? JSON.stringify(trustPolicy, null, 2) : 'Loading policy...'}
          </pre>

          <div className="p-3 bg-red-950/20 border border-red-500/20 rounded-xl text-[11px] text-slate-400 leading-relaxed">
            <span className="font-semibold text-red-400">Security Guarantee: </span>
            Temporary sessions expire within 3,600 seconds. Root credentials and secret keys are never requested or stored.
          </div>
        </div>
      </div>

      {/* Sync Feed Display */}
      {syncResult && (
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-red-400" />
            <span>Latest AWS Live Telemetry Ingestion</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="text-xs font-bold text-slate-300 block mb-2">Recent CloudTrail Management Events</span>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {syncResult.cloudtrail_events?.map((ev: any, idx: number) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-carbon-950 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between font-semibold text-white">
                      <span>{ev.event_name}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{ev.event_time?.slice(11, 19)}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">Actor: {ev.username} • Source: {ev.event_source}</div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <span className="text-xs font-bold text-slate-300 block mb-2">Security Hub Findings</span>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {syncResult.security_hub_findings?.map((f: any, idx: number) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-carbon-950 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between font-semibold text-red-400">
                      <span>{f.title}</span>
                      <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-red-500/20">{f.severity}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">{f.description?.slice(0, 80)}...</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
