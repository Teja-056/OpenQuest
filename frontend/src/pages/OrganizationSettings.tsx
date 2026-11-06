import React, { useState, useEffect } from 'react';
import {
  Settings,
  Building,
  KeyRound,
  Shield,
  RefreshCw,
  Copy,
  Check,
  CheckCircle2,
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import { OrganizationProfile, AuditLog } from '../types';

export const OrganizationSettings: React.FC = () => {
  const [profile, setProfile] = useState<OrganizationProfile | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [name, setName] = useState('');
  const [ownerName, setOwnerName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [industry, setIndustry] = useState('Technology');
  const [country, setCountry] = useState('United States');
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [profData, logsData] = await Promise.all([
        api.getOrgProfile().catch(() => null),
        api.getOrgAuditLogs(50).catch(() => []),
      ]);
      if (profData) {
        setProfile(profData);
        setName(profData.name || '');
        setOwnerName(profData.owner_name || '');
        setEmail(profData.email || '');
        setPhone(profData.phone || '');
        setIndustry(profData.industry || 'Technology');
        setCountry(profData.country || 'United States');
      }
      setAuditLogs(logsData);
    } catch (err) {
      console.error('Failed to load organization settings:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSuccessMessage(null);
    try {
      const updated = await api.updateOrgProfile({
        name,
        owner_name: ownerName,
        email,
        phone,
        industry,
        country,
      });
      setProfile(updated);
      setSuccessMessage('Organization profile settings updated successfully.');
      setTimeout(() => setSuccessMessage(null), 3000);
      fetchData();
    } catch (err: any) {
      console.error('Failed to update profile:', err);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Settings className="w-5 h-5 text-red-400" />
            <span>Organization Settings & Compliance Audit Log</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage your company profile, tenant security parameters, and immutable compliance audit trail.
          </p>
        </div>

        <button
          onClick={fetchData}
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

      {/* Tenant Identity Callout */}
      <div className="p-4 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
              Unique Tenant Organization ID
            </span>
            <span className="text-sm font-mono font-bold text-white">
              {profile?.organization_id || 'org_default'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30">
            TIER: {profile?.subscription_tier || 'STARTER'}
          </span>
          <button
            onClick={() => copyToClipboard(profile?.organization_id || '', 'orgid')}
            className="px-3 py-1 bg-carbon-950 border border-slate-800 rounded-lg text-xs text-slate-300 hover:text-white flex items-center gap-1.5"
          >
            {copiedKey === 'orgid' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'orgid' ? 'Copied' : 'Copy Org ID'}</span>
          </button>
        </div>
      </div>

      {/* Edit Profile Form */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Building className="w-4 h-4 text-red-400" />
          <span>Company Profile Information</span>
        </h2>

        <form onSubmit={handleSaveProfile} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Company Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Owner / Administrator Name</label>
              <input
                type="text"
                value={ownerName}
                onChange={(e) => setOwnerName(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Business Contact Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Phone Number</label>
              <input
                type="text"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Industry</label>
              <input
                type="text"
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Country Headquarters</label>
              <input
                type="text"
                value={country}
                onChange={(e) => setCountry(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSaving}
              className="px-5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white transition-all cursor-pointer disabled:opacity-50"
            >
              {isSaving ? 'Saving Changes...' : 'Save Profile Changes'}
            </button>
          </div>
        </form>
      </div>

      {/* Immutable Audit Log Table */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <FileText className="w-4 h-4 text-red-400" />
          <span>Tenant Security Audit Trail (Compliance Log)</span>
        </h2>

        {auditLogs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No audit logs recorded yet. Administrative changes and tenant logins will be logged here.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[10px] tracking-wider font-sans">
                  <th className="pb-3">Timestamp</th>
                  <th className="pb-3">Actor</th>
                  <th className="pb-3">Action</th>
                  <th className="pb-3">Target Resource</th>
                  <th className="pb-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-[11px]">
                {auditLogs.map((log) => (
                  <tr key={log.log_id} className="hover:bg-carbon-950/60 transition-colors">
                    <td className="py-2.5 text-slate-400">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="py-2.5 text-white font-bold">{log.actor_email || log.actor_id}</td>
                    <td className="py-2.5 text-red-400 font-bold">{log.action}</td>
                    <td className="py-2.5 text-slate-300 font-sans">{log.resource}</td>
                    <td className="py-2.5 text-slate-400 font-sans">{log.details}</td>
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
