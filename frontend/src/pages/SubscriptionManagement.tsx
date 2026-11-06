import React, { useState, useEffect } from 'react';
import {
  CreditCard,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Zap,
  ArrowRight,
  ShieldCheck,
  Server,
  Cloud
} from 'lucide-react';
import { api } from '../services/api';
import { SubscriptionStatus } from '../types';

export const SubscriptionManagement: React.FC = () => {
  const [subStatus, setSubStatus] = useState<SubscriptionStatus | null>(null);
  const [tiers, setTiers] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchSubscription = async () => {
    setIsLoading(true);
    try {
      const [statusData, tiersData] = await Promise.all([
        api.getSubscription(),
        api.getSubscriptionTiers().catch(() => []),
      ]);
      setSubStatus(statusData);
      setTiers(tiersData);
    } catch (err) {
      console.error('Failed to load subscription:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSubscription();
  }, []);

  const handleUpgrade = async (tierName: string) => {
    setIsUpgrading(true);
    setSuccessMessage(null);
    try {
      await api.upgradeSubscription(tierName);
      setSuccessMessage(`Subscription tier updated to ${tierName} successfully!`);
      await fetchSubscription();
    } catch (err: any) {
      console.error('Failed to upgrade subscription:', err);
    } finally {
      setIsUpgrading(false);
    }
  };

  const currentTier = subStatus?.subscription.tier || 'STARTER';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <CreditCard className="w-5 h-5 text-red-400" />
            <span>Subscription Management & Resource Quotas</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage your organization tier, monitor real-time endpoint & cloud account quotas, and upgrade plans.
          </p>
        </div>

        <button
          onClick={fetchSubscription}
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

      {/* Quota Progress Meters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Endpoints Meter */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Server className="w-5 h-5 text-red-400" />
              <span className="text-sm font-bold text-white">Endpoint Sensors Quota</span>
            </div>
            <span className="text-xs font-mono font-bold text-white">
              {subStatus?.usage.endpoints.current || 0} / {subStatus?.usage.endpoints.max || 5}
            </span>
          </div>

          <div className="w-full h-2.5 bg-carbon-950 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                (subStatus?.usage.endpoints.percentage || 0) >= 90
                  ? 'bg-red-500 shadow-md shadow-red-500/50'
                  : 'bg-gradient-to-r from-red-600 to-rose-500'
              }`}
              style={{ width: `${Math.min(100, subStatus?.usage.endpoints.percentage || 0)}%` }}
            />
          </div>

          <div className="flex justify-between text-[11px] text-slate-400">
            <span>Utilization: {subStatus?.usage.endpoints.percentage || 0}%</span>
            {subStatus?.usage.endpoints.at_limit && (
              <span className="text-amber-400 font-bold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> Quota Reached — Upgrade to add more endpoints
              </span>
            )}
          </div>
        </div>

        {/* Cloud Accounts Meter */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Cloud className="w-5 h-5 text-amber-400" />
              <span className="text-sm font-bold text-white">Cloud Accounts Quota</span>
            </div>
            <span className="text-xs font-mono font-bold text-white">
              {subStatus?.usage.cloud_accounts.current || 0} / {subStatus?.usage.cloud_accounts.max || 1}
            </span>
          </div>

          <div className="w-full h-2.5 bg-carbon-950 rounded-full overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                (subStatus?.usage.cloud_accounts.percentage || 0) >= 90
                  ? 'bg-amber-500 shadow-md shadow-amber-500/50'
                  : 'bg-gradient-to-r from-amber-500 to-red-500'
              }`}
              style={{ width: `${Math.min(100, subStatus?.usage.cloud_accounts.percentage || 0)}%` }}
            />
          </div>

          <div className="flex justify-between text-[11px] text-slate-400">
            <span>Utilization: {subStatus?.usage.cloud_accounts.percentage || 0}%</span>
            {subStatus?.usage.cloud_accounts.at_limit && (
              <span className="text-amber-400 font-bold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> Quota Reached — Upgrade to add more cloud accounts
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Subscription Tiers Selection Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[
          {
            tier: 'STARTER',
            name: 'Starter Defense',
            price: '$49',
            period: '/mo',
            endpoints: '5 Endpoints',
            cloud: '1 Cloud Account',
            desc: 'Foundational security monitoring for startups and pilot teams.',
            features: ['5 Endpoint Sensors', '1 AWS Cloud Account', 'Basic incident management', 'DLP content inspection', 'Community support']
          },
          {
            tier: 'PROFESSIONAL',
            name: 'Professional SOC',
            price: '$199',
            period: '/mo',
            endpoints: '25 Endpoints',
            cloud: '3 Cloud Accounts',
            desc: 'Autonomous threat hunting & EDR integration for growing enterprises.',
            features: ['25 Endpoint Sensors', '3 AWS Cloud Accounts', 'TypeSafe Jev AI decision support', 'Wazuh EDR deep integration', 'Automated executive reports']
          },
          {
            tier: 'ENTERPRISE',
            name: 'Enterprise Shield',
            price: '$499',
            period: '/mo',
            endpoints: 'Unlimited Endpoints',
            cloud: '50 Cloud Accounts',
            desc: 'Uncompromised zero-trust defense with dedicated AI model SLAs.',
            features: ['Unlimited / 1000+ Endpoints', '50 Cloud Accounts', 'Custom ML model retraining', 'Agent Guard zero-trust', 'Rule 4 hard lock guarantee', '24/7 dedicated SOC support']
          }
        ].map((t) => {
          const isCurrent = currentTier === t.tier;
          return (
            <div
              key={t.tier}
              className={`p-6 rounded-2xl border transition-all flex flex-col justify-between ${
                isCurrent
                  ? 'bg-red-500/15 border-red-500 shadow-2xl shadow-red-500/20'
                  : 'bg-carbon-900 border-slate-800'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-bold text-white">{t.name}</span>
                  {isCurrent && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500 text-white">
                      ACTIVE PLAN
                    </span>
                  )}
                </div>

                <div className="text-3xl font-extrabold text-white font-mono mb-1">
                  {t.price}<span className="text-xs text-slate-500 font-normal">{t.period}</span>
                </div>
                <p className="text-xs text-slate-400 mb-4">{t.desc}</p>

                <div className="space-y-2 py-4 border-t border-slate-800/80 text-xs">
                  <div className="font-bold text-slate-200">• {t.endpoints}</div>
                  <div className="font-bold text-slate-200">• {t.cloud}</div>
                  {t.features.map((f, i) => (
                    <div key={i} className="text-slate-400 text-[11px]">• {f}</div>
                  ))}
                </div>
              </div>

              <button
                onClick={() => handleUpgrade(t.tier)}
                disabled={isCurrent || isUpgrading}
                className={`w-full mt-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                  isCurrent
                    ? 'bg-carbon-950 border border-slate-800 text-slate-500 cursor-default'
                    : 'bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white shadow-md shadow-red-600/30'
                }`}
              >
                {isCurrent ? 'Current Plan' : isUpgrading ? 'Updating...' : `Select ${t.name}`}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};
