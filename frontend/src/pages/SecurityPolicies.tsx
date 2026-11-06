import React, { useState, useEffect } from 'react';
import {
  FileCode,
  Shield,
  CheckCircle2,
  Lock,
  Sliders,
  AlertTriangle,
  RefreshCw
} from 'lucide-react';
import { SecurityPolicy } from '../types';
import { api } from '../services/api';

export const SecurityPolicies: React.FC = () => {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Baseline enterprise policies fallback
  const defaultPolicies: SecurityPolicy[] = [
    {
      policy_id: 'POL-DLP-001',
      policy_name: 'Prohibit External Sharing of Restricted Data',
      policy_type: 'DLP',
      description: 'Strictly blocks transmission of files tagged CONFIDENTIAL or RESTRICTED to personal email domains or public cloud links.',
      rules: {
        prohibited_destinations: ['personal_email', 'public_dropbox', 'google_drive', 'mega.nz'],
        restricted_keywords: ['payroll', 'customer_pii', 'keys', 'secrets'],
        enforcement_action: 'quarantine_attachment_and_notify_manager'
      },
      is_active: true,
      severity: 'critical'
    },
    {
      policy_id: 'POL-AGENT-002',
      policy_name: 'AI Agent Least-Privilege & Boundary Enforcement',
      policy_type: 'AGENT_ACCESS',
      description: 'Denies autonomous agent access to administrative credentials, production secrets, or salary records by default.',
      rules: {
        denied_by_default: true,
        prohibited_resources: ['/admin/keys', 'payroll', 'credentials', '.env'],
        max_violations_before_suspension: 3,
        auto_isolate: true
      },
      is_active: true,
      severity: 'critical'
    },
    {
      policy_id: 'POL-RATE-003',
      policy_name: 'API Sliding-Window Threat Protection',
      policy_type: 'API_RATE_LIMIT',
      description: 'Limits client burst requests to prevent automated brute force, data scraping, and denial of service.',
      rules: {
        burst_limit_per_minute: 30,
        lockout_duration_seconds: 120,
        brute_force_threshold_attempts: 5
      },
      is_active: true,
      severity: 'high'
    },
    {
      policy_id: 'POL-CLASSIFY-004',
      policy_name: 'Autonomous Data Classification Standards',
      policy_type: 'DATA_CLASSIFICATION',
      description: 'Defines 4-tier data classification hierarchy (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED).',
      rules: {
        tiers: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'],
        pii_patterns: ['PAN', 'Aadhaar', 'Credit_Card_Luhn', 'API_Keys', 'Plaintext_Passwords']
      },
      is_active: true,
      severity: 'medium'
    },
    {
      policy_id: 'POL-RULE4-005',
      policy_name: 'Rule 4 Strict Enforcement Override',
      policy_type: 'RULE_ENFORCEMENT',
      description: 'Deterministic security policy and agent boundaries strictly override machine learning risk downgrades.',
      rules: {
        ml_override_denial_permitted: false,
        forced_hard_denial_risk_floor: 85.0,
        auto_quarantine_on_critical: true
      },
      is_active: true,
      severity: 'critical'
    }
  ];

  const fetchPolicies = async () => {
    setIsLoading(true);
    try {
      const data = await api.getPolicies();
      if (Array.isArray(data) && data.length > 0) {
        setPolicies(data);
      } else {
        setPolicies(defaultPolicies);
      }
    } catch (err) {
      setPolicies(defaultPolicies);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileCode className="w-5 h-5 text-red-500" />
            Active Security Policies & Rule Definitions
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Configurable rule constraints enforced across the Central Pipeline, DLP Scanner, and Agent Guard.
          </p>
        </div>

        <button
          onClick={fetchPolicies}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-carbon-800 hover:bg-carbon-700 text-slate-300 text-xs font-semibold border border-red-950/60 hover:border-red-500/40 transition-all shadow-sm"
        >
          <RefreshCw className="w-3.5 h-3.5 text-red-400" />
          <span>Reload Policies</span>
        </button>
      </div>

      {/* Policies Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {policies.map((pol) => {
          const parsedRules = typeof pol.rules === 'string'
            ? (() => { try { return JSON.parse(pol.rules); } catch { return pol.rules; } })()
            : pol.rules;

          return (
            <div
              key={pol.policy_id}
              className="p-5 rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 space-y-3 flex flex-col justify-between shadow-xl hover:border-red-500/40 transition-all group"
            >
              <div>
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-100 group-hover:text-red-300 transition-colors">{pol.policy_name}</h4>
                    <span className="text-[10px] text-red-400 font-mono font-bold">{pol.policy_id} | Type: {pol.policy_type}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    pol.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                    pol.severity === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  }`}>
                    {pol.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mt-2 leading-relaxed font-sans">
                  {pol.description}
                </p>

                {/* Rules JSON snippet */}
                <div className="mt-3 p-3 rounded-lg bg-[#0e0a10] border border-red-950/60 font-mono text-[11px] text-slate-300 shadow-inner">
                  <span className="text-red-400 text-[10px] uppercase font-bold block mb-1">Enforced Constraints:</span>
                  <pre className="whitespace-pre-wrap leading-tight text-slate-300">
                    {JSON.stringify(parsedRules, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="pt-3 border-t border-carbon-800 flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Policy Enforced in Pipeline</span>
                </span>
                <span className="text-[10px] text-slate-500 font-mono">Immutable Rule</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
