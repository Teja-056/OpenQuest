import React, { useState, useEffect } from 'react';
import {
  Shield,
  Cloud,
  Cpu,
  CreditCard,
  CheckCircle2,
  Copy,
  Check,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Server,
  FileText,
  KeyRound,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { OrganizationProfile, CloudIntegration, WazuhIntegration } from '../types';

interface CompanyOnboardingProps {
  organization: OrganizationProfile;
  onComplete: () => void;
}

export const CompanyOnboarding: React.FC<CompanyOnboardingProps> = ({
  organization,
  onComplete,
}) => {
  const [currentStep, setCurrentStep] = useState(1);
  const [isSaving, setIsSaving] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Step 1: Profile & Compliance
  const [industry, setIndustry] = useState(organization.industry || 'Technology');
  const [country, setCountry] = useState(organization.country || 'United States');
  const [employeeCount, setEmployeeCount] = useState(organization.employee_count || 25);
  const [complianceFrameworks, setComplianceFrameworks] = useState<string[]>(['SOC2', 'ISO27001']);

  // Step 2: AWS Cloud Setup
  const [awsAccountId, setAwsAccountId] = useState('');
  const [awsRoleArn, setAwsRoleArn] = useState('');
  const [awsRegions, setAwsRegions] = useState<string[]>(['us-east-1']);
  const [awsExternalId, setAwsExternalId] = useState(`aishield-${organization.organization_id}-sec`);
  const [awsTestStatus, setAwsTestStatus] = useState<'idle' | 'testing' | 'connected' | 'unconfigured' | 'error'>('idle');
  const [awsTestError, setAwsTestError] = useState<string | null>(null);
  const [showTrustPolicyModal, setShowTrustPolicyModal] = useState(false);

  // Step 3: Wazuh EDR
  const [wazuhManagerUrl, setWazuhManagerUrl] = useState('');
  const [wazuhSecret, setWazuhSecret] = useState(`whsec_${organization.organization_id}`);

  // Step 4: Subscription Tier
  const [selectedTier, setSelectedTier] = useState<string>(organization.subscription_tier || 'PROFESSIONAL');

  useEffect(() => {
    // Fetch initial statuses
    api.getAwsStatus().then(res => {
      if (res?.integration) {
        setAwsAccountId(res.integration.account_id || '');
        setAwsRoleArn(res.integration.role_arn || '');
        setAwsExternalId(res.integration.external_id || `aishield-${organization.organization_id}-sec`);
        if (res.integration.status === 'CONNECTED') setAwsTestStatus('connected');
        else if (res.integration.account_id) setAwsTestStatus('unconfigured');
      }
    }).catch(() => {});

    api.getWazuhStatus().then(res => {
      if (res?.integration) {
        setWazuhManagerUrl(res.integration.manager_url || '');
        setWazuhSecret(res.integration.webhook_secret || `whsec_${organization.organization_id}`);
      }
    }).catch(() => {});
  }, [organization.organization_id]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleTestAwsConnection = async () => {
    if (!awsAccountId || !awsRoleArn) {
      setAwsTestStatus('error');
      setAwsTestError('Both 12-digit AWS Account ID and IAM Role ARN are required to test connection.');
      return;
    }
    setAwsTestStatus('testing');
    setAwsTestError(null);
    try {
      const res = await api.connectAws({
        account_id: awsAccountId,
        role_arn: awsRoleArn,
        regions: awsRegions,
      });

      if (res.test_result?.is_connected) {
        setAwsTestStatus('connected');
      } else {
        setAwsTestStatus('unconfigured');
        setAwsTestError(res.test_result?.error || 'AWS STS AssumeRole verification required. Please verify IAM trust policy.');
      }
    } catch (err: any) {
      setAwsTestStatus('error');
      setAwsTestError(err.message || 'Failed to contact AWS STS service.');
    }
  };

  const handleNextStep = async () => {
    setIsSaving(true);
    try {
      if (currentStep === 1) {
        await api.updateOnboarding({
          step: 2,
          industry,
          country,
          employee_count: employeeCount,
        });
        setCurrentStep(2);
      } else if (currentStep === 2) {
        if (awsAccountId && awsRoleArn) {
          await api.updateOnboarding({
            step: 3,
            cloud: {
              account_id: awsAccountId,
              role_arn: awsRoleArn,
              regions: awsRegions,
            },
          });
        }
        setCurrentStep(3);
      } else if (currentStep === 3) {
        if (wazuhManagerUrl) {
          await api.updateOnboarding({
            step: 4,
            endpoint: { manager_url: wazuhManagerUrl },
          });
        }
        setCurrentStep(4);
      } else if (currentStep === 4) {
        await api.updateOnboarding({
          step: 5,
          subscription_tier: selectedTier,
        });
        setCurrentStep(5);
      } else if (currentStep === 5) {
        await api.updateOnboarding({
          step: 5,
          completed: true,
        });
        onComplete();
      }
    } catch (err) {
      console.error('Failed to save onboarding progress:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const trustPolicyJson = JSON.stringify(
    {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::000000000000:root' },
          Action: 'sts:AssumeRole',
          Condition: {
            StringEquals: { 'sts:ExternalId': awsExternalId },
          },
        },
      ],
    },
    null,
    2
  );

  return (
    <div className="min-h-screen bg-carbon-950 text-slate-100 flex flex-col items-center py-10 px-4 sm:px-6 relative font-sans">
      <div className="absolute top-10 left-1/2 -translate-x-1/2 w-[650px] h-[650px] bg-red-600/10 blur-[140px] pointer-events-none rounded-full" />

      {/* Header */}
      <div className="w-full max-w-4xl text-center mb-8 z-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/60 border border-red-500/30 text-red-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Shield className="w-3.5 h-3.5" />
          <span>Tenant Organization Onboarding</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white">
          Configure Your Defense Perimeter for <span className="text-red-400">{organization.name}</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Complete the guided setup to connect AWS cloud monitoring, Wazuh endpoint sensors, and AI threat hunting.
        </p>

        {/* Step Indicator Bar */}
        <div className="flex items-center justify-center gap-2 sm:gap-4 mt-6">
          {[
            { step: 1, label: 'Profile' },
            { step: 2, label: 'Cloud' },
            { step: 3, label: 'Endpoints' },
            { step: 4, label: 'Subscription' },
            { step: 5, label: 'Finish' },
          ].map((item, idx) => {
            const isDone = currentStep > item.step;
            const isCurrent = currentStep === item.step;
            return (
              <React.Fragment key={item.step}>
                <div className="flex items-center gap-2">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
                      isDone
                        ? 'bg-red-500 text-white'
                        : isCurrent
                        ? 'bg-red-950 border border-red-500 text-red-400 shadow-md shadow-red-500/20'
                        : 'bg-carbon-900 border border-slate-800 text-slate-500'
                    }`}
                  >
                    {isDone ? <Check className="w-4 h-4" /> : item.step}
                  </div>
                  <span className={`text-xs font-semibold hidden md:inline ${isCurrent ? 'text-white' : 'text-slate-500'}`}>
                    {item.label}
                  </span>
                </div>
                {idx < 4 && <div className={`w-6 sm:w-12 h-0.5 ${isDone ? 'bg-red-500' : 'bg-slate-800'}`} />}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Main Form Step Box */}
      <div className="w-full max-w-4xl bg-carbon-900/90 border border-red-950/60 rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl shadow-black/80 z-10">
        {/* STEP 1: Profile & Compliance Frameworks */}
        {currentStep === 1 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-red-400" />
                <span>Step 1: Security Scope & Compliance Targets</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Customize data loss prevention (DLP) and policy rules for your company's regulatory standard.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Industry</label>
                <input
                  type="text"
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  className="w-full px-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Country Headquarters</label>
                <input
                  type="text"
                  value={country}
                  onChange={(e) => setCountry(e.target.value)}
                  className="w-full px-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Compliance Frameworks to Audit & Enforce
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {['SOC2 Type II', 'ISO 27001', 'HIPAA', 'PCI-DSS', 'GDPR', 'NIST CSF'].map((fw) => {
                  const isSelected = complianceFrameworks.includes(fw);
                  return (
                    <button
                      type="button"
                      key={fw}
                      onClick={() => {
                        setComplianceFrameworks(prev =>
                          isSelected ? prev.filter(x => x !== fw) : [...prev, fw]
                        );
                      }}
                      className={`p-3 rounded-xl border text-left text-xs font-semibold transition-all ${
                        isSelected
                          ? 'bg-red-500/15 border-red-500 text-white'
                          : 'bg-carbon-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span>{fw}</span>
                        {isSelected && <Check className="w-3.5 h-3.5 text-red-400" />}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* STEP 2: AWS Cloud Infrastructure */}
        {currentStep === 2 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Cloud className="w-5 h-5 text-red-400" />
                  <span>Step 2: Connect AWS Cloud Infrastructure</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Connect using AWS STS AssumeRole with read-only least-privilege. No permanent keys or root access required.
                </p>
              </div>

              <button
                type="button"
                onClick={() => setShowTrustPolicyModal(true)}
                className="px-3 py-1.5 rounded-lg bg-carbon-950 border border-slate-800 hover:border-slate-700 text-xs text-slate-300 flex items-center gap-1.5"
              >
                <KeyRound className="w-3.5 h-3.5 text-red-400" />
                <span>View IAM Trust Policy</span>
              </button>
            </div>

            {/* External ID Callout */}
            <div className="p-4 rounded-xl bg-carbon-950 border border-red-950/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider block">
                  Your Organization External ID (STS Security Boundary)
                </span>
                <span className="text-sm font-mono text-white select-all">{awsExternalId}</span>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(awsExternalId, 'extid')}
                className="px-3 py-1.5 rounded-lg bg-carbon-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white flex items-center gap-1.5"
              >
                {copiedKey === 'extid' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'extid' ? 'Copied' : 'Copy ID'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  AWS Account ID (12 digits) *
                </label>
                <input
                  type="text"
                  placeholder="123456789012"
                  value={awsAccountId}
                  onChange={(e) => setAwsAccountId(e.target.value)}
                  className="w-full px-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  IAM Role ARN *
                </label>
                <input
                  type="text"
                  placeholder="arn:aws:iam::123456789012:role/AIShieldSecurityAuditRole"
                  value={awsRoleArn}
                  onChange={(e) => setAwsRoleArn(e.target.value)}
                  className="w-full px-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white font-mono"
                />
              </div>
            </div>

            {/* Test Connection Button & Result */}
            <div className="p-4 rounded-xl bg-carbon-950/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-200">Connection Status:</span>
                  {awsTestStatus === 'connected' ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> CONNECTED
                    </span>
                  ) : awsTestStatus === 'unconfigured' || awsTestStatus === 'error' ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> CONFIGURATION REQUIRED
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                      NOT TESTED
                    </span>
                  )}
                </div>
                {awsTestError && (
                  <p className="text-[11px] text-amber-400/90 mt-1 max-w-lg leading-relaxed">
                    {awsTestError}
                  </p>
                )}
              </div>

              <button
                type="button"
                onClick={handleTestAwsConnection}
                disabled={awsTestStatus === 'testing'}
                className="px-4 py-2 rounded-xl bg-carbon-900 border border-red-500/40 text-red-400 hover:bg-red-500/10 text-xs font-bold flex items-center gap-2 transition-all cursor-pointer"
              >
                {awsTestStatus === 'testing' ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-red-400/20 border-t-red-400 rounded-full animate-spin" />
                    <span>Verifying STS Role...</span>
                  </>
                ) : (
                  <>
                    <Cloud className="w-3.5 h-3.5" />
                    <span>Test AWS Connection</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* STEP 3: Endpoint Monitoring & Wazuh Setup */}
        {currentStep === 3 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Server className="w-5 h-5 text-red-400" />
                <span>Step 3: Endpoint Monitoring (Wazuh EDR Integration)</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Collect real-time host intrusion alerts, file integrity violations, and rootkit attempts across employee devices and servers.
              </p>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Wazuh Manager Host / IP (Optional if hosted externally)
              </label>
              <input
                type="text"
                placeholder="wazuh-manager.acme.corp:55000"
                value={wazuhManagerUrl}
                onChange={(e) => setWazuhManagerUrl(e.target.value)}
                className="w-full px-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white font-mono"
              />
            </div>

            {/* Ingestion Webhook URL & Secret */}
            <div className="p-4 rounded-xl bg-carbon-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold text-red-400 uppercase tracking-wider block">
                    Organization EDR Webhook Ingestion Endpoint
                  </span>
                  <span className="text-xs font-mono text-slate-300">
                    /api/integrations/wazuh/alert?organization_id={organization.organization_id}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">
                  Organization Webhook Secret (HMAC Signature)
                </span>
                <div className="flex items-center gap-2 mt-1">
                  <input
                    type="text"
                    readOnly
                    value={wazuhSecret}
                    className="flex-1 px-3 py-1.5 bg-carbon-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300"
                  />
                  <button
                    type="button"
                    onClick={() => copyToClipboard(wazuhSecret, 'wsec')}
                    className="px-3 py-1.5 rounded-lg bg-carbon-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white flex items-center gap-1.5"
                  >
                    {copiedKey === 'wsec' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey === 'wsec' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Quick Install Command */}
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-2">
                Linux Agent Installation Command
              </span>
              <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-300 flex items-center justify-between overflow-x-auto">
                <code className="text-[11px] text-red-300 whitespace-nowrap">
                  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add - && sudo apt-get install wazuh-agent
                </code>
                <button
                  type="button"
                  onClick={() => copyToClipboard("curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add - && sudo apt-get install wazuh-agent", 'linuxcmd')}
                  className="ml-3 shrink-0 px-2 py-1 bg-carbon-900 border border-slate-800 rounded text-[11px] text-slate-300"
                >
                  {copiedKey === 'linuxcmd' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 4: Subscription Tier Selection */}
        {currentStep === 4 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <CreditCard className="w-5 h-5 text-red-400" />
                <span>Step 4: Subscription Plan & Enforcement Limits</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Select your service tier. Resource quotas are automatically enforced across endpoints and cloud accounts.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                {
                  id: 'STARTER',
                  name: 'Starter Defense',
                  price: '$49',
                  desc: 'Ideal for small startups',
                  endpoints: '5 Endpoints',
                  cloud: '1 Cloud Account',
                  features: ['Basic event monitoring', 'Incident triage', 'DLP scanner', 'Community support'],
                },
                {
                  id: 'PROFESSIONAL',
                  name: 'Professional SOC',
                  price: '$199',
                  desc: 'Growing teams & compliance',
                  endpoints: '25 Endpoints',
                  cloud: '3 Cloud Accounts',
                  features: ['TypeSafe Jev AI decision support', 'Isolation Forest ML', 'Wazuh EDR deep integration', 'Compliance reports'],
                },
                {
                  id: 'ENTERPRISE',
                  name: 'Enterprise Shield',
                  price: '$499',
                  desc: 'Unrestricted scale & 24/7 SOC',
                  endpoints: 'Unlimited Endpoints',
                  cloud: '50 Cloud Accounts',
                  features: ['Custom ML retraining', 'Agent Guard zero-trust', 'Rule 4 hard override guarantee', 'Dedicated SOC SLAs'],
                },
              ].map((tier) => {
                const isSelected = selectedTier === tier.id;
                return (
                  <div
                    key={tier.id}
                    onClick={() => setSelectedTier(tier.id)}
                    className={`p-5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'bg-red-500/15 border-red-500 shadow-xl shadow-red-500/20'
                        : 'bg-carbon-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-bold text-white">{tier.name}</span>
                        {isSelected && <CheckCircle2 className="w-4 h-4 text-red-400" />}
                      </div>
                      <div className="text-2xl font-extrabold text-white font-mono mb-1">
                        {tier.price}<span className="text-xs text-slate-500 font-normal">/month</span>
                      </div>
                      <p className="text-xs text-slate-400 mb-4">{tier.desc}</p>

                      <div className="space-y-1.5 py-3 border-t border-slate-800/80 text-xs">
                        <div className="font-semibold text-slate-300">• {tier.endpoints}</div>
                        <div className="font-semibold text-slate-300">• {tier.cloud}</div>
                        {tier.features.map((f, i) => (
                          <div key={i} className="text-slate-400 text-[11px]">• {f}</div>
                        ))}
                      </div>
                    </div>

                    <button
                      type="button"
                      className={`w-full mt-4 py-2 rounded-xl text-xs font-bold transition-all ${
                        isSelected
                          ? 'bg-red-600 text-white shadow-md shadow-red-600/30'
                          : 'bg-carbon-900 border border-slate-800 text-slate-300'
                      }`}
                    >
                      {isSelected ? 'Active Selection' : 'Select Plan'}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* STEP 5: Provisioning Confirmation */}
        {currentStep === 5 && (
          <div className="space-y-6 text-center py-4">
            <div className="w-16 h-16 rounded-full bg-red-500/20 border border-red-500 flex items-center justify-center mx-auto text-red-400 shadow-xl shadow-red-500/30">
              <CheckCircle2 className="w-8 h-8" />
            </div>

            <div>
              <h2 className="text-xl font-extrabold text-white">Setup Ready for {organization.name}!</h2>
              <p className="text-xs text-slate-400 mt-2 max-w-md mx-auto">
                Your tenant workspace is isolated with organization ID{' '}
                <span className="font-mono text-red-400 font-bold">{organization.organization_id}</span>.
                The event processing pipeline, ML models, and security rules are initialized.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 max-w-xl mx-auto text-left text-xs">
              <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">AWS Cloud</span>
                <span className="font-bold text-slate-200">
                  {awsTestStatus === 'connected' ? 'Connected' : 'Configuration Required'}
                </span>
              </div>
              <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Wazuh EDR</span>
                <span className="font-bold text-slate-200">
                  {wazuhManagerUrl ? 'Configured' : 'Ready for Agents'}
                </span>
              </div>
              <div className="p-3 bg-carbon-950 border border-slate-800 rounded-xl">
                <span className="text-[10px] text-slate-500 font-bold uppercase block">Subscription</span>
                <span className="font-bold text-red-400">{selectedTier}</span>
              </div>
            </div>
          </div>
        )}

        {/* Footer Navigation Buttons */}
        <div className="mt-8 pt-6 border-t border-slate-800 flex items-center justify-between">
          {currentStep > 1 ? (
            <button
              type="button"
              onClick={() => setCurrentStep(prev => prev - 1)}
              className="px-4 py-2 rounded-xl bg-carbon-950 border border-slate-800 text-xs font-semibold text-slate-400 hover:text-white flex items-center gap-1.5 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back</span>
            </button>
          ) : <div />}

          <button
            type="button"
            onClick={handleNextStep}
            disabled={isSaving}
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-xs shadow-lg shadow-red-600/30 flex items-center gap-2 cursor-pointer transition-all disabled:opacity-50"
          >
            {isSaving ? (
              <span>Saving...</span>
            ) : currentStep === 5 ? (
              <span>Launch Organization Dashboard</span>
            ) : (
              <>
                <span>Continue to {currentStep === 1 ? 'Cloud Setup' : currentStep === 2 ? 'Endpoints' : currentStep === 3 ? 'Subscription' : 'Summary'}</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>

      {/* IAM Trust Policy Modal */}
      {showTrustPolicyModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-carbon-900 border border-red-950/80 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-red-400" />
                <span>AWS IAM Role Trust Policy (Least Privilege)</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowTrustPolicyModal(false)}
                className="text-slate-500 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Attach this trust policy to your AWS IAM role to permit AI Shield to safely assume role using your External ID:
            </p>

            <pre className="p-3 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-red-300 overflow-x-auto select-all">
              {trustPolicyJson}
            </pre>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => copyToClipboard(trustPolicyJson, 'modal_policy')}
                className="px-4 py-2 rounded-xl bg-carbon-950 border border-slate-800 text-xs font-semibold text-slate-200 hover:text-white flex items-center gap-1.5"
              >
                {copiedKey === 'modal_policy' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'modal_policy' ? 'Copied JSON' : 'Copy JSON'}</span>
              </button>
              <button
                type="button"
                onClick={() => setShowTrustPolicyModal(false)}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
