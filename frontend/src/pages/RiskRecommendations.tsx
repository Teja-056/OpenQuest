import React, { useState, useEffect } from 'react';
import {
  Cpu,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  ArrowRight,
  Calculator,
  Lock,
  UserX,
  Bot,
  Zap,
  Activity
} from 'lucide-react';
import { SecurityIncident, SecurityEvent } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const RiskRecommendations: React.FC = () => {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [highRiskEvents, setHighRiskEvents] = useState<SecurityEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Interactive Risk Calculator Sandbox
  const [hasHardDenial, setHasHardDenial] = useState(true);
  const [mlScore, setMlScore] = useState<number>(15.0);
  const [isSensitive, setIsSensitive] = useState(true);
  const [isExternal, setIsExternal] = useState(true);

  useEffect(() => {
    const fetchRiskData = async () => {
      setIsLoading(true);
      try {
        const [incData, evData] = await Promise.all([
          api.getIncidents().catch(() => []),
          api.getEvents({ limit: 50 }).catch(() => [])
        ]);
        setIncidents(Array.isArray(incData) ? incData : []);
        const filteredEvs = (Array.isArray(evData) ? evData : []).filter(e => (e.risk_score || 0) >= 50);
        setHighRiskEvents(filteredEvs);
      } catch (err) {
        console.error('Failed to load risk telemetry:', err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchRiskData();
  }, []);

  // Compute composite risk adhering strictly to backend risk_engine.py logic
  let computedScore = mlScore;
  let computedLevel = 'low';
  let rule4Triggered = false;

  if (hasHardDenial) {
    computedScore = Math.max(mlScore, 85.0);
    computedLevel = 'critical';
    rule4Triggered = true;
  } else if (mlScore >= 60.0) {
    computedScore = mlScore;
    computedLevel = mlScore >= 80.0 ? 'critical' : 'high';
  } else if (mlScore >= 30.0) {
    computedScore = mlScore;
    computedLevel = 'medium';
  } else {
    computedScore = mlScore;
    computedLevel = 'low';
  }

  const recommendations = [
    {
      code: 'quarantine_attachment_and_notify_manager',
      title: 'Quarantine Attachment & Escalate to Management',
      trigger: 'DLP Violation: Exfiltration of Restricted or Confidential file to external email/cloud.',
      steps: [
        'Move intercepted file to secure quarantine directory.',
        'Invalidate external sharing link or token.',
        'Notify departmental manager and employee compliance officer.'
      ]
    },
    {
      code: 'revoke_agent_token_and_isolate',
      title: 'Revoke Agent Token & Isolate AI System',
      trigger: 'Agent Guard: Autonomous agent exceeded least-privilege boundary or 3 violations.',
      steps: [
        'Instantly invalidate JWT authentication token for agent.',
        'Inspect orchestrator prompt for jailbreak or prompt injection attack.',
        'Require administrator sign-off before reactivation.'
      ]
    },
    {
      code: 'flag_for_analyst_review',
      title: 'Queue for Security Analyst Triage',
      trigger: 'ML Anomaly: Statistical outlier detected during off-hours or unusual activity volume.',
      steps: [
        'Review employee historical activity patterns.',
        'Verify legitimate business reason for off-hours data processing.',
        'Escalate to Tier 2 incident response if suspicious.'
      ]
    },
    {
      code: 'log_sensitive_access',
      title: 'Internal Audit Logging',
      trigger: 'Nominal Access: Authorized employee reading internal sensitive record.',
      steps: [
        'Record immutable audit log in PostgreSQL.',
        'No active disruption to employee workflow.'
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-red-500" />
          Central Risk Engine & Decision Matrix
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Unified scoring framework combining deterministic security policy results, ML anomaly vectors, and SME risk thresholds.
        </p>
      </div>

      {/* Core Principle: Rule 4 Banner */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-3">
        <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
          <Lock className="w-4 h-4 text-red-500" />
          Guaranteed Contractual Constraint: Rule 4 Preservation
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          <span className="font-semibold text-red-400">&ldquo;ML provides an anomaly signal; it must never override a hard security denial.&rdquo;</span>{' '}
          In AI-SHIELD, if a security policy or agent boundary violation is confirmed, the composite risk score is permanently locked to{' '}
          <span className="font-mono font-bold text-red-400">&ge; 85.0 (CRITICAL)</span>, even if statistical anomaly models report a misleadingly low score.
        </p>
      </div>

      {/* Live High-Risk Entities & Incidents Telemetry Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active High-Risk Events */}
        <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-carbon-800 pb-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                Live Elevated Risk Events ({highRiskEvents.length})
              </h3>
              <p className="text-[11px] text-slate-500">Events with composite risk score &ge; 50.0</p>
            </div>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto">
            {isLoading ? (
              <p className="text-xs text-slate-500 text-center py-6">Loading risk telemetry...</p>
            ) : highRiskEvents.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No active high-risk events recorded.</p>
            ) : (
              highRiskEvents.slice(0, 6).map((ev) => (
                <div key={ev.event_id} className="p-3 rounded-lg bg-[#0e0a10] border border-red-950/50 flex items-center justify-between text-xs font-mono">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-red-400 font-bold">{ev.event_id}</span>
                      <span className="text-slate-300 font-sans font-medium">{ev.actor_id} ({ev.actor_type})</span>
                    </div>
                    <p className="text-slate-400 text-[11px] truncate max-w-xs mt-0.5 font-sans">{ev.resource}</p>
                    <span className="text-[10px] text-slate-500 uppercase">{ev.rule_result}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-base font-extrabold text-red-400 font-mono block">{ev.risk_score}</span>
                    <SeverityBadge severity={ev.risk_level} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Active Incident Remediations */}
        <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-carbon-800 pb-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Prescribed Incident Remediations ({incidents.filter(i => i.status !== 'resolved').length})
              </h3>
              <p className="text-[11px] text-slate-500">Remediation actions generated by the decision matrix</p>
            </div>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto">
            {isLoading ? (
              <p className="text-xs text-slate-500 text-center py-6">Loading incident remediations...</p>
            ) : incidents.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No open security incidents requiring remediation.</p>
            ) : (
              incidents.slice(0, 5).map((inc) => (
                <div key={inc.incident_id} className="p-3 rounded-lg bg-[#0e0a10] border border-red-950/50 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-red-400 font-mono font-bold">{inc.incident_id}</span>
                    <SeverityBadge severity={inc.severity} />
                  </div>
                  <h4 className="font-bold text-slate-200 text-xs font-sans truncate">{inc.title}</h4>
                  <div className="flex items-center justify-between text-[11px] pt-1 border-t border-carbon-800">
                    <span className="text-slate-400 font-mono">Actor: {inc.actor_id || 'N/A'}</span>
                    <span className="text-red-400 font-semibold uppercase text-[10px] bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40">
                      Remediate &rarr;
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Interactive Risk Sandbox Calculator */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
            <Calculator className="w-4 h-4" />
            Interactive Composite Risk Sandbox
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Simulate Backend Engine</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* Inputs */}
          <div className="space-y-4 text-xs">
            <div>
              <label className="flex items-center justify-between text-slate-300 font-semibold mb-2">
                <span>Deterministic Hard Denial Triggered:</span>
                <input
                  type="checkbox"
                  checked={hasHardDenial}
                  onChange={(e) => setHasHardDenial(e.target.checked)}
                  className="w-4 h-4 rounded text-red-600 focus:ring-red-500 bg-carbon-800 border-red-950"
                />
              </label>
              <p className="text-[11px] text-slate-500">
                Simulates hard DLP block, agent boundary violation, or path traversal attempt.
              </p>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 font-semibold mb-1">
                <span>Machine Learning Anomaly Score:</span>
                <span className="text-red-400 font-mono font-bold">{mlScore.toFixed(1)}</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                step="1"
                value={mlScore}
                onChange={(e) => setMlScore(parseFloat(e.target.value))}
                className="w-full accent-red-600 bg-carbon-800"
              />
              <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
                <span>0.0 (Nominal)</span>
                <span>30.0 (Medium)</span>
                <span>60.0 (High)</span>
                <span>80.0+ (Critical)</span>
              </div>
            </div>
          </div>

          {/* Computed Output */}
          <div className="p-4 rounded-xl bg-[#0e0a10] border border-red-950/60 flex flex-col justify-between text-xs font-mono shadow-inner">
            <div>
              <span className="text-slate-400 text-[11px] uppercase tracking-wider">Computed Risk Decision:</span>
              <div className="mt-2 flex items-baseline gap-3">
                <span className={`text-3xl font-extrabold ${
                  computedLevel === 'critical' ? 'text-red-400' :
                  computedLevel === 'high' ? 'text-amber-400' :
                  computedLevel === 'medium' ? 'text-yellow-300' : 'text-emerald-400'
                }`}>
                  {computedScore.toFixed(1)}
                </span>
                <span className="text-xs uppercase font-bold text-slate-400">/ 100.0</span>
                <span className={`ml-auto px-2.5 py-1 rounded text-xs uppercase font-bold ${
                  computedLevel === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  computedLevel === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}>
                  {computedLevel}
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-carbon-800 text-[11px] font-sans">
              {rule4Triggered ? (
                <p className="text-amber-400 font-semibold flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 shrink-0 text-red-400" />
                  <span>Rule 4 In Effect: Injected ML score overridden by hard denial.</span>
                </p>
              ) : (
                <p className="text-slate-400">Standard weighted scoring active.</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Actionable Recommendations Matrix */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 p-5 space-y-4 shadow-xl">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Actionable Recommendations Matrix
          </h3>
          <p className="text-[11px] text-slate-500">Prescriptive procedures linked to incident detection outcomes</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {recommendations.map((rec) => (
            <div key={rec.code} className="p-4 rounded-xl bg-[#0e0a10] border border-red-950/50 space-y-2 text-xs">
              <h4 className="font-bold text-slate-200">{rec.title}</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">{rec.trigger}</p>
              <div className="pt-2 border-t border-carbon-800 space-y-1">
                <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider block">Recommended Steps:</span>
                <ul className="list-disc list-inside text-slate-300 space-y-0.5 text-[11px]">
                  {rec.steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
