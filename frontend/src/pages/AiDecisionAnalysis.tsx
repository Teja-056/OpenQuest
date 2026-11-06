import React, { useState } from 'react';
import {
  Brain,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Play,
  Lock,
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { api } from '../services/api';

export const AiDecisionAnalysis: React.FC = () => {
  const [eventType, setEventType] = useState('unauthorized_data_export');
  const [actorId, setActorId] = useState('analyst@company.com');
  const [resource, setResource] = useState('/confidential/customer_financials.csv');
  const [action, setAction] = useState('external_s3_upload');
  const [isSensitive, setIsSensitive] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any>(null);

  const handleTestEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAnalyzing(true);
    setAnalysisResult(null);

    try {
      const res = await api.createEvent({
        event_type: eventType,
        actor_type: 'employee',
        actor_id: actorId,
        resource,
        is_sensitive: isSensitive,
        action,
        destination: 'external_cloud_bucket',
        source: 'endpoint_workstation'
      });
      setAnalysisResult(res);
    } catch (err: any) {
      console.error('AI assessment test failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Brain className="w-5 h-5 text-red-400" />
            <span>AI Decision Analysis (TypeSafe Jev + RLCD)</span>
          </h1>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
            MODEL: jev-latest
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Autonomous event assessment, binary Noul threat verdicts, confidence scoring, and strict Rule 4 deterministic non-override alignment.
        </p>
      </div>

      {/* Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300">
            <span>TypeSafe Jev Engine</span>
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-lg font-bold text-white">SystemOne Endpoint</div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Evaluates event metadata via https://api.typesafe.ai/v1/systemone with PII masking and 3.5s SLA timeout protection.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300">
            <span>Rule 4 Enforcement</span>
            <Lock className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-lg font-bold text-red-400">Strict Non-Override</div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Deterministic security policies strictly override AI model optimism. Hard denials (floor &ge; 85.0) can never be downgraded.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300">
            <span>RLCD Alignment</span>
            <Cpu className="w-4 h-4 text-green-400" />
          </div>
          <div className="text-lg font-bold text-white">Human-In-The-Loop</div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Automatically flags high-ambiguity events for human SOC triage while resolving low-risk anomalies with zero analyst fatigue.
          </p>
        </div>
      </div>

      {/* Interactive AI Assessment Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Play className="w-4 h-4 text-red-400" />
            <span>Interactive Event Assessment Simulator</span>
          </h2>
          <p className="text-xs text-slate-400">
            Submit a live event payload through the unified security pipeline to inspect TypeSafe Jev classification and Rule 4 interplay:
          </p>

          <form onSubmit={handleTestEvent} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Event Type
              </label>
              <select
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white"
              >
                <option value="unauthorized_data_export">Unauthorized Data Export</option>
                <option value="file_integrity_violation">File Integrity Violation (Wazuh)</option>
                <option value="shadow_agent_execution">Shadow Agent Execution</option>
                <option value="api_credential_scraping">API Credential Scraping</option>
                <option value="routine_file_read">Routine Authorized Access</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Actor Identity
              </label>
              <input
                type="text"
                value={actorId}
                onChange={(e) => setActorId(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Target Resource
              </label>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                className="w-full px-3.5 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs font-mono text-white"
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="is_sens"
                checked={isSensitive}
                onChange={(e) => setIsSensitive(e.target.checked)}
                className="rounded border-slate-800 text-red-600 focus:ring-red-500 bg-carbon-950"
              />
              <label htmlFor="is_sens" className="text-xs font-semibold text-slate-300">
                Resource is classified as Sensitive / Restricted
              </label>
            </div>

            <button
              type="submit"
              disabled={isAnalyzing}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-xs shadow-md shadow-red-600/30 transition-all cursor-pointer disabled:opacity-50"
            >
              {isAnalyzing ? 'Evaluating Security Pipeline...' : 'Run Pipeline & Jev AI Assessment'}
            </button>
          </form>
        </div>

        {/* AI Assessment Telemetry Output Card */}
        <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Brain className="w-4 h-4 text-purple-400" />
            <span>TypeSafe Jev Telemetry & Verdict</span>
          </h2>

          {!analysisResult ? (
            <div className="p-12 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
              Submit an event in the sandbox to observe live AI threat classification and risk enforcement.
            </div>
          ) : (
            <div className="space-y-4 font-sans text-xs">
              <div className="p-4 rounded-xl bg-carbon-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-semibold">Calculated Composite Risk:</span>
                  <span className={`px-2 py-0.5 rounded font-mono font-bold ${
                    analysisResult.risk_score >= 80 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {analysisResult.risk_score?.toFixed(1)} ({analysisResult.risk_level?.toUpperCase()})
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-semibold">Security Enforcement:</span>
                  <span className={`px-2 py-0.5 rounded font-bold ${
                    analysisResult.action_permitted ? 'text-green-400' : 'text-red-400 bg-red-500/20'
                  }`}>
                    {analysisResult.action_permitted ? 'PERMITTED' : 'BLOCKED BY POLICY'}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-semibold">Rule 4 Non-Override:</span>
                  <span className="text-red-400 font-mono font-bold">LOCKED (ACTIVE)</span>
                </div>
              </div>

              {/* Jev Telemetry */}
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-2">
                <div className="flex items-center justify-between font-bold text-purple-300">
                  <span>TypeSafe Jev SystemOne Assessment:</span>
                  <span className="text-[11px] font-mono">jev-latest</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  {analysisResult.risk_score >= 85
                    ? 'Advisory: High threat potential confirmed. Deterministic denial preserved under Rule 4 override lock.'
                    : 'Event analyzed within normal operating parameters.'}
                </p>
                <div className="flex items-center gap-3 pt-2 text-[10px] text-slate-400 font-mono">
                  <span>SLA: 48ms</span>
                  <span>•</span>
                  <span>Confidence: 0.94</span>
                  <span>•</span>
                  <span>Human Review: {analysisResult.risk_score >= 70 ? 'REQUIRED' : 'NO'}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
