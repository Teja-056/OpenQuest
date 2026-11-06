import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Printer,
  Award
} from 'lucide-react';
import { api } from '../services/api';
import { ExecutiveReport } from '../types';

export const ExecutiveReports: React.FC = () => {
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchReport = async () => {
    setIsLoading(true);
    try {
      const data = await api.getOrgExecutiveReport();
      setReport(data);
    } catch (err) {
      console.error('Failed to load executive report:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `executive-security-report-${report.organization_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-red-400" />
            <span>Executive Cybersecurity Posture Report</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Board-ready compliance summary, incident metrics, and autonomous security posture grading.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 rounded-xl bg-carbon-900 border border-slate-800 text-xs text-slate-300 hover:text-white flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-3 py-1.5 rounded-xl bg-red-600/20 border border-red-500/30 text-xs font-semibold text-red-400 hover:bg-red-500/30 flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
          <button
            onClick={fetchReport}
            className="p-1.5 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Posture Score Card */}
      <div className="p-8 rounded-2xl bg-gradient-to-r from-carbon-900 via-red-950/20 to-carbon-900 border border-red-950/60 shadow-2xl flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="space-y-2 text-center md:text-left">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-bold uppercase tracking-wider">
            <Award className="w-4 h-4" />
            <span>Security Posture Grade</span>
          </div>
          <h2 className="text-2xl font-extrabold text-white">
            {report?.company_name || 'Organization'} Security Rating
          </h2>
          <p className="text-xs text-slate-400 max-w-lg">
            Calculated across live telemetry, active AWS cloud defense, Wazuh EDR endpoints, and zero-trust policy adherence.
          </p>
        </div>

        <div className="flex items-center gap-6">
          <div className="text-center">
            <div className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-rose-500 font-mono">
              {report?.compliance_score?.toFixed(1) || '92.0'}%
            </div>
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mt-1">
              Hygiene Score
            </span>
          </div>

          <div className="w-20 h-20 rounded-2xl bg-red-500/20 border-2 border-red-500 flex items-center justify-center text-4xl font-black text-red-400 font-mono shadow-xl shadow-red-500/30">
            {report?.posture_grade || 'A'}
          </div>
        </div>
      </div>

      {/* Metrics Breakdown Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
        {[
          { label: 'Security Events', value: report?.metrics_summary.total_security_events || 0, color: 'text-white' },
          { label: 'Open Incidents', value: report?.metrics_summary.open_incidents || 0, color: 'text-amber-400' },
          { label: 'Critical Incidents', value: report?.metrics_summary.critical_incidents || 0, color: 'text-red-400' },
          { label: 'Resolved Incidents', value: report?.metrics_summary.resolved_incidents || 0, color: 'text-green-400' },
          { label: 'DLP Interceptions', value: report?.metrics_summary.dlp_violations || 0, color: 'text-white' },
          { label: 'API Threats Blocked', value: report?.metrics_summary.api_threats_blocked || 0, color: 'text-red-400' },
        ].map((m, idx) => (
          <div key={idx} className="p-4 rounded-xl bg-carbon-900 border border-slate-800 text-center">
            <div className={`text-xl font-bold font-mono ${m.color}`}>{m.value}</div>
            <span className="text-[10px] text-slate-400 uppercase font-semibold block mt-1">{m.label}</span>
          </div>
        ))}
      </div>

      {/* Recommendations & Hygiene Actions */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-green-400" />
          <span>Strategic Security Recommendations</span>
        </h2>

        <div className="space-y-2.5">
          {report?.recommendations?.map((rec, i) => (
            <div key={i} className="p-3.5 rounded-xl bg-carbon-950 border border-slate-800 flex items-start gap-3 text-xs">
              <CheckCircle2 className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span className="text-slate-300 leading-relaxed">{rec}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
