import React, { useState, useEffect } from 'react';
import {
  EyeOff,
  Search,
  ShieldAlert,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  FolderLock,
  Lock,
  Sparkles
} from 'lucide-react';
import { DLPViolation } from '../types';
import { api } from '../services/api';

export const DlpViolations: React.FC = () => {
  const [violations, setViolations] = useState<DLPViolation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  // Interactive Live Scanner State
  const [testPayload, setTestPayload] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

  const fetchViolations = async () => {
    setIsLoading(true);
    try {
      const data = await api.getDlpViolations();
      setViolations(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Failed to load DLP violations:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchViolations();
  }, []);

  const handleRunInspector = async () => {
    if (!testPayload.trim()) return;
    setIsScanning(true);
    try {
      const res = await api.inspectContent(testPayload, 'interactive_analyst_test_input.txt');
      setScanResult(res);
    } catch (err: any) {
      alert(`Inspection error: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const filteredViolations = (violations || []).filter(v =>
    (v.violation_id || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (v.actor_id || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (v.resource || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (v.destination || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <EyeOff className="w-5 h-5 text-red-500" />
          Data Loss Prevention (DLP) & Quarantine Engine
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Enforces enterprise classifications (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED) and intercepts sensitive PII and secrets.
        </p>
      </div>

      {/* Interactive Content Inspection Sandbox */}
      <div className="p-5 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/70 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-xs">
            <FileSearch className="w-4 h-4" />
            Live DLP Content Scanner Sandbox
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Regex & Pattern Verification Active</span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Test file contents or raw text for sensitive PII (Indian PAN, Aadhaar, Credit Card Luhn verification), API keys, or plaintext passwords.
        </p>

        <div className="space-y-3">
          <textarea
            rows={3}
            placeholder="Paste sample content here (e.g. 'Customer PAN: ABCDE1234F, Aadhaar: 2345 6789 0123, CC: 4532-0150-1234-5671, API Key: AKIAIOSFODNN7EXAMPLE')..."
            value={testPayload}
            onChange={(e) => setTestPayload(e.target.value)}
            className="w-full p-3 rounded-lg bg-[#0e0a10] border border-red-950/60 text-xs text-slate-200 font-mono focus:outline-none focus:border-red-500"
          />

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setTestPayload("Customer PAN: ABCDE1234F, Aadhaar: 2345 6789 0123, CreditCard: 4532-0150-1234-5671, APIKey: AKIAIOSFODNN7EXAMPLE")}
                className="text-[11px] text-red-400 hover:text-red-300 hover:underline flex items-center gap-1 font-mono"
              >
                <Sparkles className="w-3 h-3" />
                <span>Sample PII + API Key</span>
              </button>
            </div>
            <button
              onClick={handleRunInspector}
              disabled={isScanning || !testPayload.trim()}
              className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-semibold text-xs transition-all shadow-lg shadow-red-600/30 border border-red-500/40 disabled:opacity-50 active:scale-95"
            >
              {isScanning ? 'Scanning...' : 'Inspect Content'}
            </button>
          </div>
        </div>

        {/* Scan Results Display */}
        {scanResult && (
          <div className="mt-4 p-4 rounded-lg bg-[#0e0a10] border border-red-950/70 space-y-2 text-xs shadow-inner">
            <div className="flex items-center justify-between border-b border-carbon-800 pb-2">
              <span className="font-bold text-slate-200">Inspection Outcome:</span>
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                scanResult.classification === 'RESTRICTED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                scanResult.classification === 'CONFIDENTIAL' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
              }`}>
                {scanResult.classification}
              </span>
            </div>

            <div className="space-y-1 pt-1 font-mono">
              <p className="text-slate-300">
                Sensitive Patterns Found: <span className="font-bold text-red-400">{scanResult.matches_count}</span>
              </p>
              {scanResult.matches && scanResult.matches.map((m: any, idx: number) => (
                <div key={idx} className="flex items-center gap-2 text-[11px] text-amber-400 pl-2">
                  <span>&bull;</span>
                  <span className="font-bold text-slate-300">{m.pattern}:</span>
                  <span className="text-slate-400">{m.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Recorded Violations Table */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-red-950/60 flex items-center justify-between bg-[#180f1a]">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Recorded DLP Exfiltration Incidents ({violations.length})
            </h3>
            <p className="text-[11px] text-slate-500">Persisted in security repository</p>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search resource or destination..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1 rounded bg-carbon-800 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-56"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-3 px-4">Violation ID</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Asset / Resource</th>
                <th className="py-3 px-4">Destination Target</th>
                <th className="py-3 px-4">Detected Patterns</th>
                <th className="py-3 px-4">Enforcement Action</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    Loading DLP records...
                  </td>
                </tr>
              ) : filteredViolations.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No active DLP policy violations recorded.
                  </td>
                </tr>
              ) : (
                filteredViolations.map((v) => {
                  const patterns = Array.isArray(v.detected_patterns)
                    ? v.detected_patterns
                    : (typeof v.detected_patterns === 'string'
                      ? (() => { try { return JSON.parse(v.detected_patterns); } catch { return []; } })()
                      : []);

                  return (
                    <tr key={v.violation_id} className="hover:bg-red-950/20 transition-colors">
                      <td className="py-3 px-4 text-red-400 font-bold">{v.violation_id}</td>
                      <td className="py-3 px-4 text-slate-300 font-sans">{v.actor_id} ({v.actor_type})</td>
                      <td className="py-3 px-4 font-sans">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          v.classification === 'RESTRICTED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          v.classification === 'CONFIDENTIAL' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {v.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-200 truncate max-w-xs">{v.resource}</td>
                      <td className="py-3 px-4 text-red-400 font-sans font-medium truncate max-w-xs">{v.destination}</td>
                      <td className="py-3 px-4 text-slate-300 text-[11px]">
                        {patterns.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {patterns.map((p: any, idx: number) => (
                              <span key={idx} className="px-1.5 py-0.5 rounded bg-carbon-800 text-amber-300 text-[10px] border border-red-950/40">
                                {typeof p === 'string' ? p : (p.pattern || p.name || p.type || 'PII_PATTERN')}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Sensitive Exfiltration</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs font-sans">
                        {v.action_taken}
                      </td>
                      <td className="py-3 px-4 text-slate-500 text-[11px]">
                        {new Date(v.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
