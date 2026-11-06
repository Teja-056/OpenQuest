import React, { useState, useEffect } from 'react';
import {
  FolderLock,
  Share2,
  FileText,
  AlertTriangle,
  ExternalLink,
  ShieldCheck,
  Search
} from 'lucide-react';
import { SecurityEvent } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const FilesSharing: React.FC = () => {
  const [fileEvents, setFileEvents] = useState<SecurityEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [destinationFilter, setDestinationFilter] = useState('all');

  const fetchFileEvents = async () => {
    setIsLoading(true);
    setFetchError(null);
    try {
      const events = await api.getEvents({ limit: 100 });
      const list = Array.isArray(events) ? events : [];
      const filtered = list.filter(e =>
        ['file_share', 'file_sharing', 'file_access', 'file_download', 'data_export'].includes(e.event_type) ||
        (e.resource && (e.resource.includes('.') || e.resource.includes('/')))
      );
      setFileEvents(filtered);
    } catch (err: any) {
      console.error('Failed to load file events:', err);
      setFetchError(err.message || 'Telemetry connection failed');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFileEvents();
  }, []);

  const displayedEvents = (fileEvents || []).filter(e => {
    const term = searchTerm.toLowerCase();
    const res = (e.resource || '').toLowerCase();
    const act = (e.actor_id || '').toLowerCase();
    const dest = (e.destination || '').toLowerCase();
    const matchesSearch = res.includes(term) || act.includes(term) || dest.includes(term);
    if (!matchesSearch) return false;

    const isExternal = Boolean(e.destination && !['internal', 'local', 'corp', ''].includes(dest));
    if (destinationFilter === 'external') return isExternal;
    if (destinationFilter === 'internal') return !isExternal;
    return true;
  });

  const externalCount = (fileEvents || []).filter(e => e.destination && !['internal', 'local', 'corp', ''].includes(e.destination.toLowerCase())).length;
  const sensitiveCount = (fileEvents || []).filter(e => e.is_sensitive).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FolderLock className="w-5 h-5 text-red-500" />
            Files & Data Sharing Activity
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Monitoring data movement, external file transfers, and confidential file access across SME workflows.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search resource or employee..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-60"
            />
          </div>

          <select
            value={destinationFilter}
            onChange={(e) => setDestinationFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Destinations</option>
            <option value="external">External Only</option>
            <option value="internal">Internal Only</option>
          </select>
        </div>
      </div>

      {/* Quick Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Total File Operations</p>
            <h4 className="text-xl font-bold text-slate-100 font-mono mt-0.5">{fileEvents.length}</h4>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-red-600/15 text-red-400 border border-red-500/30">
            <ExternalLink className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">External Transfers</p>
            <h4 className="text-xl font-bold text-red-400 font-mono mt-0.5">{externalCount}</h4>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gradient-to-br from-[#140e15] to-[#070508] border border-red-950/60 flex items-center gap-4 shadow-lg">
          <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-slate-400 uppercase font-semibold">Sensitive Assets Involved</p>
            <h4 className="text-xl font-bold text-amber-400 font-mono mt-0.5">{sensitiveCount}</h4>
          </div>
        </div>
      </div>

      {/* File Activity Table */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-3 px-4">File / Asset</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Destination Target</th>
                <th className="py-3 px-4">Risk Severity</th>
                <th className="py-3 px-4">Rule Decision</th>
                <th className="py-3 px-4">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    Loading file transfer telemetry from repository...
                  </td>
                </tr>
              ) : fetchError && fileEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-amber-400 font-sans">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <p>Unable to load file sharing telemetry ({fetchError})</p>
                      <button
                        onClick={fetchFileEvents}
                        className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow"
                      >
                        Retry Loading Files
                      </button>
                    </div>
                  </td>
                </tr>
              ) : displayedEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    <div className="flex flex-col items-center justify-center gap-1">
                      <p>No matching file transfer events found.</p>
                      {(searchTerm || destinationFilter !== 'all') && (
                        <button
                          onClick={() => { setSearchTerm(''); setDestinationFilter('all'); }}
                          className="text-xs text-red-400 hover:underline mt-1"
                        >
                          Clear active search and filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                displayedEvents.map((ev) => {
                  const isExt = ev.destination && !['internal', 'local', 'corp', ''].includes(ev.destination.toLowerCase());
                  return (
                    <tr key={ev.event_id} className="hover:bg-red-950/20 transition-colors">
                      <td className="py-3 px-4 text-slate-200 font-medium max-w-xs truncate flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span>{ev.resource}</span>
                      </td>
                      <td className="py-3 px-4 font-sans">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          ev.is_sensitive ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {ev.is_sensitive ? 'CONFIDENTIAL' : 'INTERNAL'}
                        </span>
                      </td>
                      <td className="py-3 px-4 uppercase text-[11px] text-slate-300 font-bold">{ev.action}</td>
                      <td className="py-3 px-4 font-sans text-slate-300">{ev.actor_id}</td>
                      <td className="py-3 px-4 font-sans">
                        <span className={`flex items-center gap-1.5 text-xs ${isExt ? 'text-red-400 font-semibold' : 'text-slate-400'}`}>
                          {isExt ? <AlertTriangle className="w-3.5 h-3.5 text-red-400" /> : <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                          <span className="truncate max-w-xs">{ev.destination || 'internal'}</span>
                        </span>
                      </td>
                      <td className="py-3 px-4 font-sans">
                        <SeverityBadge severity={ev.risk_level} />
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs">{ev.rule_result}</td>
                      <td className="py-3 px-4 text-slate-500 text-[11px]">
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
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
