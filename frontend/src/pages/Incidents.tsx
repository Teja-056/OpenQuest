import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  UserCheck,
  ShieldCheck,
  FileText
} from 'lucide-react';
import { SecurityIncident, Severity } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { Modal } from '../components/common/Modal';

interface IncidentsProps {
  initialIncidentId?: string | null;
}

export const Incidents: React.FC<IncidentsProps> = ({ initialIncidentId }) => {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [isUpdating, setIsUpdating] = useState(false);

  const fetchIncidents = async () => {
    setIsLoading(true);
    setFetchError(null);
    try {
      const params: any = {};
      if (severityFilter !== 'all') params.severity = severityFilter;
      if (statusFilter !== 'all') params.status = statusFilter;
      const data = await api.getIncidents(params);
      if (Array.isArray(data)) {
        setIncidents(data);
      }

      if (initialIncidentId && Array.isArray(data)) {
        const found = data.find(i => i.incident_id === initialIncidentId);
        if (found) setSelectedIncident(found);
      }
    } catch (err: any) {
      console.error('Failed to load incidents:', err);
      setFetchError(err.message || 'Connection failed');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [severityFilter, statusFilter]);

  const handleUpdateStatus = async (newStatus: string) => {
    if (!selectedIncident) return;
    setIsUpdating(true);
    try {
      const updated = await api.updateIncident(selectedIncident.incident_id, { status: newStatus });
      setSelectedIncident(updated);
      setIncidents(prev => prev.map(inc => inc.incident_id === updated.incident_id ? updated : inc));
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleAssignAnalyst = async (analystName: string) => {
    if (!selectedIncident) return;
    setIsUpdating(true);
    try {
      const updated = await api.updateIncident(selectedIncident.incident_id, { assigned_to: analystName });
      setSelectedIncident(updated);
      setIncidents(prev => prev.map(inc => inc.incident_id === updated.incident_id ? updated : inc));
    } catch (err: any) {
      alert(`Failed to assign incident: ${err.message}`);
    } finally {
      setIsUpdating(false);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch =
      inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inc.actor_id && inc.actor_id.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            Security Incident Management
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Automated incident lifecycle: investigation, analyst assignment, and explainability.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search incidents or actors..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-56"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assigned To</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    Loading security incidents from Supabase PostgreSQL...
                  </td>
                </tr>
              ) : fetchError && incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-amber-400 font-sans">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <p>Unable to connect to telemetry service ({fetchError})</p>
                      <button
                        onClick={fetchIncidents}
                        className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow"
                      >
                        Retry Loading Incidents
                      </button>
                    </div>
                  </td>
                </tr>
              ) : filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    <div className="flex flex-col items-center justify-center gap-1">
                      <p>No matching incidents found.</p>
                      {(searchTerm || severityFilter !== 'all' || statusFilter !== 'all') && (
                        <button
                          onClick={() => { setSearchTerm(''); setSeverityFilter('all'); setStatusFilter('all'); }}
                          className="text-xs text-red-400 hover:underline mt-1"
                        >
                          Clear active search and filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((incident) => (
                  <tr key={incident.incident_id} className="hover:bg-red-950/20 transition-colors">
                    <td className="py-3 px-4 text-red-400 font-bold">{incident.incident_id}</td>
                    <td className="py-3 px-4 font-sans text-slate-200 max-w-sm truncate font-medium">
                      {incident.title}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{incident.actor_id || 'N/A'}</td>
                    <td className="py-3 px-4 font-sans">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`inline-flex px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                        incident.status === 'open' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                        incident.status === 'investigating' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                        'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      }`}>
                        {incident.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-sans">
                      {incident.assigned_to ? (
                        <span className="flex items-center gap-1 text-slate-300">
                          <UserCheck className="w-3.5 h-3.5 text-red-400" />
                          {incident.assigned_to}
                        </span>
                      ) : (
                        <span className="text-slate-500 italic">Unassigned</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-500 text-[11px]">
                      {new Date(incident.created_at).toLocaleDateString()} {new Date(incident.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedIncident(incident)}
                        className="px-3 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 font-sans text-xs font-semibold transition-all shadow-sm shadow-red-950/40"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Investigation Modal / Drawer */}
      {selectedIncident && (
        <Modal
          isOpen={Boolean(selectedIncident)}
          onClose={() => setSelectedIncident(null)}
          title={`Investigation: ${selectedIncident.incident_id}`}
          maxWidth="max-w-3xl"
        >
          <div className="space-y-5 text-xs">
            {/* Incident Header Info */}
            <div className="p-4 rounded-xl bg-[#140e15] border border-red-950/70 flex items-start justify-between">
              <div>
                <h4 className="text-sm font-bold text-slate-100">{selectedIncident.title}</h4>
                <p className="text-slate-400 mt-1 font-mono">Related Event: {selectedIncident.event_id || 'Direct Ingestion'}</p>
              </div>
              <div className="flex flex-col items-end gap-1.5">
                <SeverityBadge severity={selectedIncident.severity} />
                <span className="text-[10px] text-slate-500 font-mono">
                  Created: {new Date(selectedIncident.created_at).toLocaleString()}
                </span>
              </div>
            </div>

            {/* 8-Part Structured Explanation Breakdown */}
            <div className="p-4 rounded-xl bg-[#0e0a10] border border-red-950/60 space-y-3">
              <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-[11px]">
                <FileText className="w-4 h-4" />
                Deterministic Explainability Summary
              </div>
              <pre className="p-3.5 rounded-lg bg-[#070508] border border-red-950/50 text-slate-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed overflow-x-auto">
                {selectedIncident.description}
              </pre>
            </div>

            {/* Analyst Controls & Status Transitions */}
            <div className="p-4 rounded-xl bg-[#140e15] border border-red-950/70 space-y-3">
              <h5 className="font-bold text-slate-200">Incident Remediation Actions</h5>
              <div className="flex flex-wrap items-center justify-between gap-3">
                {/* Status Transitions */}
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Set Status:</span>
                  <button
                    disabled={isUpdating || selectedIncident.status === 'investigating'}
                    onClick={() => handleUpdateStatus('investigating')}
                    className="px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 disabled:opacity-50"
                  >
                    Investigating
                  </button>
                  <button
                    disabled={isUpdating || selectedIncident.status === 'resolved'}
                    onClick={() => handleUpdateStatus('resolved')}
                    className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 disabled:opacity-50"
                  >
                    Resolve Incident
                  </button>
                  <button
                    disabled={isUpdating || selectedIncident.status === 'false_positive'}
                    onClick={() => handleUpdateStatus('false_positive')}
                    className="px-2.5 py-1 rounded bg-carbon-800 text-slate-300 hover:bg-carbon-700 disabled:opacity-50 border border-red-950/50"
                  >
                    False Positive
                  </button>
                </div>

                {/* Assignment */}
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Assign:</span>
                  <button
                    disabled={isUpdating}
                    onClick={() => handleAssignAnalyst('alice.chen')}
                    className="px-2.5 py-1 rounded bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25"
                  >
                    Alice Chen
                  </button>
                  <button
                    disabled={isUpdating}
                    onClick={() => handleAssignAnalyst('sec_analyst')}
                    className="px-2.5 py-1 rounded bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25"
                  >
                    Lead Analyst
                  </button>
                </div>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
