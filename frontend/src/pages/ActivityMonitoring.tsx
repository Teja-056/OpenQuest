import React, { useState, useEffect } from 'react';
import {
  Activity,
  Search,
  Filter,
  Play,
  CheckCircle,
  AlertCircle,
  FileText,
  Calendar,
  User,
  Shield,
  Radio
} from 'lucide-react';
import { SecurityEvent } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { Modal } from '../components/common/Modal';

export const ActivityMonitoring: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [actorTypeFilter, setActorTypeFilter] = useState('all');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const fetchEvents = async () => {
    setIsLoading(true);
    setFetchError(null);
    try {
      const params: any = { limit: 100 };
      if (actorTypeFilter !== 'all') params.actor_type = actorTypeFilter;
      if (eventTypeFilter !== 'all') params.event_type = eventTypeFilter;
      const data = await api.getEvents(params);
      if (Array.isArray(data)) {
        setEvents(data);
      }
    } catch (err: any) {
      console.error('Failed to load events:', err);
      setFetchError(err.message || 'Telemetry connection error');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [actorTypeFilter, eventTypeFilter]);

  const handleSimulateEvent = async () => {
    setIsSimulating(true);
    try {
      const simEvent: Partial<SecurityEvent> = {
        event_id: `SIM-LIVE-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
        event_type: 'file_share',
        actor_type: 'employee',
        actor_id: 'EMP002',
        resource: 'q3_customer_records.csv',
        is_sensitive: true,
        action: 'share',
        destination: 'personal_cloud_storage@gmail.com',
        source: 'interactive_simulator',
        description: 'Simulated real-time DLP exfiltration test event emitted from dashboard'
      };
      await api.createEvent(simEvent);
      await fetchEvents();
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  const filteredEvents = (events || []).filter(ev => {
    const term = searchTerm.toLowerCase();
    return (
      (ev.event_id || '').toLowerCase().includes(term) ||
      (ev.actor_id || '').toLowerCase().includes(term) ||
      (ev.resource || '').toLowerCase().includes(term) ||
      ((ev.description || '')).toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-red-500 animate-pulse" />
            Activity Monitoring Feed
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time event-driven telemetry stream across employees, AI agents, and external consumers.
          </p>
        </div>

        {/* Action & Filter bar */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleSimulateEvent}
            disabled={isSimulating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-semibold shadow-lg shadow-red-600/30 border border-red-500/40 transition-all disabled:opacity-50 active:scale-95"
          >
            <Play className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>Emit Test Event</span>
          </button>

          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search resource or actor..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-52"
            />
          </div>

          <select
            value={actorTypeFilter}
            onChange={(e) => setActorTypeFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Actors</option>
            <option value="employee">Employee</option>
            <option value="agent">AI Agent</option>
            <option value="external">External</option>
          </select>

          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Event Types</option>
            <option value="file_access">File Access</option>
            <option value="file_share">File Share / Sharing</option>
            <option value="file_download">File Download</option>
            <option value="authentication">Authentication</option>
            <option value="api_request">API Request</option>
            <option value="data_export">Data Export</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-xl bg-gradient-to-b from-[#130d14] to-[#070508] border border-red-950/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#180f1a] text-red-400/80 font-semibold border-b border-red-950/60">
              <tr>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Destination</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">ML Score</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-red-950/30 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 font-sans">
                    Loading security events from repository...
                  </td>
                </tr>
              ) : fetchError && events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-amber-400 font-sans">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <p>Unable to load activity events ({fetchError})</p>
                      <button
                        onClick={fetchEvents}
                        className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow"
                      >
                        Retry Loading Events
                      </button>
                    </div>
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 font-sans">
                    <div className="flex flex-col items-center justify-center gap-1">
                      <p>No matching activity events found.</p>
                      {(searchTerm || actorTypeFilter !== 'all' || eventTypeFilter !== 'all') && (
                        <button
                          onClick={() => { setSearchTerm(''); setActorTypeFilter('all'); setEventTypeFilter('all'); }}
                          className="text-xs text-red-400 hover:underline mt-1"
                        >
                          Clear active search and filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-red-950/20 transition-colors">
                    <td className="py-2.5 px-4 text-red-400 font-bold">{ev.event_id}</td>
                    <td className="py-2.5 px-4 font-sans text-slate-300">
                      <span className="font-medium text-slate-200">{ev.actor_id}</span>
                      <span className="ml-1 text-[10px] text-slate-500 uppercase">({ev.actor_type})</span>
                    </td>
                    <td className="py-2.5 px-4 uppercase text-[11px] text-slate-400">{ev.event_type}</td>
                    <td className="py-2.5 px-4 text-slate-300 font-bold">{ev.action}</td>
                    <td className="py-2.5 px-4 text-slate-200 truncate max-w-xs">{ev.resource}</td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px] truncate max-w-xs">{ev.destination || 'internal'}</td>
                    <td className="py-2.5 px-4 font-sans">
                      <SeverityBadge severity={ev.risk_level} />
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-bold">
                      {ev.risk_score !== undefined ? `${ev.risk_score}` : '-'}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="px-2.5 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 font-sans text-xs transition-all"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Inspection Modal */}
      {selectedEvent && (
        <Modal
          isOpen={Boolean(selectedEvent)}
          onClose={() => setSelectedEvent(null)}
          title={`Event Inspection: ${selectedEvent.event_id}`}
        >
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3 p-3.5 rounded-lg bg-[#140e15] border border-red-950/70">
              <div>
                <span className="text-slate-500 text-[11px]">Actor:</span>
                <p className="text-slate-200 font-bold">{selectedEvent.actor_id} ({selectedEvent.actor_type})</p>
              </div>
              <div>
                <span className="text-slate-500 text-[11px]">Resource:</span>
                <p className="text-slate-200 truncate">{selectedEvent.resource}</p>
              </div>
              <div>
                <span className="text-slate-500 text-[11px]">Action:</span>
                <p className="text-slate-200">{selectedEvent.action}</p>
              </div>
              <div>
                <span className="text-slate-500 text-[11px]">Destination:</span>
                <p className="text-slate-200">{selectedEvent.destination || 'internal'}</p>
              </div>
              <div>
                <span className="text-slate-500 text-[11px]">Risk Score:</span>
                <p className="text-red-400 font-bold">{selectedEvent.risk_score} / 100.0</p>
              </div>
              <div>
                <span className="text-slate-500 text-[11px]">Risk Severity:</span>
                <div className="mt-0.5">
                  <SeverityBadge severity={selectedEvent.risk_level} />
                </div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#140e15] border border-red-950/70 space-y-1">
              <span className="text-slate-500 text-[11px]">Rule Result:</span>
              <p className="text-slate-200">{selectedEvent.rule_result || 'None'}</p>
              <span className="text-slate-500 text-[11px] block mt-2">Recommended Action:</span>
              <p className="text-amber-400 font-bold">{selectedEvent.recommended_action || 'none'}</p>
            </div>

            {selectedEvent.description && (
              <div className="p-3.5 rounded-lg bg-[#0e0a10] border border-red-950/60">
                <span className="text-slate-500 text-[11px] block mb-1">Description:</span>
                <p className="text-slate-300 font-sans">{selectedEvent.description}</p>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
