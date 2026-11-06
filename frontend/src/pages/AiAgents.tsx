import React, { useState, useEffect } from 'react';
import {
  Bot,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Plus,
  Lock,
  Search,
  User,
  History
} from 'lucide-react';
import { AIAgent, AgentViolation } from '../types';
import { api } from '../services/api';
import { Modal } from '../components/common/Modal';
import { CyberRadar3D } from '../components/3d/CyberRadar3D';

export const AiAgents: React.FC = () => {
  const [agents, setAgents] = useState<AIAgent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Selected agent for violation history modal
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null);
  const [violations, setViolations] = useState<AgentViolation[]>([]);
  const [isLoadingViolations, setIsLoadingViolations] = useState(false);

  // Reactivation / Suspension state
  const [isUpdating, setIsUpdating] = useState(false);

  const fetchAgents = async () => {
    setIsLoading(true);
    setFetchError(null);
    try {
      const data = await api.getAgents(statusFilter !== 'all' ? statusFilter : undefined);
      if (Array.isArray(data)) {
        setAgents(data);
      }
    } catch (err: any) {
      console.error('Failed to load AI agents:', err);
      setFetchError(err.message || 'Agent registry unreachable');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, [statusFilter]);

  const handleToggleStatus = async (agent: AIAgent) => {
    const isCurrentlySuspended = agent.status === 'suspended';
    const targetStatus = isCurrentlySuspended ? 'active' : 'suspended';
    const reason = isCurrentlySuspended
      ? 'Administrator authorized reactivation'
      : 'Manual suspension via Security Dashboard';

    setIsUpdating(true);
    try {
      const updated = await api.updateAgentStatus(agent.agent_id, targetStatus, reason);
      setAgents(prev => prev.map(a => a.agent_id === updated.agent_id ? updated : a));
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleViewViolations = async (agent: AIAgent) => {
    setSelectedAgent(agent);
    setIsLoadingViolations(true);
    try {
      const data = await api.getAgentViolations(agent.agent_id);
      setViolations(data);
    } catch (err) {
      console.error('Failed to load agent violations:', err);
    } finally {
      setIsLoadingViolations(false);
    }
  };

  const filteredAgents = agents.filter(ag =>
    ag.agent_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    ag.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    ag.owner.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bot className="w-5 h-5 text-red-500" />
            AI Agent Guard & Governance Registry
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Least-privilege permission matrix, automatic 3-violation suspension, and admin-supervised reactivation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search agent ID or name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-200 focus:outline-none focus:border-red-500 w-56"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-shield-900 border border-red-950/60 text-xs text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Agent Statuses</option>
            <option value="active">Active Only</option>
            <option value="suspended">Suspended Only</option>
          </select>
        </div>
      </div>

      {/* 3D Cyber Radar & Policy Overview Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-8 p-6 rounded-2xl bg-gradient-to-br from-[#140e15] via-[#0d090f] to-[#070508] border border-red-950/70 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-red-400 text-xs font-bold uppercase tracking-wider">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              Real-time AI Guard Enforcement Matrix
            </div>
            <h3 className="text-lg font-bold text-slate-100 mt-1">
              Deterministic Autonomous Security Guard
            </h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Every AI agent invocation is strictly validated against permitted resources, allowed actions, and destination endpoints. Exceeding 3 security violations triggers immediate automatic suspension under Rule 4.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 mt-4 pt-3 border-t border-carbon-800">
            <span className="px-2.5 py-1 rounded bg-carbon-800 text-[11px] font-mono text-slate-300 border border-red-950/60">
              Active: <strong className="text-emerald-400">{agents.filter(a => a.status === 'active').length}</strong>
            </span>
            <span className="px-2.5 py-1 rounded bg-carbon-800 text-[11px] font-mono text-slate-300 border border-red-950/60">
              Suspended: <strong className="text-red-400">{agents.filter(a => a.status === 'suspended').length}</strong>
            </span>
            <span className="px-2.5 py-1 rounded bg-carbon-800 text-[11px] font-mono text-slate-300 border border-red-950/60">
              Max Violations: <strong className="text-amber-400">3 Allowed</strong>
            </span>
          </div>
        </div>

        <div className="lg:col-span-4 h-full">
          <CyberRadar3D
            height={200}
            activeNodes={agents.filter(a => a.status === 'active').length}
            threatDetected={agents.some(a => a.status === 'suspended')}
          />
        </div>
      </div>

      {/* Agents Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {isLoading ? (
          <div className="col-span-2 py-12 text-center text-xs text-slate-500">
            Loading AI agents from registry...
          </div>
        ) : fetchError && agents.length === 0 ? (
          <div className="col-span-2 py-12 text-center text-xs text-amber-400">
            <div className="flex flex-col items-center justify-center gap-2">
              <p>Unable to load AI agents ({fetchError})</p>
              <button
                onClick={fetchAgents}
                className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow"
              >
                Retry Loading Agents
              </button>
            </div>
          </div>
        ) : filteredAgents.length === 0 ? (
          <div className="col-span-2 py-12 text-center text-xs text-slate-500">
            <div className="flex flex-col items-center justify-center gap-1">
              <p>No registered AI agents found.</p>
              {(searchTerm || statusFilter !== 'all') && (
                <button
                  onClick={() => { setSearchTerm(''); setStatusFilter('all'); }}
                  className="text-xs text-red-400 hover:underline mt-1 font-sans"
                >
                  Clear active search and status filter
                </button>
              )}
            </div>
          </div>
        ) : (
          filteredAgents.map((agent) => {
            const isSuspended = agent.status === 'suspended';
            return (
              <div
                key={agent.agent_id}
                className={`p-5 rounded-xl border bg-gradient-to-b from-[#130d14] to-[#070508] transition-all ${
                  isSuspended
                    ? 'border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.2)]'
                    : 'border-red-950/60 hover:border-red-500/30'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-lg border ${isSuspended ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-red-950/40 text-red-400 border-red-900/50'}`}>
                      <Bot className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-slate-100">{agent.name}</h4>
                      <p className="text-[11px] text-slate-500 font-mono">ID: {agent.agent_id} | Owner: {agent.owner}</p>
                    </div>
                  </div>

                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                    isSuspended ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                  }`}>
                    {agent.status}
                  </span>
                </div>

                {agent.description && (
                  <p className="text-xs text-slate-400 mt-3 font-sans leading-relaxed">
                    {agent.description}
                  </p>
                )}

                {/* Boundaries & Access Control */}
                <div className="mt-4 pt-3 border-t border-carbon-800 space-y-2 text-xs">
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 text-[11px] w-28 shrink-0">Allowed Resources:</span>
                    <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                      {agent.allowed_resources && agent.allowed_resources.length > 0 ? (
                        agent.allowed_resources.map((r, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-carbon-800 text-slate-300 border border-red-950/40">
                            {r}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 italic">None configured</span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 text-[11px] w-28 shrink-0">Allowed Actions:</span>
                    <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                      {agent.allowed_actions && agent.allowed_actions.map((a, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-carbon-800 text-red-400 border border-red-950/40 uppercase font-bold">
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 text-[11px] w-28 shrink-0">Violations Incurred:</span>
                    <span className={`font-mono font-bold ${agent.violation_count >= 3 ? 'text-red-400' : 'text-slate-300'}`}>
                      {agent.violation_count} / 3 threshold
                    </span>
                  </div>
                </div>

                {/* Actions Footer */}
                <div className="mt-4 pt-3 border-t border-carbon-800 flex items-center justify-between text-xs">
                  <button
                    onClick={() => handleViewViolations(agent)}
                    className="flex items-center gap-1.5 text-slate-400 hover:text-red-400 transition-colors"
                  >
                    <History className="w-3.5 h-3.5" />
                    <span>View Violation History</span>
                  </button>

                  <button
                    disabled={isUpdating}
                    onClick={() => handleToggleStatus(agent)}
                    className={`px-3 py-1 rounded-lg font-semibold text-xs transition-all disabled:opacity-50 ${
                      isSuspended
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30'
                    }`}
                  >
                    {isSuspended ? 'Reactivate Agent' : 'Suspend Agent'}
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Agent Violations Audit Modal */}
      {selectedAgent && (
        <Modal
          isOpen={Boolean(selectedAgent)}
          onClose={() => setSelectedAgent(null)}
          title={`Violation History: ${selectedAgent.name} (${selectedAgent.agent_id})`}
          maxWidth="max-w-2xl"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3.5 rounded-lg bg-[#140e15] border border-red-950/70 flex justify-between font-mono">
              <span>Recorded Violations: <strong className="text-red-400">{violations.length}</strong></span>
              <span>Status: <strong className="uppercase text-slate-200">{selectedAgent.status}</strong></span>
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto">
              {isLoadingViolations ? (
                <p className="text-slate-500 text-center py-4">Loading violations...</p>
              ) : violations.length === 0 ? (
                <p className="text-slate-500 text-center py-4">No violations recorded for this agent.</p>
              ) : (
                violations.map((v) => (
                  <div key={v.violation_id} className="p-3 rounded-lg bg-[#0e0a10] border border-red-950/60 space-y-1 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-red-400 font-bold uppercase">{v.violation_type}</span>
                      <span className="text-[10px] text-slate-500">{new Date(v.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-slate-300 font-sans text-xs">{v.details}</p>
                    <div className="text-[10px] text-slate-500 flex gap-3 pt-1">
                      <span>Action: {v.action_attempted || 'N/A'}</span>
                      <span>Target: {v.resource_attempted || 'N/A'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
