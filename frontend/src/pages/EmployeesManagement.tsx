import React, { useState, useEffect } from 'react';
import {
  Users,
  UserPlus,
  RefreshCw,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { api } from '../services/api';
import { Employee } from '../types';

export const EmployeesManagement: React.FC = () => {
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('');

  const fetchEmployees = async () => {
    setIsLoading(true);
    try {
      const data = await api.getEmployees({ limit: 100 });
      setEmployees(data);
    } catch (err) {
      console.error('Failed to load employees:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEmployees();
  }, []);

  const filtered = employees.filter(e => {
    const matchesSearch = e.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          e.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          e.role.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesDept = !departmentFilter || e.department === departmentFilter;
    return matchesSearch && matchesDept;
  });

  const departments = Array.from(new Set(employees.map(e => e.department).filter(Boolean)));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Users className="w-5 h-5 text-red-400" />
            <span>Employees & Identity Access Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Directory of organization employees, behavioral risk scores, role-based access control, and endpoint activity.
          </p>
        </div>

        <button
          onClick={fetchEmployees}
          className="p-2 rounded-xl bg-carbon-900 border border-slate-800 text-slate-400 hover:text-white"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-2.5" />
          <input
            type="text"
            placeholder="Search employees by name, email, or role..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-red-500/80"
          />
        </div>

        <div className="relative sm:w-56">
          <Filter className="w-4 h-4 text-slate-500 absolute left-3.5 top-2.5" />
          <select
            value={departmentFilter}
            onChange={(e) => setDepartmentFilter(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-carbon-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-red-500/80"
          >
            <option value="">All Departments</option>
            {departments.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Employees Table */}
      <div className="p-6 rounded-2xl bg-carbon-900 border border-red-950/60 shadow-xl">
        {filtered.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No employees match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase text-[10px] tracking-wider">
                  <th className="pb-3">Employee</th>
                  <th className="pb-3">Department</th>
                  <th className="pb-3">Role</th>
                  <th className="pb-3">Behavioral Risk Score</th>
                  <th className="pb-3">Access Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filtered.map((emp) => (
                  <tr key={emp.employee_id} className="hover:bg-carbon-950/60 transition-colors">
                    <td className="py-3.5">
                      <div className="font-bold text-white">{emp.name}</div>
                      <div className="text-[11px] text-slate-400 font-mono">{emp.email}</div>
                    </td>
                    <td className="py-3.5 text-slate-300 font-semibold">{emp.department}</td>
                    <td className="py-3.5 text-slate-400">{emp.role}</td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                        emp.risk_score >= 60 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {emp.risk_score?.toFixed(1) || '0.0'}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        emp.status === 'active'
                          ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      }`}>
                        {emp.status?.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
