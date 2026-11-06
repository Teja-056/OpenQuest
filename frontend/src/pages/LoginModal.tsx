import React, { useState } from 'react';
import { Lock, User, Key, CheckCircle, AlertCircle } from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { api } from '../services/api';
import { UserSession } from '../types';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: UserSession) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose, onLoginSuccess }) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('Admin@AIShield2026!');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.login(username, password);
      onLoginSuccess(res.user);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Security Operations Authentication" maxWidth="max-w-md">
      <form onSubmit={handleSubmit} className="space-y-4 text-xs">
        <p className="text-slate-400">
          Enter credentials to access administrative and analyst controls.
        </p>

        {error && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div>
          <label className="block text-slate-300 font-semibold mb-1">Username</label>
          <div className="relative">
            <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-shield-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

        <div>
          <label className="block text-slate-300 font-semibold mb-1">Password</label>
          <div className="relative">
            <Key className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-shield-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

        {/* Quick Fill Demo Credential Helpers */}
        <div className="pt-2 border-t border-slate-800 space-y-1.5">
          <span className="text-[10px] text-slate-500 uppercase font-bold block">Quick Demo Credentials:</span>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => handleQuickFill('admin', 'Admin@AIShield2026!')}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[10px]"
            >
              Org Admin
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('analyst', 'Analyst@AIShield2026!')}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[10px]"
            >
              Security Analyst
            </button>
          </div>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50 mt-2"
        >
          {isLoading ? 'Verifying...' : 'Sign In'}
        </button>
      </form>
    </Modal>
  );
};
