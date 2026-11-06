import React, { useState } from 'react';
import { Shield, Lock, Building, User, Mail, Phone, Globe, Users, ArrowRight, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import { UserSession, OrganizationProfile } from '../types';

interface CompanyRegistrationProps {
  onRegistrationSuccess: (user: UserSession, org: OrganizationProfile) => void;
  onNavigateToLogin: () => void;
}

export const CompanyRegistration: React.FC<CompanyRegistrationProps> = ({
  onRegistrationSuccess,
  onNavigateToLogin,
}) => {
  const [companyName, setCompanyName] = useState('');
  const [ownerName, setOwnerName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [industry, setIndustry] = useState('Technology');
  const [country, setCountry] = useState('United States');
  const [employeeCount, setEmployeeCount] = useState(25);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [subscriptionTier, setSubscriptionTier] = useState<'STARTER' | 'PROFESSIONAL' | 'ENTERPRISE'>('PROFESSIONAL');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setErrorMessage('Password must be at least 8 characters in length');
      return;
    }

    setIsLoading(true);
    try {
      const res = await api.registerCompany({
        company_name: companyName,
        owner_name: ownerName,
        email,
        phone,
        industry,
        country,
        employee_count: Number(employeeCount),
        password,
        subscription_tier: subscriptionTier,
      });

      onRegistrationSuccess(res.user, res.organization);
    } catch (err: any) {
      setErrorMessage(err.message || 'Registration failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-carbon-950 text-slate-100 flex flex-col justify-center items-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden font-sans">
      {/* Background radial glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[700px] h-[700px] bg-red-600/10 blur-[140px] pointer-events-none rounded-full" />
      <div className="absolute -bottom-20 -left-20 w-96 h-96 bg-red-950/20 blur-[100px] pointer-events-none rounded-full" />

      {/* Top Logo */}
      <div className="text-center z-10 mb-6">
        <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-red-950/50 border border-red-500/30 text-red-400 text-xs font-semibold tracking-wider uppercase mb-3 shadow-lg shadow-red-950/40">
          <Shield className="w-3.5 h-3.5 text-red-400" />
          <span>Multi-Tenant Enterprise Security Platform</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
          Register Your <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-rose-600">Organization</span>
        </h1>
        <p className="mt-2 text-sm text-slate-400 max-w-md mx-auto">
          Establish isolated tenant cloud perimeter, EDR endpoint protection, and autonomous AI defense.
        </p>
      </div>

      {/* Form Container */}
      <div className="w-full max-w-2xl bg-carbon-900/90 border border-red-950/60 rounded-2xl p-8 backdrop-blur-xl shadow-2xl shadow-black/80 z-10">
        {errorMessage && (
          <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-3">
            <AlertCircle className="w-5 h-5 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Company Name */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Company Name *
              </label>
              <div className="relative">
                <Building className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="text"
                  required
                  placeholder="Acme Cybersecurity Inc."
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>

            {/* Owner Name */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Admin Full Name *
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="text"
                  required
                  placeholder="Jane Doe"
                  value={ownerName}
                  onChange={(e) => setOwnerName(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>

            {/* Business Email */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Business Email *
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="email"
                  required
                  placeholder="admin@acme-defense.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>

            {/* Phone Number */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Phone Number
              </label>
              <div className="relative">
                <Phone className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="text"
                  placeholder="+1 (555) 019-2834"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>

            {/* Industry */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Industry
              </label>
              <div className="relative">
                <Globe className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <select
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white focus:outline-none focus:border-red-500/80 transition-colors"
                >
                  <option value="Technology">Technology & SaaS</option>
                  <option value="Finance">Financial Services & Banking</option>
                  <option value="Healthcare">Healthcare & Life Sciences</option>
                  <option value="Defense">Aerospace & Defense</option>
                  <option value="Retail">Retail & E-Commerce</option>
                  <option value="Government">Government & Public Sector</option>
                </select>
              </div>
            </div>

            {/* Employee Count */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Company Size
              </label>
              <div className="relative">
                <Users className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <select
                  value={employeeCount}
                  onChange={(e) => setEmployeeCount(Number(e.target.value))}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white focus:outline-none focus:border-red-500/80 transition-colors"
                >
                  <option value={10}>1 - 10 employees</option>
                  <option value={25}>11 - 50 employees</option>
                  <option value={100}>51 - 200 employees</option>
                  <option value={500}>201 - 1,000 employees</option>
                  <option value={2000}>1,000+ employees</option>
                </select>
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Password *
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Confirm Password *
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-carbon-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 focus:outline-none focus:border-red-500/80 transition-colors"
                />
              </div>
            </div>
          </div>

          {/* Subscription Tier Selection */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Initial Subscription Tier
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {[
                { id: 'STARTER', name: 'Starter', price: '$49/mo', desc: '5 Endpoints • 1 AWS Account' },
                { id: 'PROFESSIONAL', name: 'Professional', price: '$199/mo', desc: '25 Endpoints • 3 AWS Accounts' },
                { id: 'ENTERPRISE', name: 'Enterprise', price: '$499/mo', desc: 'Unlimited • 50 AWS Accounts' },
              ].map((tier) => (
                <button
                  type="button"
                  key={tier.id}
                  onClick={() => setSubscriptionTier(tier.id as any)}
                  className={`p-3.5 rounded-xl border text-left transition-all ${
                    subscriptionTier === tier.id
                      ? 'bg-red-500/15 border-red-500 text-white shadow-md shadow-red-500/20'
                      : 'bg-carbon-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between font-bold text-xs">
                    <span>{tier.name}</span>
                    <span className="text-red-400 font-mono">{tier.price}</span>
                  </div>
                  <p className="text-[10px] text-slate-400 mt-1">{tier.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-sm shadow-lg shadow-red-600/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isLoading ? (
              <span className="flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Provisioning Tenant & Security Stack...
              </span>
            ) : (
              <>
                <span>Complete Registration & Begin Setup</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Bottom Login Link */}
        <div className="mt-6 pt-6 border-t border-slate-800 text-center text-xs text-slate-400">
          Already registered?{' '}
          <button
            onClick={onNavigateToLogin}
            className="text-red-400 hover:text-red-300 font-semibold underline underline-offset-4 ml-1 cursor-pointer"
          >
            Sign in to existing account
          </button>
        </div>
      </div>
    </div>
  );
};
