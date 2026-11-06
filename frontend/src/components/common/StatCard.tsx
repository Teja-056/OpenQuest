import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'cyan' | 'red' | 'amber' | 'emerald' | 'blue';
  trend?: string;
  trendPositive?: boolean;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'red',
  trend,
  trendPositive,
}) => {
  const colorMap = {
    cyan: {
      bg: 'bg-red-500/10',
      border: 'border-red-500/25',
      text: 'text-red-400',
      glow: 'shadow-[0_0_18px_rgba(239,68,68,0.12)]',
    },
    red: {
      bg: 'bg-red-600/15',
      border: 'border-red-500/35',
      text: 'text-red-400',
      glow: 'shadow-[0_0_20px_rgba(239,68,68,0.18)]',
    },
    amber: {
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/25',
      text: 'text-amber-400',
      glow: 'shadow-[0_0_15px_rgba(245,158,11,0.12)]',
    },
    emerald: {
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/25',
      text: 'text-emerald-400',
      glow: 'shadow-[0_0_15px_rgba(16,185,129,0.12)]',
    },
    blue: {
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/25',
      text: 'text-rose-400',
      glow: 'shadow-[0_0_15px_rgba(244,63,94,0.12)]',
    },
  };

  const scheme = colorMap[color];

  return (
    <div className={`relative p-5 rounded-xl bg-gradient-to-br from-[#130d14] via-[#0d090f] to-[#070508] border ${scheme.border} ${scheme.glow} transition-all duration-300 hover:border-red-500/50 hover:shadow-[0_0_25px_rgba(239,68,68,0.2)] group`}>
      {/* Corner bracket accent */}
      <div className="absolute top-0 right-0 w-2.5 h-2.5 border-t border-r border-red-500/40 rounded-tr" />
      <div className="absolute bottom-0 left-0 w-2.5 h-2.5 border-b border-l border-red-500/40 rounded-bl" />

      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</p>
          <h3 className="text-2xl font-bold mt-1 text-slate-100 font-mono tracking-tight group-hover:text-red-300 transition-colors">{value}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-2.5 rounded-lg ${scheme.bg} ${scheme.text} border border-red-500/20`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      {trend && (
        <div className="mt-3 flex items-center text-xs">
          <span className={`font-semibold mr-1.5 ${trendPositive ? 'text-emerald-400' : 'text-red-400'}`}>
            {trend}
          </span>
          <span className="text-slate-500">vs nominal baseline</span>
        </div>
      )}
    </div>
  );
};
