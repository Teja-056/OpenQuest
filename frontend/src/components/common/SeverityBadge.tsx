import React from 'react';
import { Severity } from '../../types';

interface SeverityBadgeProps {
  severity?: Severity | string;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity = 'low', className = '' }) => {
  const norm = String(severity).toLowerCase();

  const styles: Record<string, string> = {
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    high: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
    low: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  };

  const activeStyle = styles[norm] || styles.low;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${activeStyle} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current animate-pulse" />
      {norm}
    </span>
  );
};
