/** Shared presentational building blocks used across every VulScanner page. */

import type { ReactNode } from 'react';

import type { Severity } from '@/types';

export const SEVERITY_STYLES: Record<Severity, { chip: string; text: string; bar: string; hex: string }> = {
  critical: {
    chip: 'bg-severity-critical/15 text-severity-critical border border-severity-critical/40',
    text: 'text-severity-critical',
    bar: 'bg-severity-critical',
    hex: '#f0356b',
  },
  high: {
    chip: 'bg-severity-high/15 text-severity-high border border-severity-high/40',
    text: 'text-severity-high',
    bar: 'bg-severity-high',
    hex: '#fb7333',
  },
  medium: {
    chip: 'bg-severity-medium/15 text-severity-medium border border-severity-medium/40',
    text: 'text-severity-medium',
    bar: 'bg-severity-medium',
    hex: '#f5c518',
  },
  low: {
    chip: 'bg-severity-low/15 text-severity-low border border-severity-low/40',
    text: 'text-severity-low',
    bar: 'bg-severity-low',
    hex: '#3ba3f5',
  },
  informational: {
    chip: 'bg-severity-info/15 text-severity-info border border-severity-info/40',
    text: 'text-severity-info',
    bar: 'bg-severity-info',
    hex: '#8ba0b8',
  },
};

export const SEVERITY_ORDER: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
];

export function SeverityChip({ severity }: { severity: Severity | string }) {
  const style = SEVERITY_STYLES[(severity as Severity) ?? 'informational'] ?? SEVERITY_STYLES.informational;
  return <span className={`chip ${style.chip}`}>{severity}</span>;
}

export function StatusChip({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40',
    partial: 'bg-amber-500/15 text-amber-400 border border-amber-500/40',
    running: 'bg-brand-500/15 text-brand-300 border border-brand-500/40 animate-pulse',
    queued: 'bg-slate-500/15 text-slate-300 border border-slate-500/40',
    failed: 'bg-severity-critical/15 text-severity-critical border border-severity-critical/40',
    cancelled: 'bg-slate-600/15 text-slate-400 border border-slate-600/40',
    open: 'bg-severity-high/15 text-severity-high border border-severity-high/40',
    resolved: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40',
    reopened: 'bg-amber-500/15 text-amber-400 border border-amber-500/40',
    risk_accepted: 'bg-purple-500/15 text-purple-300 border border-purple-500/40',
    false_positive: 'bg-slate-500/15 text-slate-400 border border-slate-500/40',
    observed: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40',
    inferred: 'bg-slate-500/15 text-slate-400 border border-slate-500/40',
    confirmed: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40',
  };
  return (
    <span className={`chip ${styles[status] ?? 'bg-ink-800 text-slate-300 border border-ink-700'}`}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export function Panel({
  title,
  actions,
  children,
  className = '',
  bodyClassName = 'p-5',
  subtitle,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          <div>
            {title && <h2 className="panel-title">{title}</h2>}
            {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone = 'default',
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: 'default' | Severity | 'good';
  icon?: ReactNode;
}) {
  const toneClass =
    tone === 'good'
      ? 'text-emerald-400'
      : tone === 'default'
        ? 'text-slate-100'
        : SEVERITY_STYLES[tone].text;
  return (
    <div className="panel px-5 py-4">
      <div className="flex items-start justify-between gap-3">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          {label}
        </p>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <p className={`mt-2 text-3xl font-bold tabular-nums ${toneClass}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function ScoreGauge({ score, label = 'Security score' }: { score: number; label?: string }) {
  const clamped = Math.max(0, Math.min(100, score));
  const tone =
    clamped >= 85 ? '#34d399' : clamped >= 60 ? '#f5c518' : clamped >= 35 ? '#fb7333' : '#f0356b';
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);

  return (
    <div className="flex flex-col items-center justify-center">
      <svg viewBox="0 0 140 140" className="w-36 h-36 -rotate-90">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#152238" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={tone}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-700"
        />
      </svg>
      <div className="-mt-24 text-center">
        <p className="text-4xl font-bold tabular-nums" style={{ color: tone }}>
          {clamped.toFixed(0)}
        </p>
        <p className="text-[11px] uppercase tracking-wider text-slate-500">/ 100</p>
      </div>
      <p className="mt-14 text-xs font-medium uppercase tracking-wider text-slate-400">
        {label}
      </p>
    </div>
  );
}

export function RiskBar({ score, max = 100 }: { score: number; max?: number }) {
  const percent = Math.max(0, Math.min(100, (score / max) * 100));
  const tone =
    score >= 90 ? 'bg-severity-critical'
      : score >= 70 ? 'bg-severity-high'
        : score >= 40 ? 'bg-severity-medium'
          : 'bg-severity-low';
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="h-1.5 flex-1 rounded-full bg-ink-800 overflow-hidden">
        <div className={`h-full rounded-full ${tone}`} style={{ width: `${percent}%` }} />
      </div>
      <span className="text-xs tabular-nums text-slate-300 w-9 text-right">
        {score.toFixed(0)}
      </span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-12 h-12 rounded-xl bg-ink-800 border border-ink-700 flex items-center justify-center mb-4">
        <span className="text-xl text-slate-500">∅</span>
      </div>
      <p className="text-sm font-semibold text-slate-200">{title}</p>
      <p className="mt-1.5 max-w-md text-xs text-slate-500 leading-relaxed">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-slate-500">
      <span className="w-4 h-4 rounded-full border-2 border-brand-500 border-t-transparent animate-spin" />
      <span className="text-sm">{label}…</span>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center">
      <p className="text-sm font-semibold text-severity-critical">Could not load data</p>
      <p className="mt-1.5 max-w-lg text-xs text-slate-400">{message}</p>
      {onRetry && (
        <button className="btn-secondary mt-4" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function KeyValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="kv-label">{label}</dt>
      <dd className="kv-value break-words">{value ?? '—'}</dd>
    </div>
  );
}

export function Banner({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning' | 'danger' | 'success';
  children: ReactNode;
}) {
  const tones = {
    info: 'bg-brand-600/10 border-brand-500/40 text-brand-100',
    warning: 'bg-severity-medium/10 border-severity-medium/40 text-amber-100',
    danger: 'bg-severity-critical/10 border-severity-critical/40 text-rose-100',
    success: 'bg-emerald-500/10 border-emerald-500/40 text-emerald-100',
  };
  return (
    <div className={`rounded-lg border px-4 py-3 text-xs leading-relaxed ${tones[tone]}`}>
      {children}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">{title}</h1>
        {description && (
          <p className="mt-1 text-sm text-slate-400 max-w-3xl">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}
