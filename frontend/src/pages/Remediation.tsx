import { useState } from 'react';
import { Link } from 'react-router-dom';

import {
  Banner,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  SeverityChip,
  StatCard,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const PRIORITY_LABEL: Record<number, string> = {
  1: 'Immediate',
  2: 'High priority',
  3: 'Planned',
  4: 'Backlog',
  5: 'Informational',
};

export default function Remediation() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const { data, loading, error, reload } = useApi(() => api.remediation(), []);

  if (loading && !data) return <Loading label="Building remediation plan" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;

  const items = data?.items ?? [];
  const summary = data?.summary;

  const grouped = items.reduce<Record<number, typeof items>>((accumulator, item) => {
    (accumulator[item.priority] ??= []).push(item);
    return accumulator;
  }, {});

  return (
    <>
      <PageHeader
        title="Remediation centre"
        description="Every open finding, ordered by priority, with what is wrong, why it matters, the recommended fix and how to verify it."
      />

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <StatCard label="Total actions" value={summary.total_items} />
          <StatCard
            label="Immediate"
            value={summary.immediate_action_required.length}
            tone="critical"
            hint="fix within 7 days"
          />
          <StatCard
            label="Quick wins"
            value={summary.quick_wins.length}
            tone="good"
            hint="low effort, meaningful impact"
          />
          <StatCard
            label="Need a reboot"
            value={summary.requires_reboot_count}
            hint="schedule a maintenance window"
          />
        </div>
      )}

      <div className="mb-4">
        <Banner tone="warning">
          {summary?.policy ??
            'VulScanner never applies remediation automatically. Every command is guidance for an authorized operator to review and execute.'}
        </Banner>
      </div>

      {!items.length ? (
        <Panel>
          <EmptyState
            title="Nothing to remediate"
            description="There are no open findings. Run a scan to check the current posture."
          />
        </Panel>
      ) : (
        <div className="space-y-6">
          {Object.entries(grouped)
            .sort(([left], [right]) => Number(left) - Number(right))
            .map(([priority, entries]) => (
              <section key={priority}>
                <h2 className="mb-3 text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <span className="chip bg-ink-800 text-slate-300 border border-ink-700">
                    P{priority}
                  </span>
                  {PRIORITY_LABEL[Number(priority)] ?? 'Other'}
                  <span className="text-xs font-normal text-slate-500">
                    {entries.length} action{entries.length > 1 ? 's' : ''}
                  </span>
                </h2>

                <div className="space-y-2">
                  {entries.map((item) => {
                    const open = expanded === item.finding_uid;
                    return (
                      <div key={item.finding_uid} className="panel">
                        <button
                          className="w-full px-5 py-3.5 flex items-start justify-between gap-4 text-left"
                          onClick={() => setExpanded(open ? null : item.finding_uid)}
                        >
                          <div className="flex items-start gap-3 min-w-0">
                            <SeverityChip severity={item.severity} />
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-slate-100">
                                {item.title}
                              </p>
                              <p className="text-[11px] text-slate-500 mt-0.5">
                                {item.category} · effort {item.effort}
                                {item.sla_days ? ` · fix within ${item.sla_days} days` : ''}
                                {item.requires_reboot ? ' · requires reboot' : ''}
                                {item.patch_reference ? ` · ${item.patch_reference}` : ''}
                              </p>
                            </div>
                          </div>
                          <span className="text-slate-500 text-xs shrink-0">
                            {open ? '▾' : '▸'}
                          </span>
                        </button>

                        {open && (
                          <div className="px-5 pb-5 border-t border-ink-800 pt-4 space-y-4">
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                  What is wrong
                                </p>
                                <p className="text-sm text-slate-300 leading-relaxed">
                                  {item.what_is_wrong}
                                </p>
                              </div>
                              <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                  Why it matters
                                </p>
                                <p className="text-sm text-slate-300 leading-relaxed">
                                  {item.why_it_matters}
                                </p>
                              </div>
                            </div>

                            <div>
                              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                Recommended fix
                              </p>
                              <p className="text-sm text-slate-300 leading-relaxed">
                                {item.recommended_fix}
                              </p>
                              {item.command && <pre className="code mt-2">{item.command}</pre>}
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                  Verification
                                </p>
                                <p className="text-sm text-slate-300">{item.verification}</p>
                              </div>
                              <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                  References
                                </p>
                                {item.references.length ? (
                                  <ul className="space-y-0.5">
                                    {item.references.map((reference) => (
                                      <li key={reference}>
                                        <a
                                          href={reference}
                                          target="_blank"
                                          rel="noreferrer noopener"
                                          className="text-xs text-brand-300 hover:text-brand-200 break-all"
                                        >
                                          {reference}
                                        </a>
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <p className="text-xs text-slate-600">None recorded.</p>
                                )}
                              </div>
                            </div>

                            <p className="text-[11px] text-slate-500 pt-2 border-t border-ink-800">
                              {item.execution_note} Finding{' '}
                              <span className="font-mono">{item.finding_uid}</span> —{' '}
                              <Link
                                to={`/findings?search=${encodeURIComponent(item.title)}`}
                                className="text-brand-300 hover:text-brand-200"
                              >
                                open finding
                              </Link>
                            </p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
        </div>
      )}
    </>
  );
}
