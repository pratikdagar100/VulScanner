import { useState } from 'react';

import {
  Banner,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const ACTIONS = [
  '',
  'login',
  'login_failed',
  'logout',
  'scan_started',
  'scan_completed',
  'scan_cancelled',
  'scan_failed',
  'target_added',
  'target_deleted',
  'finding_resolved',
  'finding_reopened',
  'risk_accepted',
  'report_generated',
  'user_created',
  'user_updated',
  'authorization_denied',
];

export default function AuditLogs() {
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [outcome, setOutcome] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const { data, loading, error, reload } = useApi(
    () =>
      api.auditLogs({
        action: action || undefined,
        actor: actor || undefined,
        outcome: outcome || undefined,
        limit: 300,
      }),
    [action, actor, outcome],
    20000,
  );

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only record of authentication, scanning, triage and reporting activity. Credentials, tokens and secret values are never written here."
      />

      <Panel
        bodyClassName="p-0"
        title={`${data?.length ?? 0} entries`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-40 py-1.5"
              placeholder="Actor…"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
            />
            <select
              className="input w-32 py-1.5"
              value={outcome}
              onChange={(event) => setOutcome(event.target.value)}
            >
              <option value="">Any outcome</option>
              <option value="success">success</option>
              <option value="failure">failure</option>
              <option value="denied">denied</option>
            </select>
            <select
              className="input w-48 py-1.5"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            >
              {ACTIONS.map((value) => (
                <option key={value} value={value}>
                  {value ? value.replace(/_/g, ' ') : 'All actions'}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading audit log" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No audit entries"
            description="Audit entries are written as soon as anyone signs in or starts a scan."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Outcome</th>
                  <th>Actor</th>
                  <th>Entity</th>
                  <th>Message</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {data.map((entry) => (
                  <>
                    <tr
                      key={entry.id}
                      className="cursor-pointer"
                      onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                    >
                      <td className="text-xs text-slate-400 whitespace-nowrap">
                        {formatDate(entry.created_at)}
                      </td>
                      <td className="text-xs font-mono text-brand-300">{entry.action}</td>
                      <td>
                        <StatusChip
                          status={entry.outcome === 'success' ? 'completed' : 'failed'}
                        />
                      </td>
                      <td className="text-xs text-slate-200">{entry.actor_name}</td>
                      <td className="text-xs text-slate-400">
                        {entry.entity_type ? `${entry.entity_type} ${entry.entity_id}` : '—'}
                      </td>
                      <td className="text-xs text-slate-300 max-w-[440px]">{entry.message}</td>
                      <td className="text-xs font-mono text-slate-500">
                        {entry.source_ip ?? '—'}
                      </td>
                    </tr>
                    {expanded === entry.id && Object.keys(entry.details ?? {}).length > 0 && (
                      <tr key={`${entry.id}-detail`}>
                        <td colSpan={7} className="bg-ink-950/60">
                          <pre className="code max-h-56">
                            {JSON.stringify(entry.details, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="mt-4">
        <Banner tone="info">
          Audit entries are sanitised before storage: any field whose name looks like a
          credential is replaced with [REDACTED], and free-text messages are scrubbed for
          credential patterns.
        </Banner>
      </div>
    </>
  );
}
