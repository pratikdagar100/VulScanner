import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  StatusChip,
  formatDate,
  formatDuration,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const STATUSES = ['', 'queued', 'running', 'completed', 'partial', 'failed', 'cancelled'];

export default function Scans() {
  const navigate = useNavigate();
  const [status, setStatus] = useState('');
  const [target, setTarget] = useState('');

  const { data, loading, error, reload } = useApi(
    () => api.scans({ status: status || undefined, target: target || undefined, limit: 200 }),
    [status, target],
    10000,
  );

  async function cancel(id: number, event: React.MouseEvent) {
    event.stopPropagation();
    await api.cancelScan(id).catch(() => undefined);
    reload();
  }

  return (
    <>
      <PageHeader
        title="Scans"
        description="Scan history with live status. Scans started from the CLI appear here too — both interfaces share one engine and one database."
        actions={
          <button className="btn-primary" onClick={() => navigate('/scans/new')}>
            + New scan
          </button>
        }
      />

      <Panel
        bodyClassName="p-0"
        title="Scan history"
        actions={
          <div className="flex items-center gap-2">
            <input
              className="input w-52 py-1.5"
              placeholder="Filter by target…"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
            />
            <select
              className="input w-36 py-1.5"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value || 'All statuses'}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading scans" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No scans yet"
            description="Start with 'Scan my computer' for a full local security audit, or run: vulscanner scan local --profile full"
            action={
              <button className="btn-primary" onClick={() => navigate('/scans/new')}>
                Start a scan
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Target</th>
                  <th>Profile</th>
                  <th>Status</th>
                  <th>Score</th>
                  <th>Findings (C/H/M/L)</th>
                  <th>Duration</th>
                  <th>Finished</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((scan) => (
                  <tr
                    key={scan.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                  >
                    <td>
                      <p className="font-medium text-slate-100">#{scan.id}</p>
                      <p className="text-xs text-slate-500 max-w-[220px] truncate">
                        {scan.name}
                      </p>
                    </td>
                    <td className="font-mono text-xs text-brand-300">{scan.target}</td>
                    <td className="text-xs text-slate-400">{scan.profile}</td>
                    <td>
                      <StatusChip status={scan.status} />
                      {scan.status === 'running' && (
                        <div className="mt-1.5 h-1 w-24 rounded-full bg-ink-800 overflow-hidden">
                          <div
                            className="h-full bg-brand-500 transition-all"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                      )}
                    </td>
                    <td className="tabular-nums">
                      {scan.security_score !== null ? `${scan.security_score}/100` : '—'}
                    </td>
                    <td className="tabular-nums text-xs">
                      <span className="text-severity-critical">{scan.critical_count}</span>
                      {' / '}
                      <span className="text-severity-high">{scan.high_count}</span>
                      {' / '}
                      <span className="text-severity-medium">{scan.medium_count}</span>
                      {' / '}
                      <span className="text-severity-low">{scan.low_count}</span>
                    </td>
                    <td className="text-xs text-slate-400">
                      {formatDuration(scan.duration_seconds)}
                    </td>
                    <td className="text-xs text-slate-400">{formatDate(scan.finished_at)}</td>
                    <td className="text-right">
                      {(scan.status === 'running' || scan.status === 'queued') && (
                        <button
                          className="btn-ghost text-xs"
                          onClick={(event) => cancel(scan.id, event)}
                        >
                          Cancel
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
