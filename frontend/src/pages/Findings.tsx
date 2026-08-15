import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  SEVERITY_ORDER,
  SeverityChip,
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi, useDebounced } from '@/hooks/useApi';
import { api } from '@/services/api';

const STATUSES = ['', 'open', 'reopened', 'resolved', 'risk_accepted', 'false_positive'];

export default function Findings() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const scanId = params.get('scan');

  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('open');
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounced(search);

  const { data: summary } = useApi(
    () => api.findingsSummary(scanId ? { scan_id: Number(scanId) } : undefined),
    [scanId],
  );

  const { data, loading, error, reload } = useApi(
    () =>
      api.findings({
        scan_id: scanId ? Number(scanId) : undefined,
        severity: severity || undefined,
        status: status || undefined,
        category: category || undefined,
        search: debouncedSearch || undefined,
        limit: 500,
      }),
    [scanId, severity, status, category, debouncedSearch],
  );

  const categories = Object.keys(summary?.by_category ?? {});

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every finding carries its evidence, detection method, confidence level and a VulScanner risk score computed from exposure and exploitation intelligence."
      />

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
        {SEVERITY_ORDER.map((level) => (
          <button
            key={level}
            onClick={() => setSeverity(severity === level ? '' : level)}
            className={`panel px-4 py-3 text-left transition-colors ${
              severity === level ? 'ring-1 ring-brand-500' : ''
            }`}
          >
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              {level}
            </p>
            <p className="mt-1 text-2xl font-bold tabular-nums text-slate-100">
              {summary?.by_severity[level] ?? 0}
            </p>
          </button>
        ))}
      </div>

      <Panel
        bodyClassName="p-0"
        title={`${data?.length ?? 0} findings`}
        subtitle={scanId ? `Filtered to scan #${scanId}` : 'Across all scans'}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-56 py-1.5"
              placeholder="Search title or description…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select
              className="input w-40 py-1.5"
              value={category}
              onChange={(event) => setCategory(event.target.value)}
            >
              <option value="">All categories</option>
              {categories.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
            <select
              className="input w-36 py-1.5"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value ? value.replace(/_/g, ' ') : 'All statuses'}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading findings" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No findings match"
            description="Adjust the filters, or run a scan if the database is empty. VulScanner never fabricates findings — an empty list means nothing was detected."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>CVSS</th>
                  <th>Finding</th>
                  <th>Category</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.map((finding) => (
                  <tr
                    key={finding.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/findings/${finding.id}`)}
                  >
                    <td>
                      <SeverityChip severity={finding.severity} />
                    </td>
                    <td className="w-32">
                      <RiskBar score={finding.risk_score} />
                    </td>
                    <td className="tabular-nums text-xs text-slate-400">
                      {finding.cvss_score ?? '—'}
                    </td>
                    <td className="max-w-[420px]">
                      <p className="text-slate-100">{finding.title}</p>
                      <p className="text-[11px] text-slate-500 font-mono">
                        {finding.finding_uid}
                      </p>
                    </td>
                    <td className="text-xs text-slate-400">{finding.category}</td>
                    <td className="text-xs text-slate-400">{finding.confidence}</td>
                    <td>
                      <StatusChip status={finding.status} />
                    </td>
                    <td className="text-xs text-slate-500">
                      {formatDate(finding.last_detected_at)}
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
