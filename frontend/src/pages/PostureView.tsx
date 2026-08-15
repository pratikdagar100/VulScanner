/**
 * Windows posture views.
 *
 * Software, Patches, Firewall, Defender, RDP, Users & Groups and Security
 * Policies are all projections of the same stored collector evidence, so they
 * share one page driven by a per-view descriptor. Nothing is rendered that was
 * not actually collected: a collector that could not read a value shows its
 * warning rather than a fabricated default.
 */

import { useMemo, useState } from 'react';
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
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';
import type { CollectorResult } from '@/types';

export type PostureViewName =
  | 'software'
  | 'patches'
  | 'firewall'
  | 'defender'
  | 'rdp'
  | 'accounts'
  | 'policies';

interface ViewDescriptor {
  title: string;
  description: string;
  collectors: string[];
  findingCategories: string[];
}

const VIEWS: Record<PostureViewName, ViewDescriptor> = {
  software: {
    title: 'Installed software',
    description:
      'Application inventory read from the uninstall registry hives. Products with a parseable version participate in CVE correlation.',
    collectors: ['software', 'dotnet', 'powershell'],
    findingCategories: ['software', 'vulnerability'],
  },
  patches: {
    title: 'Patches & updates',
    description:
      'Installed hotfixes and, where the Windows Update agent was queried, updates it reports as applicable and not installed.',
    collectors: ['hotfixes', 'updates'],
    findingCategories: ['patch'],
  },
  firewall: {
    title: 'Windows Firewall',
    description:
      'Profile state and inbound rule analysis. Rules that allow traffic from any remote address to a sensitive port are flagged.',
    collectors: ['firewall'],
    findingCategories: ['firewall'],
  },
  defender: {
    title: 'Microsoft Defender',
    description:
      'Antivirus status, cloud protection, attack surface reduction and exclusions, plus any other registered security product.',
    collectors: ['defender', 'antivirus', 'amsi'],
    findingCategories: ['defender', 'antivirus'],
  },
  rdp: {
    title: 'Remote Desktop',
    description:
      'RDP enablement, Network Level Authentication, encryption level, firewall exposure and current sessions.',
    collectors: ['rdp'],
    findingCategories: ['rdp'],
  },
  accounts: {
    title: 'Users & groups',
    description:
      'Local accounts, privileged group membership and the effective password policy. No password or hash material is ever read.',
    collectors: ['local_users', 'local_groups'],
    findingCategories: ['accounts'],
  },
  policies: {
    title: 'Security policies',
    description:
      'Audit policy, local security policy, UAC, authentication hardening and boot integrity.',
    collectors: ['uac', 'audit_policy', 'group_policy', 'ntlm', 'secure_boot', 'sysmon'],
    findingCategories: ['policy', 'authentication', 'logging', 'boot_integrity'],
  },
};

/** Renders a scalar value with sensible treatment for booleans and nulls. */
function Value({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === '') {
    return <span className="text-slate-600">not collected</span>;
  }
  if (typeof value === 'boolean') {
    return (
      <span className={value ? 'text-emerald-400' : 'text-severity-high'}>
        {value ? 'yes' : 'no'}
      </span>
    );
  }
  if (Array.isArray(value)) {
    if (!value.length) return <span className="text-slate-600">none</span>;
    return (
      <span className="text-slate-200">
        {value
          .map((entry) => (typeof entry === 'object' ? JSON.stringify(entry) : String(entry)))
          .join(', ')}
      </span>
    );
  }
  if (typeof value === 'object') {
    return <pre className="code mt-1 max-h-40">{JSON.stringify(value, null, 2)}</pre>;
  }
  return <span className="text-slate-200 break-words">{String(value)}</span>;
}

function humanize(key: string): string {
  return key.replace(/_/g, ' ').replace(/^\w/, (char) => char.toUpperCase());
}

/** Splits a collector payload into scalar fields and tabular collections. */
function partition(data: Record<string, unknown>) {
  const scalars: Array<[string, unknown]> = [];
  const tables: Array<[string, Array<Record<string, unknown>>]> = [];
  const nested: Array<[string, Record<string, unknown>]> = [];

  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value)) {
      const rows = value.filter(
        (entry): entry is Record<string, unknown> =>
          typeof entry === 'object' && entry !== null && !Array.isArray(entry),
      );
      if (rows.length) {
        tables.push([key, rows]);
      } else {
        scalars.push([key, value]);
      }
    } else if (value !== null && typeof value === 'object') {
      nested.push([key, value as Record<string, unknown>]);
    } else {
      scalars.push([key, value]);
    }
  }
  return { scalars, tables, nested };
}

function CollectorPanel({ result }: { result: CollectorResult }) {
  const { scalars, tables, nested } = useMemo(() => partition(result.data ?? {}), [result]);
  const [openTable, setOpenTable] = useState<string | null>(
    tables.length ? tables[0][0] : null,
  );

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <span className="font-mono text-xs">{result.collector}</span>
          <StatusChip status={result.status} />
        </span>
      }
      subtitle={result.collection_method}
      actions={
        <span className="text-[11px] text-slate-500">
          collected {formatDate(result.collected_at)}
        </span>
      }
    >
      {(result.errors?.length > 0 || result.warnings?.length > 0) && (
        <div className="mb-4 space-y-2">
          {result.errors?.map((message, index) => (
            <Banner key={`error-${index}`} tone="danger">
              {message}
            </Banner>
          ))}
          {result.warnings?.map((message, index) => (
            <Banner key={`warning-${index}`} tone="warning">
              {message}
            </Banner>
          ))}
        </div>
      )}

      {scalars.length > 0 && (
        <dl className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-x-6 gap-y-3">
          {scalars.map(([key, value]) => (
            <div key={key}>
              <dt className="kv-label">{humanize(key)}</dt>
              <dd className="text-sm">
                <Value value={value} />
              </dd>
            </div>
          ))}
        </dl>
      )}

      {nested.length > 0 && (
        <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
          {nested.map(([key, value]) => (
            <div key={key} className="rounded-lg border border-ink-700 bg-ink-850 p-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                {humanize(key)}
              </p>
              <dl className="space-y-1.5">
                {Object.entries(value).map(([childKey, childValue]) => (
                  <div key={childKey} className="flex items-start justify-between gap-3">
                    <dt className="text-xs text-slate-500">{humanize(childKey)}</dt>
                    <dd className="text-xs text-right max-w-[60%]">
                      <Value value={childValue} />
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      )}

      {tables.length > 0 && (
        <div className="mt-5">
          <div className="flex flex-wrap gap-1.5 mb-3">
            {tables.map(([key, rows]) => (
              <button
                key={key}
                onClick={() => setOpenTable(openTable === key ? null : key)}
                className={`chip ${
                  openTable === key
                    ? 'bg-brand-600/20 text-brand-200 border border-brand-500/50'
                    : 'bg-ink-800 text-slate-400 border border-ink-700'
                }`}
              >
                {humanize(key)} · {rows.length}
              </button>
            ))}
          </div>

          {tables
            .filter(([key]) => key === openTable)
            .map(([key, rows]) => {
              const columns = Array.from(
                rows
                  .slice(0, 40)
                  .reduce<Set<string>>((set, row) => {
                    Object.keys(row).forEach((column) => set.add(column));
                    return set;
                  }, new Set<string>()),
              ).slice(0, 9);
              return (
                <div key={key} className="overflow-x-auto max-h-96 rounded-lg border border-ink-700">
                  <table className="table-base">
                    <thead className="sticky top-0">
                      <tr>
                        {columns.map((column) => (
                          <th key={column}>{humanize(column)}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.slice(0, 200).map((row, index) => (
                        <tr key={index}>
                          {columns.map((column) => (
                            <td key={column} className="text-xs max-w-[260px] truncate">
                              <Value value={row[column]} />
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {rows.length > 200 && (
                    <p className="px-4 py-2 text-[11px] text-slate-500">
                      Showing the first 200 of {rows.length} rows.
                    </p>
                  )}
                </div>
              );
            })}
        </div>
      )}
    </Panel>
  );
}

export default function PostureView({ view }: { view: PostureViewName }) {
  const descriptor = VIEWS[view];
  const [scanId, setScanId] = useState<number | undefined>(undefined);

  const { data: scans } = useApi(() => api.scans({ limit: 50 }), []);
  const effectiveScanId = useMemo(() => {
    if (scanId) return scanId;
    const completed = (scans ?? []).find((scan) =>
      ['completed', 'partial'].includes(scan.status),
    );
    return completed?.id;
  }, [scanId, scans]);

  const { data, loading, error, reload } = useApi(
    () => (effectiveScanId ? api.scanResults(effectiveScanId) : Promise.resolve([])),
    [effectiveScanId],
  );

  const { data: findings } = useApi(
    () =>
      effectiveScanId
        ? api.findings({ scan_id: effectiveScanId, limit: 200 })
        : Promise.resolve([]),
    [effectiveScanId],
  );

  const relevant = (data ?? []).filter((result) =>
    descriptor.collectors.includes(result.collector),
  );
  const relevantFindings = (findings ?? []).filter((finding) =>
    descriptor.findingCategories.includes(finding.category),
  );

  return (
    <>
      <PageHeader
        title={descriptor.title}
        description={descriptor.description}
        actions={
          <select
            className="input w-60 py-1.5"
            value={effectiveScanId ?? ''}
            onChange={(event) =>
              setScanId(event.target.value ? Number(event.target.value) : undefined)
            }
          >
            <option value="">Latest completed scan</option>
            {(scans ?? []).map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} — {scan.target} ({scan.profile})
              </option>
            ))}
          </select>
        }
      />

      {loading && !data ? (
        <Loading label="Loading collected evidence" />
      ) : error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : !effectiveScanId ? (
        <Panel>
          <EmptyState
            title="No completed scan"
            description="This view renders stored collector evidence. Run a scan first."
          />
        </Panel>
      ) : !relevant.length ? (
        <Panel>
          <EmptyState
            title="This scan did not run the required collectors"
            description={`The ${descriptor.title.toLowerCase()} view needs: ${descriptor.collectors.join(', ')}. Re-run with the standard or full profile.`}
          />
        </Panel>
      ) : (
        <div className="space-y-4">
          {relevantFindings.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(['critical', 'high', 'medium', 'low'] as const).map((severity) => (
                <StatCard
                  key={severity}
                  label={`${severity} findings`}
                  value={relevantFindings.filter((f) => f.severity === severity).length}
                  tone={severity}
                />
              ))}
            </div>
          )}

          {relevantFindings.length > 0 && (
            <Panel
              title={`Related findings (${relevantFindings.length})`}
              bodyClassName="p-0"
            >
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Evidence</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {relevantFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <SeverityChip severity={finding.severity} />
                      </td>
                      <td>
                        <Link
                          to={`/findings/${finding.id}`}
                          className="text-slate-100 hover:text-brand-300"
                        >
                          {finding.title}
                        </Link>
                      </td>
                      <td className="text-xs text-slate-500 max-w-[380px]">
                        {finding.evidence_summary}
                      </td>
                      <td className="tabular-nums text-sm text-slate-300">
                        {finding.risk_score.toFixed(0)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}

          {relevant.map((result) => (
            <CollectorPanel key={result.collector} result={result} />
          ))}

          <Banner tone="info">
            Every value above was read from the target at the collection timestamp shown
            on each panel. Fields marked <i>not collected</i> were unavailable — VulScanner
            reports them as unknown rather than assuming an insecure default.
          </Banner>
        </div>
      )}
    </>
  );
}
