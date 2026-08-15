import { useState } from 'react';

import {
  Banner,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  StatusChip,
  formatBytes,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const FORMATS = ['html', 'pdf', 'json', 'csv'] as const;

export default function Reports() {
  const [scanId, setScanId] = useState<number | ''>('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: scans } = useApi(() => api.scans({ limit: 100 }), []);
  const { data, loading, error: loadError, reload } = useApi(() => api.reports({ limit: 200 }), []);

  const reportable = (scans ?? []).filter((scan) =>
    ['completed', 'partial', 'cancelled', 'failed'].includes(scan.status),
  );

  async function generate(format: string) {
    const target = scanId || reportable[0]?.id;
    if (!target) {
      setError('Run a scan before generating a report.');
      return;
    }
    setBusy(format);
    setError(null);
    try {
      const report = await api.createReport(Number(target), format);
      await api.downloadReport(report);
      reload();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Reports"
        description="VulScanner Security Assessment Reports carry the scan id, timestamps, target, scanner version, profile and per-collector evidence timestamps."
      />

      <Panel className="mb-4" title="Generate a report">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[280px]">
            <label className="label" htmlFor="scan">
              Scan
            </label>
            <select
              id="scan"
              className="input"
              value={scanId}
              onChange={(event) =>
                setScanId(event.target.value ? Number(event.target.value) : '')
              }
            >
              <option value="">Most recent scan</option>
              {reportable.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} — {scan.target} ({scan.profile},{' '}
                  {scan.critical_count + scan.high_count} critical/high)
                </option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            {FORMATS.map((format) => (
              <button
                key={format}
                className={format === 'html' ? 'btn-primary' : 'btn-secondary'}
                disabled={busy !== null}
                onClick={() => generate(format)}
              >
                {busy === format ? 'Generating…' : format.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        {error && (
          <div className="mt-3">
            <Banner tone="danger">{error}</Banner>
          </div>
        )}
        <p className="mt-3 text-[11px] text-slate-500">
          PDF generation is pure Python (ReportLab) — no external binary or browser is
          required on the server.
        </p>
      </Panel>

      <Panel bodyClassName="p-0" title={`Generated reports (${data?.length ?? 0})`}>
        {loading && !data ? (
          <Loading label="Loading reports" />
        ) : loadError ? (
          <ErrorState message={loadError} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No reports yet"
            description="Generate one above, or from the CLI: vulscanner report --scan-id <ID> --pdf"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Scan</th>
                  <th>Format</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Size</th>
                  <th>Generated</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((report) => (
                  <tr key={report.id}>
                    <td className="text-xs font-mono text-slate-300">{report.file_name}</td>
                    <td className="text-xs text-slate-400">#{report.scan_id}</td>
                    <td className="text-xs uppercase text-brand-300">{report.format}</td>
                    <td>
                      <StatusChip status={report.status} />
                    </td>
                    <td className="text-xs text-slate-400 tabular-nums">
                      {report.summary?.total_findings ?? '—'}
                    </td>
                    <td className="text-xs text-slate-400">{formatBytes(report.size_bytes)}</td>
                    <td className="text-xs text-slate-500">{formatDate(report.generated_at)}</td>
                    <td className="text-right whitespace-nowrap">
                      <button
                        className="btn-ghost text-xs"
                        onClick={() => api.downloadReport(report)}
                      >
                        Download
                      </button>
                      <button
                        className="btn-ghost text-xs text-severity-critical"
                        onClick={async () => {
                          await api.deleteReport(report.id).catch(() => undefined);
                          reload();
                        }}
                      >
                        Delete
                      </button>
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
