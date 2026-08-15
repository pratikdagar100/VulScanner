import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import {
  Banner,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  ScoreGauge,
  SEVERITY_ORDER,
  SeverityChip,
  StatCard,
  StatusChip,
  formatDate,
  formatDuration,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { useScanProgress } from '@/hooks/useScanProgress';
import { api } from '@/services/api';

const ACTIVE = new Set(['queued', 'running']);

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const id = Number(scanId);
  const [reportBusy, setReportBusy] = useState<string | null>(null);

  const { data: scan, loading, error, reload } = useApi(() => api.scan(id), [id], 5000);
  const running = scan ? ACTIVE.has(scan.status) : false;
  const progress = useScanProgress(id, running);

  const { data: findings } = useApi(
    () => api.findings({ scan_id: id, limit: 500 }),
    [id, scan?.status],
  );

  if (loading && !scan) return <Loading label="Loading scan" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!scan) return null;

  const stages = progress.stages.length ? progress.stages : scan.stages ?? [];
  const currentIndex = stages.findIndex((stage) => stage.key === (progress.stage || scan.current_stage));

  async function generate(format: string) {
    setReportBusy(format);
    try {
      const report = await api.createReport(id, format);
      await api.downloadReport(report);
    } finally {
      setReportBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        title={`Scan #${scan.id}`}
        description={`${scan.name} — target ${scan.target} (${scan.target_type}), profile ${scan.profile}, VulScanner ${scan.scanner_version}`}
        actions={
          <>
            {running ? (
              <button
                className="btn-danger"
                onClick={async () => {
                  await api.cancelScan(id).catch(() => undefined);
                  reload();
                }}
              >
                Cancel scan
              </button>
            ) : (
              <>
                <button
                  className="btn-secondary"
                  disabled={reportBusy !== null}
                  onClick={() => generate('html')}
                >
                  {reportBusy === 'html' ? 'Generating…' : 'HTML report'}
                </button>
                <button
                  className="btn-secondary"
                  disabled={reportBusy !== null}
                  onClick={() => generate('pdf')}
                >
                  {reportBusy === 'pdf' ? 'Generating…' : 'PDF report'}
                </button>
              </>
            )}
          </>
        }
      />

      {running && (
        <Panel
          className="mb-4"
          title={
            <span className="flex items-center gap-2">
              Live scan progress
              <span
                className={`chip ${
                  progress.live
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40'
                    : 'bg-slate-500/15 text-slate-400 border border-slate-500/40'
                }`}
              >
                {progress.live ? 'websocket' : 'polling'}
              </span>
            </span>
          }
          subtitle={progress.message || 'Collecting evidence from the target…'}
        >
          <div className="flex items-center gap-4 mb-5">
            <div className="flex-1 h-2.5 rounded-full bg-ink-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-brand-600 to-brand-400 transition-all duration-500"
                style={{ width: `${Math.max(progress.progress, scan.progress)}%` }}
              />
            </div>
            <span className="text-sm font-semibold tabular-nums text-brand-300 w-14 text-right">
              {Math.max(progress.progress, scan.progress).toFixed(0)}%
            </span>
          </div>

          <ul className="space-y-1.5">
            {stages.map((stage, index) => {
              const state =
                index < currentIndex || stage.status === 'complete'
                  ? 'done'
                  : index === currentIndex
                    ? 'running'
                    : 'pending';
              return (
                <li key={stage.key} className="flex items-center gap-2.5 text-sm">
                  <span
                    className={
                      state === 'done'
                        ? 'text-emerald-400'
                        : state === 'running'
                          ? 'text-brand-400 animate-pulse'
                          : 'text-slate-600'
                    }
                  >
                    {state === 'done' ? '✓' : state === 'running' ? '→' : '○'}
                  </span>
                  <span
                    className={
                      state === 'pending' ? 'text-slate-600' : 'text-slate-200'
                    }
                  >
                    {stage.label}
                  </span>
                </li>
              );
            })}
          </ul>
        </Panel>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-4">
        <Panel bodyClassName="p-5 flex items-center justify-center">
          <ScoreGauge score={scan.security_score ?? 0} />
        </Panel>
        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-4">
          <StatCard label="Critical" value={scan.critical_count} tone="critical" />
          <StatCard label="High" value={scan.high_count} tone="high" />
          <StatCard label="Medium" value={scan.medium_count} tone="medium" />
          <StatCard label="Low" value={scan.low_count} tone="low" />
          <StatCard label="Vulnerabilities" value={scan.vulnerability_count} />
          <StatCard label="Status" value={<StatusChip status={scan.status} />} />
          <StatCard label="Duration" value={formatDuration(scan.duration_seconds)} />
          <StatCard label="Assets" value={scan.asset_count} />
          <StatCard
            label="Highest risk"
            value={scan.risk_score !== null ? scan.risk_score.toFixed(0) : '—'}
          />
          <StatCard label="Started" value={<span className="text-sm">{formatDate(scan.started_at)}</span>} />
        </div>
      </div>

      {scan.errors?.length > 0 && (
        <div className="mb-4">
          <Banner tone="danger">
            <p className="font-semibold mb-1">
              {scan.errors.length} collector error(s) — this scan is partial
            </p>
            <ul className="list-disc pl-4 space-y-0.5">
              {scan.errors.slice(0, 6).map((message, index) => (
                <li key={index}>{message}</li>
              ))}
            </ul>
          </Banner>
        </div>
      )}

      {scan.warnings?.length > 0 && (
        <div className="mb-4">
          <Banner tone="warning">
            <p className="font-semibold mb-1">
              {scan.warnings.length} collection warning(s)
            </p>
            <ul className="list-disc pl-4 space-y-0.5">
              {scan.warnings.slice(0, 6).map((message, index) => (
                <li key={index}>{message}</li>
              ))}
            </ul>
            <p className="mt-1.5 opacity-80">
              Data that could not be read is reported as incomplete — never assumed
              insecure.
            </p>
          </Banner>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Panel
          className="xl:col-span-2"
          title={`Findings (${findings?.length ?? 0})`}
          bodyClassName="p-0"
          actions={
            <button
              className="btn-ghost text-xs"
              onClick={() => navigate(`/findings?scan=${id}`)}
            >
              Open in findings →
            </button>
          }
        >
          {!findings?.length ? (
            <EmptyState
              title="No findings"
              description={
                running
                  ? 'Findings appear once analysis completes.'
                  : 'This scan raised no findings.'
              }
            />
          ) : (
            <div className="overflow-x-auto max-h-[540px]">
              <table className="table-base">
                <thead className="sticky top-0">
                  <tr>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Finding</th>
                    <th>Category</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {SEVERITY_ORDER.flatMap((severity) =>
                    findings
                      .filter((finding) => finding.severity === severity)
                      .map((finding) => (
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
                          <td>
                            <p className="text-slate-100">{finding.title}</p>
                            <p className="text-[11px] text-slate-500 font-mono">
                              {finding.finding_uid}
                            </p>
                          </td>
                          <td className="text-xs text-slate-400">{finding.category}</td>
                          <td className="text-xs text-slate-400">{finding.confidence}</td>
                        </tr>
                      )),
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Collection evidence" bodyClassName="p-0">
          <div className="max-h-[540px] overflow-y-auto">
            <table className="table-base">
              <thead className="sticky top-0">
                <tr>
                  <th>Collector</th>
                  <th>Status</th>
                  <th className="text-right">Time</th>
                </tr>
              </thead>
              <tbody>
                {(scan.results ?? []).map((result) => (
                  <tr key={result.id}>
                    <td>
                      <p className="text-slate-200 font-mono text-xs">{result.collector}</p>
                      <p className="text-[10px] text-slate-500 max-w-[220px] truncate">
                        {result.collection_method}
                      </p>
                      {(result.warnings?.length > 0 || result.errors?.length > 0) && (
                        <p className="text-[10px] text-amber-400/80 mt-0.5">
                          {[...(result.errors ?? []), ...(result.warnings ?? [])][0]}
                        </p>
                      )}
                    </td>
                    <td>
                      <StatusChip status={result.status} />
                    </td>
                    <td className="text-right text-[11px] text-slate-500 tabular-nums">
                      {result.duration_seconds?.toFixed(1)}s
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <Panel className="mt-4" title="Scan parameters">
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KeyValue label="Target" value={<span className="font-mono">{scan.target}</span>} />
          <KeyValue label="Target type" value={scan.target_type} />
          <KeyValue label="Profile" value={scan.profile} />
          <KeyValue label="Scanner version" value={scan.scanner_version} />
          <KeyValue label="Started" value={formatDate(scan.started_at)} />
          <KeyValue label="Finished" value={formatDate(scan.finished_at)} />
          <KeyValue label="Collectors run" value={scan.results?.length ?? 0} />
          <KeyValue
            label="CVE correlation"
            value={scan.options?.vulnerability_correlation === false ? 'disabled' : 'enabled'}
          />
        </dl>
      </Panel>
    </>
  );
}
