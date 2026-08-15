import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import {
  Banner,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  SeverityChip,
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';
import type { FindingStatus } from '@/types';

const TRIAGE: Array<{ value: FindingStatus; label: string }> = [
  { value: 'resolved', label: 'Mark resolved' },
  { value: 'reopened', label: 'Reopen' },
  { value: 'risk_accepted', label: 'Accept risk' },
  { value: 'false_positive', label: 'False positive' },
];

export default function FindingDetail() {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const id = Number(findingId);

  const { data, loading, error, reload } = useApi(() => api.finding(id), [id]);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  if (loading && !data) return <Loading label="Loading finding" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return null;

  async function triage(status: FindingStatus) {
    setBusy(true);
    setTriageError(null);
    try {
      await api.updateFinding(id, status, note);
      setNote('');
      reload();
    } catch (exc) {
      setTriageError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  const factors = data.risk_factors ?? {};

  return (
    <>
      <PageHeader
        title={data.title}
        description={`${data.finding_uid} · rule ${data.rule_id} · ${data.category}`}
        actions={
          <button className="btn-secondary" onClick={() => navigate(-1)}>
            ← Back
          </button>
        }
      />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 space-y-4">
          <Panel title="Assessment">
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <SeverityChip severity={data.severity} />
              <StatusChip status={data.status} />
              <span className="chip bg-ink-800 text-slate-300 border border-ink-700">
                confidence: {data.confidence}
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-5">
              <div className="rounded-lg border border-brand-500/40 bg-brand-600/10 px-4 py-3">
                <p className="text-[11px] uppercase tracking-wider text-brand-300">
                  VulScanner risk score
                </p>
                <p className="text-3xl font-bold text-brand-200 tabular-nums">
                  {data.risk_score.toFixed(0)}
                  <span className="text-sm text-brand-400/70">/100</span>
                </p>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  This weakness, on this asset
                </p>
              </div>
              <div className="rounded-lg border border-ink-700 bg-ink-850 px-4 py-3">
                <p className="text-[11px] uppercase tracking-wider text-slate-400">
                  Official CVSS
                </p>
                <p className="text-3xl font-bold text-slate-200 tabular-nums">
                  {data.cvss_score ?? '—'}
                </p>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  {data.cvss_score !== null
                    ? 'NVD base score, reported separately'
                    : 'Not a CVE-backed finding'}
                </p>
              </div>
              <div className="rounded-lg border border-ink-700 bg-ink-850 px-4 py-3">
                <p className="text-[11px] uppercase tracking-wider text-slate-400">
                  Detection method
                </p>
                <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                  {data.detection_method}
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  What is wrong
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">{data.description}</p>
              </div>
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Why it matters
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">{data.impact}</p>
              </div>
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Recommended fix
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">{data.remediation}</p>
                {data.remediation_command && (
                  <>
                    <pre className="code mt-2">{data.remediation_command}</pre>
                    <p className="mt-1.5 text-[11px] text-slate-500">
                      Guidance only — VulScanner does not run this for you. Review it
                      against your change-control process first.
                    </p>
                  </>
                )}
              </div>
              {data.references?.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                    References
                  </h3>
                  <ul className="space-y-1">
                    {data.references.map((reference) => (
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
                </div>
              )}
            </div>
          </Panel>

          <Panel title="Evidence" subtitle={data.evidence_summary}>
            <pre className="code max-h-96">
              {JSON.stringify(data.evidence, null, 2)}
            </pre>
          </Panel>

          <Panel
            title="How this risk score was calculated"
            subtitle={typeof factors.formula === 'string' ? factors.formula : undefined}
          >
            <pre className="code max-h-80">{JSON.stringify(factors, null, 2)}</pre>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Details">
            <dl className="space-y-3">
              <KeyValue label="Finding ID" value={<span className="font-mono text-xs">{data.finding_uid}</span>} />
              <KeyValue label="Rule" value={data.rule_id} />
              <KeyValue label="Category" value={data.category} />
              <KeyValue label="Scan" value={data.scan_id ? `#${data.scan_id}` : '—'} />
              <KeyValue label="Asset" value={data.asset_id ? `#${data.asset_id}` : '—'} />
              <KeyValue label="First detected" value={formatDate(data.first_detected_at)} />
              <KeyValue label="Last detected" value={formatDate(data.last_detected_at)} />
              <KeyValue label="Resolved" value={formatDate(data.resolved_at)} />
            </dl>
          </Panel>

          <Panel title="Triage">
            {data.status_note && (
              <div className="mb-3">
                <Banner tone="info">{data.status_note}</Banner>
              </div>
            )}
            <label className="label" htmlFor="note">
              Note
            </label>
            <textarea
              id="note"
              className="input min-h-[84px]"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Why is the status changing? Required when accepting risk."
            />
            {triageError && (
              <div className="mt-3">
                <Banner tone="danger">{triageError}</Banner>
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-2">
              {TRIAGE.map((entry) => (
                <button
                  key={entry.value}
                  className="btn-secondary text-xs"
                  disabled={busy || data.status === entry.value}
                  onClick={() => triage(entry.value)}
                >
                  {entry.label}
                </button>
              ))}
            </div>
            <p className="mt-3 text-[11px] text-slate-500">
              Status changes are written to the audit log with your username and the
              note above. Accepting risk requires the administrator role.
            </p>
          </Panel>
        </div>
      </div>
    </>
  );
}
