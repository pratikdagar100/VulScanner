import { useState } from 'react';

import {
  Banner,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  SeverityChip,
  StatCard,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';
import type { Vulnerability } from '@/types';

export default function Vulnerabilities() {
  const [kevOnly, setKevOnly] = useState(false);
  const [severity, setSeverity] = useState('');
  const [product, setProduct] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const { data, loading, error, reload } = useApi(
    () =>
      api.vulnerabilities({
        kev: kevOnly ? true : undefined,
        severity: severity || undefined,
        product: product || undefined,
        limit: 400,
      }),
    [kevOnly, severity, product],
  );
  const { data: intelligence } = useApi(() => api.intelligence(), []);

  const kevCount = data?.filter((entry) => entry.kev).length ?? 0;
  const confirmed = data?.filter((entry) => entry.confidence === 'confirmed').length ?? 0;

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="CVEs correlated to inventoried software by CPE match, plus missing security updates confirmed by the Windows Update agent. A CVE is never attached to a host without version or KB evidence."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <StatCard label="Correlated" value={data?.length ?? 0} />
        <StatCard
          label="CISA KEV"
          value={kevCount}
          tone={kevCount ? 'critical' : 'default'}
          hint="known exploited in the wild"
        />
        <StatCard label="Confirmed evidence" value={confirmed} hint="agent-verified" />
        <StatCard
          label="KEV catalogue"
          value={(intelligence?.kev_entries ?? 0).toLocaleString()}
          hint={intelligence?.online ? 'NVD online' : 'NVD offline'}
        />
      </div>

      {intelligence && !intelligence.nvd_api_key_configured && intelligence.online && (
        <div className="mb-4">
          <Banner tone="warning">
            No NVD API key is configured, so CVE lookups are rate limited to one request
            every six seconds and correlation covers fewer products per scan. Set
            VULSCANNER_NVD_API_KEY in .env to raise the limit.
          </Banner>
        </div>
      )}

      <Panel
        bodyClassName="p-0"
        title={`${data?.length ?? 0} vulnerability records`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-40 py-1.5"
              placeholder="Product…"
              value={product}
              onChange={(event) => setProduct(event.target.value)}
            />
            <select
              className="input w-32 py-1.5"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="">All severity</option>
              {['critical', 'high', 'medium', 'low'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1.5 text-xs text-slate-400">
              <input
                type="checkbox"
                className="accent-brand-500"
                checked={kevOnly}
                onChange={(event) => setKevOnly(event.target.checked)}
              />
              KEV only
            </label>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading vulnerabilities" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No correlated vulnerabilities"
            description="Nothing in the software inventory matched a CVE with sufficient version evidence, and the Windows Update agent reported no missing security updates."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>CVE / KB</th>
                  <th>Product</th>
                  <th>Installed</th>
                  <th>Affected range</th>
                  <th>Official CVSS</th>
                  <th>VulScanner risk</th>
                  <th>KEV</th>
                  <th>Confidence</th>
                  <th>Match</th>
                </tr>
              </thead>
              <tbody>
                {data.map((vulnerability: Vulnerability) => (
                  <>
                    <tr
                      key={vulnerability.id}
                      className="cursor-pointer"
                      onClick={() =>
                        setExpanded(expanded === vulnerability.id ? null : vulnerability.id)
                      }
                    >
                      <td className="font-mono text-xs text-brand-300">
                        {vulnerability.cve_id}
                      </td>
                      <td className="text-slate-200 text-xs">{vulnerability.product}</td>
                      <td className="font-mono text-xs text-slate-400">
                        {vulnerability.product_version || '—'}
                      </td>
                      <td className="font-mono text-[11px] text-slate-500 max-w-[180px] truncate">
                        {vulnerability.affected_versions || '—'}
                      </td>
                      <td className="tabular-nums text-slate-300">
                        {vulnerability.cvss_score ?? '—'}
                      </td>
                      <td className="w-32">
                        <RiskBar score={vulnerability.risk_score} />
                      </td>
                      <td>
                        {vulnerability.kev ? (
                          <span className="chip bg-severity-critical/15 text-severity-critical border border-severity-critical/40">
                            KEV
                          </span>
                        ) : (
                          <span className="text-xs text-slate-600">—</span>
                        )}
                      </td>
                      <td>
                        <SeverityChip severity={vulnerability.severity} />
                      </td>
                      <td className="text-[11px] text-slate-500">
                        {vulnerability.match_method}
                      </td>
                    </tr>
                    {expanded === vulnerability.id && (
                      <tr key={`${vulnerability.id}-detail`}>
                        <td colSpan={9} className="bg-ink-950/60">
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 py-2">
                            <div>
                              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                                Remediation
                              </p>
                              <p className="text-sm text-slate-300">
                                {vulnerability.remediation}
                              </p>
                              {vulnerability.patch && (
                                <p className="mt-2 text-xs text-slate-400">
                                  Patch: <span className="font-mono">{vulnerability.patch}</span>
                                </p>
                              )}
                              {vulnerability.references?.length > 0 && (
                                <ul className="mt-2 space-y-0.5">
                                  {vulnerability.references.slice(0, 5).map((reference) => (
                                    <li key={reference}>
                                      <a
                                        href={reference}
                                        target="_blank"
                                        rel="noreferrer noopener"
                                        className="text-[11px] text-brand-300 hover:text-brand-200 break-all"
                                      >
                                        {reference}
                                      </a>
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </div>
                            <div>
                              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                                Evidence
                              </p>
                              <pre className="code max-h-52">
                                {JSON.stringify(vulnerability.evidence, null, 2)}
                              </pre>
                            </div>
                          </div>
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
    </>
  );
}
