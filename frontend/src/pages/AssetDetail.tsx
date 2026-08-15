import { useNavigate, useParams } from 'react-router-dom';

import {
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  SeverityChip,
  StatCard,
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const CRITICALITY = ['critical', 'high', 'normal', 'low'];

export default function AssetDetail() {
  const { assetId } = useParams();
  const navigate = useNavigate();
  const id = Number(assetId);

  const { data: asset, loading, error, reload } = useApi(() => api.asset(id), [id]);
  const { data: findings } = useApi(() => api.assetFindings(id), [id]);
  const { data: ports } = useApi(() => api.assetPorts(id), [id]);
  const { data: vulnerabilities } = useApi(
    () => api.vulnerabilities({ asset_id: id, limit: 200 }),
    [id],
  );

  if (loading && !asset) return <Loading label="Loading asset" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!asset) return null;

  return (
    <>
      <PageHeader
        title={asset.hostname ?? asset.ip_address ?? 'Asset'}
        description={`${asset.os_name ?? 'Unknown OS'} · ${asset.ip_address ?? 'no address'} · asset ${asset.asset_uid}`}
        actions={
          <select
            className="input w-44 py-1.5"
            value={asset.criticality}
            onChange={async (event) => {
              await api.setAssetCriticality(id, event.target.value);
              reload();
            }}
          >
            {CRITICALITY.map((value) => (
              <option key={value} value={value}>
                Criticality: {value}
              </option>
            ))}
          </select>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-4">
        <StatCard label="Risk score" value={asset.risk_score.toFixed(0)} tone={asset.severity} />
        <StatCard label="Critical" value={asset.critical_count} tone="critical" />
        <StatCard label="High" value={asset.high_count} tone="high" />
        <StatCard label="Medium" value={asset.medium_count} tone="medium" />
        <StatCard label="Vulnerabilities" value={asset.vulnerability_count} />
        <StatCard label="Exposed ports" value={asset.open_port_count} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Panel title="System information" className="xl:col-span-1">
          <dl className="space-y-3">
            <KeyValue label="Hostname" value={asset.hostname} />
            <KeyValue label="Domain / workgroup" value={asset.domain} />
            <KeyValue
              label="IP addresses"
              value={
                <span className="font-mono text-xs">
                  {asset.ip_addresses?.join(', ') || asset.ip_address || '—'}
                </span>
              }
            />
            <KeyValue
              label="MAC address"
              value={<span className="font-mono text-xs">{asset.mac_address}</span>}
            />
            <KeyValue label="Vendor" value={asset.vendor} />
            <KeyValue label="Operating system" value={asset.os_name} />
            <KeyValue label="Version" value={asset.os_version} />
            <KeyValue label="Build" value={asset.os_build} />
            <KeyValue label="Edition" value={asset.os_edition} />
            <KeyValue label="Architecture" value={asset.architecture} />
            <KeyValue
              label="OS determination"
              value={<StatusChip status={asset.os_confidence} />}
            />
            <KeyValue label="Asset type" value={asset.asset_type} />
            <KeyValue label="First seen" value={formatDate(asset.first_seen)} />
            <KeyValue label="Last seen" value={formatDate(asset.last_seen)} />
          </dl>
        </Panel>

        <div className="xl:col-span-2 space-y-4">
          <Panel title={`Findings (${findings?.length ?? 0})`} bodyClassName="p-0">
            {!findings?.length ? (
              <EmptyState title="No findings" description="No weaknesses recorded for this asset." />
            ) : (
              <div className="overflow-x-auto max-h-96">
                <table className="table-base">
                  <thead className="sticky top-0">
                    <tr>
                      <th>Severity</th>
                      <th>Risk</th>
                      <th>Finding</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding) => (
                      <tr
                        key={finding.id}
                        className="cursor-pointer"
                        onClick={() => navigate(`/findings/${finding.id}`)}
                      >
                        <td>
                          <SeverityChip severity={finding.severity} />
                        </td>
                        <td className="w-28">
                          <RiskBar score={finding.risk_score} />
                        </td>
                        <td className="text-slate-200">{finding.title}</td>
                        <td>
                          <StatusChip status={finding.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title={`Listening ports (${ports?.length ?? 0})`} bodyClassName="p-0">
            {!ports?.length ? (
              <EmptyState title="No ports recorded" description="No listening endpoints were collected." />
            ) : (
              <div className="overflow-x-auto max-h-80">
                <table className="table-base">
                  <thead className="sticky top-0">
                    <tr>
                      <th>Port</th>
                      <th>Service</th>
                      <th>Address</th>
                      <th>Exposure</th>
                      <th>Process</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((port) => (
                      <tr key={port.id}>
                        <td className="font-mono text-brand-300">
                          {port.protocol}/{port.port}
                        </td>
                        <td className="text-xs text-slate-300">{port.service ?? '—'}</td>
                        <td className="font-mono text-xs text-slate-400">
                          {port.local_address ?? '—'}
                        </td>
                        <td className="text-xs text-slate-400">{port.exposure}</td>
                        <td className="text-xs text-slate-400">
                          {port.process_name ?? '—'}
                        </td>
                        <td className="w-28">
                          <RiskBar score={port.risk_score} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {vulnerabilities && vulnerabilities.length > 0 && (
            <Panel title={`Vulnerabilities (${vulnerabilities.length})`} bodyClassName="p-0">
              <div className="overflow-x-auto max-h-80">
                <table className="table-base">
                  <thead className="sticky top-0">
                    <tr>
                      <th>CVE / KB</th>
                      <th>Product</th>
                      <th>CVSS</th>
                      <th>Risk</th>
                      <th>KEV</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.map((vulnerability) => (
                      <tr key={vulnerability.id}>
                        <td className="font-mono text-xs text-brand-300">
                          {vulnerability.cve_id}
                        </td>
                        <td className="text-xs text-slate-300">
                          {vulnerability.product} {vulnerability.product_version}
                        </td>
                        <td className="tabular-nums text-xs">
                          {vulnerability.cvss_score ?? '—'}
                        </td>
                        <td className="w-28">
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
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}
