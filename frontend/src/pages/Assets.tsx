import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  SeverityChip,
  formatDate,
} from '@/components/ui';
import { useApi, useDebounced } from '@/hooks/useApi';
import { api } from '@/services/api';

export default function Assets() {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [port, setPort] = useState('');
  const [cve, setCve] = useState('');
  const debounced = useDebounced(search);

  const { data, loading, error, reload } = useApi(
    () =>
      api.assets({
        search: debounced || undefined,
        severity: severity || undefined,
        port: port ? Number(port) : undefined,
        cve: cve || undefined,
        limit: 300,
      }),
    [debounced, severity, port, cve],
  );

  return (
    <>
      <PageHeader
        title="Asset inventory"
        description="Every host VulScanner has observed, searchable by hostname, IP, MAC, vendor, exposed port or affected CVE."
      />

      <Panel
        bodyClassName="p-0"
        title={`${data?.length ?? 0} assets`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-52 py-1.5"
              placeholder="Hostname, IP, MAC, vendor…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <input
              className="input w-24 py-1.5"
              placeholder="Port"
              value={port}
              onChange={(event) => setPort(event.target.value)}
            />
            <input
              className="input w-40 py-1.5"
              placeholder="CVE-2021-34527"
              value={cve}
              onChange={(event) => setCve(event.target.value)}
            />
            <select
              className="input w-32 py-1.5"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="">All severity</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading assets" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState
            title="No assets"
            description="Assets are created from scan evidence. Run a scan to populate the inventory."
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
                  <th>Asset</th>
                  <th>Addresses</th>
                  <th>Operating system</th>
                  <th>Type</th>
                  <th>Criticality</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Findings</th>
                  <th>Ports</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.map((asset) => (
                  <tr
                    key={asset.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    <td>
                      <p className="font-medium text-slate-100">
                        {asset.hostname ?? asset.ip_address ?? asset.asset_uid.slice(0, 8)}
                      </p>
                      <p className="text-[11px] text-slate-500">{asset.domain ?? '—'}</p>
                    </td>
                    <td className="font-mono text-xs text-brand-300">
                      <p>{asset.ip_address ?? '—'}</p>
                      <p className="text-slate-500">{asset.mac_address ?? ''}</p>
                    </td>
                    <td className="text-xs text-slate-300">
                      <p>{asset.os_name ?? '—'}</p>
                      <p className="text-slate-500">
                        {asset.os_version} {asset.os_build ? `(${asset.os_build})` : ''}
                      </p>
                    </td>
                    <td className="text-xs text-slate-400">{asset.asset_type}</td>
                    <td className="text-xs text-slate-400">{asset.criticality}</td>
                    <td>
                      <SeverityChip severity={asset.severity} />
                    </td>
                    <td className="w-32">
                      <RiskBar score={asset.risk_score} />
                    </td>
                    <td className="text-xs tabular-nums">
                      <span className="text-severity-critical">{asset.critical_count}</span>
                      {' / '}
                      <span className="text-severity-high">{asset.high_count}</span>
                      {' / '}
                      <span className="text-slate-400">{asset.finding_count}</span>
                    </td>
                    <td className="text-xs tabular-nums text-slate-400">
                      {asset.open_port_count}
                    </td>
                    <td className="text-xs text-slate-500">{formatDate(asset.last_seen)}</td>
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
