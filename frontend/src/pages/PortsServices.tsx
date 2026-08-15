import { useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import {
  Banner,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  RiskBar,
  StatCard,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';

const EXPOSURES = ['', 'all-interfaces', 'private', 'public', 'loopback', 'link-local'];

export default function PortsServices() {
  const [exposure, setExposure] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');

  const { data, loading, error, reload } = useApi(
    () =>
      api.ports({
        exposure: exposure || undefined,
        protocol: protocol || undefined,
        port: port ? Number(port) : undefined,
        limit: 500,
      }),
    [exposure, protocol, port],
  );
  const { data: services } = useApi(() => api.services(), []);

  const reachable = data?.filter((entry) =>
    ['all-interfaces', 'private', 'public'].includes(entry.exposure),
  ).length ?? 0;
  const loopbackOnly = data?.filter((entry) => entry.exposure === 'loopback').length ?? 0;

  const chartData = (services ?? []).slice(0, 12).map((entry) => ({
    name: `${entry.port}/${entry.service}`,
    risk: entry.max_risk_score,
    count: entry.count,
  }));

  return (
    <>
      <PageHeader
        title="Ports & services"
        description="Listening endpoints collected from the scanned hosts, attributed to the owning process and service, and classified by how widely each socket is reachable."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <StatCard label="Listening ports" value={data?.length ?? 0} />
        <StatCard
          label="Network reachable"
          value={reachable}
          tone={reachable ? 'high' : 'default'}
          hint="beyond loopback"
        />
        <StatCard label="Loopback only" value={loopbackOnly} tone="good" hint="not exposed" />
        <StatCard label="Distinct services" value={services?.length ?? 0} />
      </div>

      {chartData.length > 0 && (
        <Panel className="mb-4" title="Highest-risk exposed services">
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={chartData}>
              <CartesianGrid stroke="#152238" vertical={false} />
              <XAxis dataKey="name" stroke="#5c7080" fontSize={10} angle={-20} textAnchor="end" height={54} />
              <YAxis stroke="#5c7080" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0b1220',
                  border: '1px solid #1d3050',
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Bar dataKey="risk" fill="#fb7333" radius={[4, 4, 0, 0]} name="Port risk" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      )}

      <Panel
        bodyClassName="p-0"
        title="Listening endpoints"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-24 py-1.5"
              placeholder="Port"
              value={port}
              onChange={(event) => setPort(event.target.value)}
            />
            <select
              className="input w-28 py-1.5"
              value={protocol}
              onChange={(event) => setProtocol(event.target.value)}
            >
              <option value="">Any protocol</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <select
              className="input w-40 py-1.5"
              value={exposure}
              onChange={(event) => setExposure(event.target.value)}
            >
              {EXPOSURES.map((value) => (
                <option key={value} value={value}>
                  {value || 'Any exposure'}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading label="Loading ports" />
        ) : error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : !data?.length ? (
          <EmptyState title="No ports recorded" description="Run a scan to collect listening endpoints." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Local address</th>
                  <th>Exposure</th>
                  <th>Process</th>
                  <th>Owning service</th>
                  <th>Banner</th>
                  <th>Port risk</th>
                </tr>
              </thead>
              <tbody>
                {data.map((entry) => (
                  <tr key={entry.id}>
                    <td className="font-mono text-brand-300">
                      {entry.protocol}/{entry.port}
                    </td>
                    <td className="text-xs text-slate-200">{entry.service ?? '—'}</td>
                    <td className="font-mono text-xs text-slate-400">
                      {entry.local_address ?? '—'}
                    </td>
                    <td>
                      <span
                        className={`chip ${
                          ['public', 'all-interfaces'].includes(entry.exposure)
                            ? 'bg-severity-high/15 text-severity-high border border-severity-high/40'
                            : entry.exposure === 'loopback'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40'
                              : 'bg-ink-800 text-slate-300 border border-ink-700'
                        }`}
                      >
                        {entry.exposure}
                      </span>
                    </td>
                    <td className="text-xs text-slate-300">
                      {entry.process_name ?? '—'}
                      {entry.process_id ? (
                        <span className="text-slate-600"> ({entry.process_id})</span>
                      ) : null}
                    </td>
                    <td className="text-xs text-slate-400">{entry.owning_service ?? '—'}</td>
                    <td className="text-[11px] font-mono text-slate-500 max-w-[200px] truncate">
                      {entry.banner ?? '—'}
                    </td>
                    <td className="w-32">
                      <RiskBar score={entry.risk_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="mt-4">
        <Banner tone="info">
          Exposure classification: <b>loopback</b> is unreachable from the network;
          <b> all-interfaces</b> means the socket is bound to 0.0.0.0 or ::, so it accepts
          connections on every interface; <b>public</b> means it is bound to a publicly
          routable address.
        </Banner>
      </div>
    </>
  );
}
