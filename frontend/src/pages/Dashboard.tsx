import { useNavigate } from 'react-router-dom';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
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
  ScoreGauge,
  SEVERITY_ORDER,
  SEVERITY_STYLES,
  SeverityChip,
  StatCard,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';
import type { Severity } from '@/types';

const AXIS = { stroke: '#5c7080', fontSize: 11 };
const GRID = '#152238';

const TOOLTIP_STYLE = {
  backgroundColor: '#0b1220',
  border: '1px solid #1d3050',
  borderRadius: 8,
  fontSize: 12,
  color: '#e2e8f0',
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(() => api.dashboard(), [], 20000);

  if (loading && !data) return <Loading label="Loading dashboard" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return null;

  const hasData = data.total_scans > 0;

  const severityData = SEVERITY_ORDER.map((severity) => ({
    name: severity,
    value: data.severity_counts[severity] ?? 0,
    fill: SEVERITY_STYLES[severity].hex,
  })).filter((entry) => entry.value > 0);

  const categoryData = Object.entries(data.category_distribution)
    .map(([name, value]) => ({ name, value }))
    .slice(0, 10);

  const trendData = data.risk_trend.map((entry) => ({
    name: `#${entry.scan_id}`,
    score: entry.security_score,
    critical: entry.critical,
    high: entry.high,
  }));

  return (
    <>
      <PageHeader
        title="Security posture"
        description="Every value below is computed from stored scan evidence. An empty dashboard means no scan has run yet."
        actions={
          <>
            <button className="btn-secondary" onClick={reload}>
              Refresh
            </button>
            <button className="btn-primary" onClick={() => navigate('/scans/new')}>
              Scan my computer
            </button>
          </>
        }
      />

      {!hasData && (
        <div className="panel mb-6">
          <EmptyState
            title="No assessment data yet"
            description="Run your first scan to populate the dashboard. VulScanner never seeds sample findings, so every number here will come from a real collection against a target you are authorized to assess."
            action={
              <button className="btn-primary" onClick={() => navigate('/scans/new')}>
                Start a scan
              </button>
            }
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-4">
        <Panel className="lg:col-span-1" bodyClassName="p-5 flex items-center justify-center">
          <ScoreGauge score={data.security_score} />
        </Panel>

        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-4">
          {SEVERITY_ORDER.map((severity) => (
            <StatCard
              key={severity}
              label={severity}
              value={data.severity_counts[severity] ?? 0}
              tone={severity as Severity}
              hint="open findings"
            />
          ))}
          <StatCard label="Total assets" value={data.total_assets} hint={`${data.scanned_assets} scanned`} />
          <StatCard label="Vulnerabilities" value={data.vulnerability_count} hint={`${data.kev_vulnerability_count} in CISA KEV`} tone={data.kev_vulnerability_count ? 'critical' : 'default'} />
          <StatCard label="Missing updates" value={data.missing_updates} hint={`${data.patch_status.coverage_percent}% patch coverage`} />
          <StatCard label="Exposed ports" value={data.exposed_ports} hint="network reachable" />
          <StatCard label="Misconfigurations" value={data.misconfigurations} hint="configuration weaknesses" />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <Panel title="Severity distribution" subtitle="Open findings by VulScanner severity">
          {severityData.length ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={54}
                  outerRadius={84}
                  paddingAngle={2}
                  stroke="#0b1220"
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend
                  verticalAlign="bottom"
                  iconType="circle"
                  formatter={(value) => (
                    <span style={{ color: '#94a3b8', fontSize: 11 }}>{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="No open findings" description="Nothing to plot yet." />
          )}
        </Panel>

        <Panel title="Findings by category" subtitle="Where the weaknesses cluster">
          {categoryData.length ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={categoryData} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid stroke={GRID} horizontal={false} />
                <XAxis type="number" {...AXIS} allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={92} {...AXIS} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#101a2c' }} />
                <Bar dataKey="value" fill="#2481d8" radius={[0, 4, 4, 0]} barSize={13} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="No categories" description="Run a scan to populate this view." />
          )}
        </Panel>

        <Panel title="Security score trend" subtitle="Across recent completed scans">
          {trendData.length > 1 ? (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={trendData}>
                <CartesianGrid stroke={GRID} />
                <XAxis dataKey="name" {...AXIS} />
                <YAxis domain={[0, 100]} {...AXIS} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Line type="monotone" dataKey="score" stroke="#4b9ae6" strokeWidth={2} dot={{ r: 3 }} name="Security score" />
                <Line type="monotone" dataKey="critical" stroke="#f0356b" strokeWidth={1.5} dot={false} name="Critical" />
                <Line type="monotone" dataKey="high" stroke="#fb7333" strokeWidth={1.5} dot={false} name="High" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              title="Not enough history"
              description="At least two completed scans are needed before a trend can be drawn."
            />
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel
          title="Top risky assets"
          subtitle="Ranked by the highest VulScanner risk score observed"
          bodyClassName="p-0"
          actions={
            <button className="btn-ghost text-xs" onClick={() => navigate('/assets')}>
              View all →
            </button>
          }
        >
          {data.top_risky_assets.length ? (
            <table className="table-base">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Operating system</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th className="text-right">Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.top_risky_assets.map((asset) => (
                  <tr
                    key={asset.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    <td>
                      <p className="font-medium text-slate-100">{asset.hostname ?? asset.ip_address}</p>
                      <p className="text-xs text-slate-500">{asset.ip_address}</p>
                    </td>
                    <td className="text-slate-400 text-xs">{asset.os_name ?? '—'}</td>
                    <td>
                      <SeverityChip severity={asset.severity} />
                    </td>
                    <td className="w-40">
                      <RiskBar score={asset.risk_score} />
                    </td>
                    <td className="text-right tabular-nums">
                      <span className="text-severity-critical">{asset.critical_count}</span>
                      {' / '}
                      <span className="text-severity-high">{asset.high_count}</span>
                      {' / '}
                      <span className="text-slate-400">{asset.finding_count}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState title="No assets yet" description="Assets appear after the first successful scan." />
          )}
        </Panel>

        <Panel
          title="Most exposed services"
          subtitle="Listening ports reachable beyond loopback"
          bodyClassName="p-0"
          actions={
            <button className="btn-ghost text-xs" onClick={() => navigate('/ports')}>
              View all →
            </button>
          }
        >
          {data.exposed_services.length ? (
            <table className="table-base">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Instances</th>
                  <th>Highest port risk</th>
                </tr>
              </thead>
              <tbody>
                {data.exposed_services.map((service) => (
                  <tr key={`${service.port}-${service.service}`}>
                    <td className="font-mono text-brand-300">{service.port}</td>
                    <td className="text-slate-200">{service.service}</td>
                    <td className="tabular-nums text-slate-400">{service.count}</td>
                    <td className="w-40">
                      <RiskBar score={service.max_risk_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState title="No exposed services" description="No listening ports reachable from the network were recorded." />
          )}
        </Panel>
      </div>

      <div className="mt-4">
        <Banner tone="info">
          Vulnerability intelligence: CISA KEV catalogue{' '}
          {data.intelligence.kev_available
            ? `loaded (${data.intelligence.kev_entries.toLocaleString()} entries)`
            : 'unavailable'}
          , NVD lookups {data.intelligence.online ? 'enabled' : 'disabled'}
          {data.intelligence.online && !data.intelligence.nvd_api_key_configured &&
            ' — no NVD API key configured, so correlation is rate limited to one request every 6 seconds'}
          . Last scan finished {formatDate(data.last_scan_at)}.
        </Banner>
      </div>
    </>
  );
}
