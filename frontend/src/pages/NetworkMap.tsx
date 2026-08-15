import { useCallback, useMemo, useState } from 'react';
import {
  Background,
  Controls,
  type Edge,
  type Node,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import {
  Banner,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  SEVERITY_STYLES,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api } from '@/services/api';
import type { TopologyEdge, TopologyNode } from '@/types';

const NODE_STYLES: Record<string, { bg: string; border: string; glyph: string }> = {
  scanner: { bg: '#12518f', border: '#4b9ae6', glyph: '◉' },
  gateway: { bg: '#1d3050', border: '#7cb8ee', glyph: '⇅' },
  host: { bg: '#101a2c', border: '#274469', glyph: '▣' },
  switch: { bg: '#1d3050', border: '#8ba0b8', glyph: '⌗' },
  internet: { bg: '#152238', border: '#5c7080', glyph: '☁' },
  subnet: { bg: '#0b1220', border: '#274469', glyph: '⊞' },
};

/** Deterministic layered layout: internet → gateway → hosts, subnets aside. */
function layout(nodes: TopologyNode[]): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};
  const rows: Record<string, TopologyNode[]> = {
    internet: [],
    gateway: [],
    scanner: [],
    switch: [],
    host: [],
    subnet: [],
  };
  for (const node of nodes) (rows[node.type] ?? rows.host).push(node);

  const place = (list: TopologyNode[], y: number, spacing = 210) => {
    const width = (list.length - 1) * spacing;
    list.forEach((node, index) => {
      positions[node.id] = { x: index * spacing - width / 2, y };
    });
  };

  place(rows.internet, 0);
  place(rows.gateway, 140);
  place(rows.switch, 140);
  place(rows.scanner, 280);
  place(rows.subnet, 280, 260);

  // Hosts wrap onto multiple rows so wide subnets stay readable.
  const perRow = Math.max(4, Math.ceil(Math.sqrt(rows.host.length)));
  rows.host.forEach((node, index) => {
    const row = Math.floor(index / perRow);
    const column = index % perRow;
    const count = Math.min(perRow, rows.host.length - row * perRow);
    positions[node.id] = {
      x: column * 200 - ((count - 1) * 200) / 2,
      y: 430 + row * 130,
    };
  });

  return positions;
}

function Graph() {
  const [scanId, setScanId] = useState<number | undefined>(undefined);
  const [riskFilter, setRiskFilter] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [showInferred, setShowInferred] = useState(true);

  const { data: scans } = useApi(() => api.scans({ limit: 50 }), []);
  const { data, loading, error, reload } = useApi(() => api.topology(scanId), [scanId]);

  const filtered = useMemo(() => {
    if (!data) return { nodes: [] as TopologyNode[], edges: [] as TopologyEdge[] };
    const nodes = data.nodes.filter((node) => {
      if (riskFilter && node.severity !== riskFilter) return false;
      if (osFilter && !(node.os_guess ?? '').toLowerCase().includes(osFilter.toLowerCase()))
        return false;
      if (portFilter) {
        const port = Number(portFilter);
        if (!Number.isNaN(port) && !node.open_ports.includes(port)) return false;
      }
      if (search) {
        const haystack = `${node.label} ${node.ip_address} ${node.hostname} ${node.mac_address} ${node.vendor}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
    const ids = new Set(nodes.map((node) => node.id));
    const edges = data.edges.filter(
      (edge) =>
        ids.has(edge.source) &&
        ids.has(edge.target) &&
        (showInferred || edge.confidence === 'observed'),
    );
    return { nodes, edges };
  }, [data, riskFilter, osFilter, portFilter, search, showInferred]);

  const positions = useMemo(() => layout(filtered.nodes), [filtered.nodes]);

  const flowNodes: Node[] = useMemo(
    () =>
      filtered.nodes.map((node) => {
        const style = NODE_STYLES[node.type] ?? NODE_STYLES.host;
        const severityColour =
          node.risk_score > 0 ? SEVERITY_STYLES[node.severity]?.hex : undefined;
        return {
          id: node.id,
          position: positions[node.id] ?? { x: 0, y: 0 },
          data: {
            label: (
              <div className="px-2.5 py-2 text-left">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] opacity-70">{style.glyph}</span>
                  <span className="text-xs font-semibold text-slate-100 truncate max-w-[140px]">
                    {node.label}
                  </span>
                </div>
                {node.ip_address && node.ip_address !== node.label && (
                  <p className="text-[10px] text-slate-400 font-mono">{node.ip_address}</p>
                )}
                {node.open_ports.length > 0 && (
                  <p className="text-[10px] text-brand-300 font-mono">
                    {node.open_ports.slice(0, 4).join(' ')}
                    {node.open_ports.length > 4 ? ` +${node.open_ports.length - 4}` : ''}
                  </p>
                )}
              </div>
            ),
          },
          style: {
            background: style.bg,
            border: `1.5px solid ${severityColour ?? style.border}`,
            borderRadius: 10,
            padding: 0,
            width: 172,
            color: '#e2e8f0',
          },
        };
      }),
    [filtered.nodes, positions],
  );

  const flowEdges: Edge[] = useMemo(
    () =>
      filtered.edges.map((edge: TopologyEdge, index: number) => ({
        id: `${edge.source}->${edge.target}-${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label || undefined,
        animated: edge.confidence === 'observed' && edge.type === 'gateway',
        style: {
          stroke: edge.confidence === 'observed' ? '#4b9ae6' : '#3d4f6b',
          strokeWidth: edge.confidence === 'observed' ? 1.8 : 1.2,
          strokeDasharray: edge.confidence === 'inferred' ? '5 4' : undefined,
        },
        labelStyle: { fill: '#8ba0b8', fontSize: 9 },
        labelBgStyle: { fill: '#0b1220' },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#3d4f6b' },
      })),
    [filtered.edges],
  );

  const [nodes, , onNodesChange] = useNodesState(flowNodes);
  const [edges, , onEdgesChange] = useEdgesState(flowEdges);

  // Keep the canvas in sync when filters change.
  const displayNodes = flowNodes.length === nodes.length ? nodes : flowNodes;
  const displayEdges = flowEdges.length === edges.length ? edges : flowEdges;

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelected(filtered.nodes.find((entry) => entry.id === node.id) ?? null);
    },
    [filtered.nodes],
  );

  if (loading && !data) return <Loading label="Building topology" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;

  return (
    <>
      <PageHeader
        title="Network map"
        description="Nodes and links are built from collected evidence. Solid links were directly observed; dashed links are inferred from IP addressing and describe logical reachability, not physical cabling."
        actions={
          <select
            className="input w-56 py-1.5"
            value={scanId ?? ''}
            onChange={(event) =>
              setScanId(event.target.value ? Number(event.target.value) : undefined)
            }
          >
            <option value="">Latest topology</option>
            {(scans ?? []).map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} — {scan.target}
              </option>
            ))}
          </select>
        }
      />

      {!data?.nodes.length ? (
        <Panel>
          <EmptyState
            title="No topology data"
            description="Run a scan with network discovery enabled, or: vulscanner network discover --scope 192.168.1.0/24"
          />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
          <Panel
            className="xl:col-span-3"
            bodyClassName="p-0"
            title={`${filtered.nodes.length} nodes · ${filtered.edges.length} links`}
            subtitle={`${data.observed_edges} observed · ${data.inferred_edges} inferred`}
            actions={
              <div className="flex flex-wrap items-center gap-2">
                <input
                  className="input w-40 py-1.5"
                  placeholder="Search host…"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
                <input
                  className="input w-24 py-1.5"
                  placeholder="Port"
                  value={portFilter}
                  onChange={(event) => setPortFilter(event.target.value)}
                />
                <input
                  className="input w-28 py-1.5"
                  placeholder="OS"
                  value={osFilter}
                  onChange={(event) => setOsFilter(event.target.value)}
                />
                <select
                  className="input w-32 py-1.5"
                  value={riskFilter}
                  onChange={(event) => setRiskFilter(event.target.value)}
                >
                  <option value="">All risk</option>
                  {['critical', 'high', 'medium', 'low', 'informational'].map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
                <label className="flex items-center gap-1.5 text-xs text-slate-400 whitespace-nowrap">
                  <input
                    type="checkbox"
                    className="accent-brand-500"
                    checked={showInferred}
                    onChange={(event) => setShowInferred(event.target.checked)}
                  />
                  inferred links
                </label>
              </div>
            }
          >
            <div className="h-[620px] rounded-b-xl overflow-hidden">
              <ReactFlow
                nodes={displayNodes}
                edges={displayEdges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                fitView
                minZoom={0.2}
                maxZoom={2}
                proOptions={{ hideAttribution: true }}
              >
                <Background color="#1d3050" gap={22} />
                <Controls className="!bg-ink-850 !border-ink-700 [&_button]:!bg-ink-850 [&_button]:!border-ink-700 [&_button]:!fill-slate-400" />
                <MiniMap
                  pannable
                  zoomable
                  style={{ background: '#0b1220', border: '1px solid #1d3050' }}
                  maskColor="rgba(7,12,20,.7)"
                  nodeColor={(node) =>
                    NODE_STYLES[(node.id.split(':')[0] as string) ?? 'host']?.border ?? '#274469'
                  }
                />
              </ReactFlow>
            </div>
          </Panel>

          <div className="space-y-4">
            <Panel title="Selected node">
              {selected ? (
                <dl className="space-y-3">
                  <KeyValue label="Label" value={selected.label} />
                  <KeyValue label="Type" value={selected.type} />
                  <KeyValue
                    label="IP address"
                    value={<span className="font-mono">{selected.ip_address || '—'}</span>}
                  />
                  <KeyValue
                    label="MAC address"
                    value={<span className="font-mono">{selected.mac_address || '—'}</span>}
                  />
                  <KeyValue label="Vendor" value={selected.vendor || '—'} />
                  <KeyValue
                    label="Operating system"
                    value={
                      selected.os_guess ? (
                        <span>
                          {selected.os_guess}{' '}
                          <span className="text-xs text-slate-500">
                            ({selected.os_confidence} confidence)
                          </span>
                        </span>
                      ) : (
                        'Unknown'
                      )
                    }
                  />
                  <KeyValue
                    label="Open ports"
                    value={
                      selected.open_ports.length ? (
                        <span className="font-mono text-xs">
                          {selected.open_ports.join(', ')}
                        </span>
                      ) : (
                        'None recorded'
                      )
                    }
                  />
                  {selected.metadata?.discovery_method && (
                    <KeyValue
                      label="Discovery method"
                      value={String(selected.metadata.discovery_method)}
                    />
                  )}
                </dl>
              ) : (
                <p className="text-xs text-slate-500">
                  Select a node on the map to inspect its collected attributes.
                </p>
              )}
            </Panel>

            <Panel title="Legend">
              <ul className="space-y-2 text-xs">
                {Object.entries(NODE_STYLES).map(([type, style]) => (
                  <li key={type} className="flex items-center gap-2 text-slate-400">
                    <span
                      className="w-4 h-4 rounded"
                      style={{ background: style.bg, border: `1.5px solid ${style.border}` }}
                    />
                    {style.glyph} {type}
                  </li>
                ))}
                <li className="flex items-center gap-2 text-slate-400 pt-2 border-t border-ink-800">
                  <svg width="26" height="6">
                    <line x1="0" y1="3" x2="26" y2="3" stroke="#4b9ae6" strokeWidth="2" />
                  </svg>
                  observed link
                </li>
                <li className="flex items-center gap-2 text-slate-400">
                  <svg width="26" height="6">
                    <line
                      x1="0"
                      y1="3"
                      x2="26"
                      y2="3"
                      stroke="#3d4f6b"
                      strokeWidth="1.5"
                      strokeDasharray="5 4"
                    />
                  </svg>
                  inferred link
                </li>
              </ul>
            </Panel>

            <Banner tone="info">{data.confidence_note}</Banner>
          </div>
        </div>
      )}
    </>
  );
}

export default function NetworkMap() {
  return (
    <ReactFlowProvider>
      <Graph />
    </ReactFlowProvider>
  );
}
