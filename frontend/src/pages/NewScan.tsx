import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Banner, PageHeader, Panel } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { ApiError, api } from '@/services/api';

type TargetMode = 'local' | 'remote' | 'network';

const MODES: Array<{ id: TargetMode; title: string; description: string; glyph: string }> = [
  {
    id: 'local',
    title: 'Scan my computer',
    description: 'Assess the Windows machine running VulScanner. No credentials needed.',
    glyph: '▣',
  },
  {
    id: 'remote',
    title: 'Scan a remote host',
    description: 'Assess an authorized Windows host over WinRM using your credentials.',
    glyph: '⇄',
  },
  {
    id: 'network',
    title: 'Discover a network',
    description: 'Enumerate live hosts and exposed services across an authorized subnet.',
    glyph: '⬡',
  },
];

export default function NewScan() {
  const navigate = useNavigate();
  const { data: profiles } = useApi(() => api.scanProfiles(), []);

  const [mode, setMode] = useState<TargetMode>('local');
  const [target, setTarget] = useState('local');
  const [profile, setProfile] = useState('standard');
  const [name, setName] = useState('');
  const [ports, setPorts] = useState('');
  const [discoveryProfile, setDiscoveryProfile] = useState('safe');
  const [networkDiscovery, setNetworkDiscovery] = useState(false);
  const [correlate, setCorrelate] = useState(true);
  const [generateReport, setGenerateReport] = useState(false);
  const [bannerGrab, setBannerGrab] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [guidance, setGuidance] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedProfile = useMemo(
    () => profiles?.find((entry) => entry.name === profile),
    [profiles, profile],
  );

  function applyMode(next: TargetMode) {
    setMode(next);
    setError(null);
    if (next === 'local') {
      setTarget('local');
      setProfile('standard');
    } else if (next === 'remote') {
      setTarget('');
      setProfile('standard');
    } else {
      setTarget('');
      setProfile('network');
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setGuidance(null);

    try {
      const scan = await api.createScan({
        name: name || undefined,
        target: target.trim(),
        profile,
        options: {
          ports: ports || undefined,
          discovery_profile: discoveryProfile,
          network_discovery: mode === 'network' ? true : networkDiscovery,
          banner_grab: bannerGrab,
          vulnerability_correlation: correlate,
          generate_report: generateReport,
        },
        credential:
          mode === 'remote' && username
            ? { username, password }
            : undefined,
      });
      navigate(`/scans/${scan.id}`);
    } catch (exc) {
      if (exc instanceof ApiError) {
        setError(exc.message);
        if (exc.isAuthorizationBoundary) {
          setGuidance(
            (exc.body as { guidance?: string })?.guidance ??
              'Register the target as authorized before scanning it.',
          );
        }
      } else {
        setError(String(exc));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="New scan"
        description="VulScanner will refuse any target outside the configured authorized scope. Scan only systems you have permission to assess."
      />

      <form onSubmit={handleSubmit} className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 space-y-4">
          <Panel title="What do you want to assess?">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {MODES.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => applyMode(entry.id)}
                  className={`text-left rounded-xl border p-4 transition-colors ${
                    mode === entry.id
                      ? 'border-brand-500 bg-brand-600/10'
                      : 'border-ink-700 bg-ink-850 hover:border-ink-600'
                  }`}
                >
                  <span className="text-lg text-brand-300">{entry.glyph}</span>
                  <p className="mt-2 text-sm font-semibold text-slate-100">{entry.title}</p>
                  <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                    {entry.description}
                  </p>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="Target">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="label" htmlFor="target">
                  {mode === 'network' ? 'Network scope (CIDR)' : 'Target'}
                </label>
                <input
                  id="target"
                  className="input font-mono"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={
                    mode === 'local'
                      ? 'local'
                      : mode === 'network'
                        ? '192.168.1.0/24'
                        : '192.168.1.25 or hostname'
                  }
                  disabled={mode === 'local'}
                  required
                />
                <p className="mt-1.5 text-[11px] text-slate-500">
                  {mode === 'local'
                    ? 'The machine running VulScanner is always in scope.'
                    : 'Must fall inside VULSCANNER_AUTHORIZED_SCOPES or be a registered authorized target.'}
                </p>
              </div>

              <div>
                <label className="label" htmlFor="name">
                  Scan name (optional)
                </label>
                <input
                  id="name"
                  className="input"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Monthly workstation audit"
                />
              </div>

              <div>
                <label className="label" htmlFor="profile">
                  Scan profile
                </label>
                <select
                  id="profile"
                  className="input"
                  value={profile}
                  onChange={(event) => setProfile(event.target.value)}
                >
                  {(profiles ?? []).map((entry) => (
                    <option key={entry.name} value={entry.name}>
                      {entry.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {selectedProfile && (
              <div className="mt-4 rounded-lg border border-ink-700 bg-ink-850 p-3">
                <p className="text-xs text-slate-300">{selectedProfile.description}</p>
                <p className="mt-2 text-[11px] text-slate-500">
                  Runs {selectedProfile.collectors.length} collectors:{' '}
                  <span className="font-mono">
                    {selectedProfile.collectors.join(', ')}
                  </span>
                </p>
              </div>
            )}
          </Panel>

          {mode === 'remote' && (
            <Panel
              title="Remote credentials"
              subtitle="Used for this scan only — never written to the database or a report"
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="label" htmlFor="username">
                    Username
                  </label>
                  <input
                    id="username"
                    className="input"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="off"
                    placeholder="DOMAIN\\administrator"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="password">
                    Password
                  </label>
                  <input
                    id="password"
                    type="password"
                    className="input"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="off"
                  />
                </div>
              </div>
              <Banner tone="info">
                The target must have WinRM enabled and the account must be a member of
                the local Administrators or Remote Management Users group. See
                docs/installation.md for the exact prerequisites.
              </Banner>
            </Panel>
          )}
        </div>

        <div className="space-y-4">
          <Panel title="Options">
            <div className="space-y-3">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-brand-500"
                  checked={correlate}
                  onChange={(event) => setCorrelate(event.target.checked)}
                />
                <span>
                  <span className="text-sm text-slate-200">Vulnerability correlation</span>
                  <span className="block text-[11px] text-slate-500">
                    Match inventoried software against NVD and the CISA KEV catalogue.
                  </span>
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-brand-500"
                  checked={mode === 'network' ? true : networkDiscovery}
                  disabled={mode === 'network'}
                  onChange={(event) => setNetworkDiscovery(event.target.checked)}
                />
                <span>
                  <span className="text-sm text-slate-200">Network discovery</span>
                  <span className="block text-[11px] text-slate-500">
                    Also sweep the locally attached subnet for live hosts.
                  </span>
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-brand-500"
                  checked={bannerGrab}
                  onChange={(event) => setBannerGrab(event.target.checked)}
                />
                <span>
                  <span className="text-sm text-slate-200">Read service banners</span>
                  <span className="block text-[11px] text-slate-500">
                    Record what each open port volunteers on connect.
                  </span>
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-brand-500"
                  checked={generateReport}
                  onChange={(event) => setGenerateReport(event.target.checked)}
                />
                <span>
                  <span className="text-sm text-slate-200">Generate a report</span>
                  <span className="block text-[11px] text-slate-500">
                    Produce an HTML assessment report when the scan finishes.
                  </span>
                </span>
              </label>
            </div>

            <div className="mt-4 pt-4 border-t border-ink-800 space-y-4">
              <div>
                <label className="label" htmlFor="ports">
                  Port range
                </label>
                <input
                  id="ports"
                  className="input font-mono"
                  value={ports}
                  onChange={(event) => setPorts(event.target.value)}
                  placeholder="22,80,443,8000-8100"
                />
              </div>
              <div>
                <label className="label" htmlFor="discovery-profile">
                  Discovery profile
                </label>
                <select
                  id="discovery-profile"
                  className="input"
                  value={discoveryProfile}
                  onChange={(event) => setDiscoveryProfile(event.target.value)}
                >
                  <option value="safe">Safe — 27 common service ports</option>
                  <option value="standard">Standard — broader service sweep</option>
                </select>
              </div>
            </div>
          </Panel>

          {error && (
            <Banner tone="danger">
              <p className="font-semibold">{error}</p>
              {guidance && <p className="mt-1.5 opacity-90">{guidance}</p>}
            </Banner>
          )}

          <button type="submit" className="btn-primary w-full" disabled={busy}>
            {busy ? 'Starting…' : 'Start scan'}
          </button>

          <p className="text-[11px] leading-relaxed text-slate-500">
            Collection is read-only: PowerShell, CIM/WMI and registry reads, plus TCP
            connect probes for discovery. VulScanner runs no exploits, reads no
            passwords or private keys, and changes nothing on the target.
          </p>
        </div>
      </form>
    </>
  );
}
