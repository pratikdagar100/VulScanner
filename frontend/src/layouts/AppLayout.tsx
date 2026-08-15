/** Application chrome: sidebar navigation, top bar and content outlet. */

import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { api, tokens } from '@/services/api';
import { useApi } from '@/hooks/useApi';

interface NavItem {
  to: string;
  label: string;
  glyph: string;
}

const NAV_SECTIONS: Array<{ heading: string; items: NavItem[] }> = [
  {
    heading: 'Overview',
    items: [
      { to: '/', label: 'Dashboard', glyph: '▤' },
      { to: '/assets', label: 'Assets', glyph: '▣' },
      { to: '/scans', label: 'Scans', glyph: '◷' },
    ],
  },
  {
    heading: 'Security',
    items: [
      { to: '/findings', label: 'Findings', glyph: '⚑' },
      { to: '/vulnerabilities', label: 'Vulnerabilities', glyph: '☣' },
      { to: '/remediation', label: 'Remediation', glyph: '✚' },
    ],
  },
  {
    heading: 'Network',
    items: [
      { to: '/network', label: 'Network Map', glyph: '⬡' },
      { to: '/ports', label: 'Ports & Services', glyph: '⇄' },
    ],
  },
  {
    heading: 'Windows posture',
    items: [
      { to: '/software', label: 'Software', glyph: '❐' },
      { to: '/patches', label: 'Patches', glyph: '⟳' },
      { to: '/firewall', label: 'Firewall', glyph: '⛨' },
      { to: '/defender', label: 'Defender', glyph: '⛉' },
      { to: '/rdp', label: 'RDP', glyph: '⌨' },
      { to: '/accounts', label: 'Users & Groups', glyph: '☺' },
      { to: '/policies', label: 'Security Policies', glyph: '§' },
    ],
  },
  {
    heading: 'Operations',
    items: [
      { to: '/reports', label: 'Reports', glyph: '⎙' },
      { to: '/audit', label: 'Audit Logs', glyph: '☰' },
      { to: '/settings', label: 'Settings', glyph: '⚙' },
    ],
  },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const identity = tokens.identity();

  // Poll for running scans so the top bar reflects live activity.
  const { data: summary } = useApi(() => api.dashboard(), [], 15000);

  useEffect(() => {
    const onUnauthenticated = () => navigate('/login', { replace: true });
    window.addEventListener('vulscanner:unauthenticated', onUnauthenticated);
    return () =>
      window.removeEventListener('vulscanner:unauthenticated', onUnauthenticated);
  }, [navigate]);

  async function handleLogout() {
    await api.logout().catch(() => undefined);
    navigate('/login', { replace: true });
  }

  return (
    <div className="flex h-full bg-ink-950">
      <aside
        className={`${
          collapsed ? 'w-16' : 'w-60'
        } shrink-0 border-r border-ink-800 bg-ink-900 flex flex-col transition-all duration-200`}
      >
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-ink-800">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center shrink-0">
            <span className="text-white font-bold text-sm">VS</span>
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-bold text-slate-50 leading-tight">VulScanner</p>
              <p className="text-[10px] text-slate-500 leading-tight">
                Security assessment
              </p>
            </div>
          )}
        </div>

        <nav className="flex-1 overflow-y-auto py-3">
          {NAV_SECTIONS.map((section) => (
            <div key={section.heading} className="mb-4">
              {!collapsed && (
                <p className="px-4 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                  {section.heading}
                </p>
              )}
              <ul className="space-y-0.5 px-2">
                {section.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.to === '/'}
                      title={item.label}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors ${
                          isActive
                            ? 'bg-brand-600/15 text-brand-200 font-medium'
                            : 'text-slate-400 hover:bg-ink-800 hover:text-slate-200'
                        }`
                      }
                    >
                      <span className="w-4 text-center text-xs opacity-80">
                        {item.glyph}
                      </span>
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <button
          onClick={() => setCollapsed((value) => !value)}
          className="h-10 border-t border-ink-800 text-slate-500 hover:text-slate-300 text-xs"
        >
          {collapsed ? '»' : '« Collapse'}
        </button>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 border-b border-ink-800 bg-ink-900/80 backdrop-blur flex items-center justify-between px-6 gap-4">
          <div className="flex items-center gap-3 min-w-0">
            {summary && summary.running_scans > 0 && (
              <span className="chip bg-brand-500/15 text-brand-300 border border-brand-500/40">
                <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse" />
                {summary.running_scans} scan{summary.running_scans > 1 ? 's' : ''} running
              </span>
            )}
            {summary && summary.severity_counts.critical > 0 && (
              <span className="chip bg-severity-critical/15 text-severity-critical border border-severity-critical/40">
                {summary.severity_counts.critical} critical open
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button className="btn-primary" onClick={() => navigate('/scans/new')}>
              + New scan
            </button>
            <div className="flex items-center gap-2 pl-3 border-l border-ink-800">
              <div className="text-right leading-tight">
                <p className="text-xs font-medium text-slate-200">
                  {identity?.username ?? 'unknown'}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">
                  {identity?.role ?? ''}
                </p>
              </div>
              <button
                onClick={handleLogout}
                title="Sign out"
                className="btn-ghost px-2 py-1.5"
              >
                ⏻
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>

        <footer className="shrink-0 border-t border-ink-800 px-6 py-2 text-[11px] text-slate-600 flex items-center justify-between">
          <span>
            VulScanner — authorized defensive assessment only. No exploitation, no
            credential collection, no automatic remediation.
          </span>
          {summary?.intelligence && (
            <span>
              CISA KEV: {summary.intelligence.kev_entries.toLocaleString()} entries ·
              NVD {summary.intelligence.online ? 'online' : 'offline'}
            </span>
          )}
        </footer>
      </div>
    </div>
  );
}
