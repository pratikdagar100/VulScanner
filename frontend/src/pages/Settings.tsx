import { useState } from 'react';

import {
  Banner,
  EmptyState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  StatusChip,
  formatDate,
} from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { api, tokens } from '@/services/api';

export default function Settings() {
  const identity = tokens.identity();
  const isAdmin = identity?.role === 'administrator';

  const { data: health } = useApi(() => api.health(), []);
  const { data: intelligence } = useApi(() => api.intelligence(), []);
  const { data: collectors } = useApi(() => api.collectors(), []);
  const { data: targets, reload: reloadTargets } = useApi(() => api.targets(), []);
  const { data: users } = useApi(
    () => (isAdmin ? api.users() : Promise.resolve([])),
    [isAdmin],
  );

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [message, setMessage] = useState<{ tone: 'success' | 'danger'; text: string } | null>(
    null,
  );

  const [targetValue, setTargetValue] = useState('');
  const [targetName, setTargetName] = useState('');
  const [targetNote, setTargetNote] = useState('');
  const [targetError, setTargetError] = useState<string | null>(null);

  async function changePassword(event: React.FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      await api.changePassword(current, next);
      setMessage({ tone: 'success', text: 'Password updated.' });
      setCurrent('');
      setNext('');
    } catch (exc) {
      setMessage({ tone: 'danger', text: exc instanceof Error ? exc.message : String(exc) });
    }
  }

  async function addTarget(event: React.FormEvent) {
    event.preventDefault();
    setTargetError(null);
    try {
      await api.createTarget({
        name: targetName || targetValue,
        value: targetValue,
        authorized: true,
        authorization_note: targetNote,
      });
      setTargetValue('');
      setTargetName('');
      setTargetNote('');
      reloadTargets();
    } catch (exc) {
      setTargetError(exc instanceof Error ? exc.message : String(exc));
    }
  }

  if (!health) return <Loading label="Loading settings" />;

  return (
    <>
      <PageHeader
        title="Settings"
        description="Environment capability, authorized scanning scope, account management and vulnerability intelligence status."
      />

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel title="Environment">
          <dl className="grid grid-cols-2 gap-4">
            <KeyValue label="Product" value={`VulScanner ${health.version}`} />
            <KeyValue label="Environment" value={String(health.environment)} />
            <KeyValue label="Platform" value={String(health.platform)} />
            <KeyValue
              label="Windows collection"
              value={
                <StatusChip
                  status={health.windows_collection_available ? 'completed' : 'failed'}
                />
              }
            />
            <KeyValue label="Collectors" value={collectors?.length ?? '—'} />
            <KeyValue
              label="Elevated collectors"
              value={collectors?.filter((entry) => entry.requires_admin).length ?? '—'}
            />
          </dl>
          {!health.windows_collection_available && (
            <div className="mt-4">
              <Banner tone="warning">
                Windows collection is unavailable on this host, so only network
                assessment will run. Windows collectors need Windows and PowerShell.
              </Banner>
            </div>
          )}
        </Panel>

        <Panel title="Vulnerability intelligence">
          {intelligence ? (
            <>
              <dl className="grid grid-cols-2 gap-4">
                <KeyValue
                  label="NVD lookups"
                  value={<StatusChip status={intelligence.online ? 'completed' : 'cancelled'} />}
                />
                <KeyValue
                  label="NVD API key"
                  value={intelligence.nvd_api_key_configured ? 'configured' : 'not set'}
                />
                <KeyValue
                  label="CISA KEV entries"
                  value={Number(intelligence.kev_entries).toLocaleString()}
                />
                <KeyValue
                  label="Rate limit"
                  value={`1 request / ${intelligence.rate_limit_interval_seconds}s`}
                />
                <KeyValue label="Cache TTL" value={`${intelligence.cache_ttl_hours} hours`} />
                <KeyValue
                  label="Cache directory"
                  value={<span className="font-mono text-[11px]">{String(intelligence.cache_directory)}</span>}
                />
              </dl>
              {!intelligence.nvd_api_key_configured && (
                <div className="mt-4">
                  <Banner tone="info">
                    Request a free NVD API key at nvd.nist.gov/developers/request-an-api-key
                    and set VULSCANNER_NVD_API_KEY in .env to raise the rate limit from one
                    request every 6 seconds to ten per second.
                  </Banner>
                </div>
              )}
            </>
          ) : (
            <Loading />
          )}
        </Panel>

        <Panel
          title="Authorized scanning scope"
          subtitle="VulScanner refuses any target outside these scopes"
        >
          <div className="flex flex-wrap gap-2 mb-4">
            {(health.authorized_scopes as string[]).map((scope) => (
              <span key={scope} className="chip bg-ink-800 text-brand-300 border border-ink-700 font-mono">
                {scope}
              </span>
            ))}
          </div>

          <form onSubmit={addTarget} className="space-y-3 pt-4 border-t border-ink-800">
            <p className="text-xs text-slate-400">
              Register an additional authorized target. The attestation and your username
              are written to the audit log.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label" htmlFor="target-value">
                  Target (IP, hostname or CIDR)
                </label>
                <input
                  id="target-value"
                  className="input font-mono"
                  value={targetValue}
                  onChange={(event) => setTargetValue(event.target.value)}
                  placeholder="10.20.0.0/24"
                  required
                />
              </div>
              <div>
                <label className="label" htmlFor="target-name">
                  Name
                </label>
                <input
                  id="target-name"
                  className="input"
                  value={targetName}
                  onChange={(event) => setTargetName(event.target.value)}
                  placeholder="Lab network"
                />
              </div>
            </div>
            <div>
              <label className="label" htmlFor="target-note">
                Authorization note (required)
              </label>
              <input
                id="target-note"
                className="input"
                value={targetNote}
                onChange={(event) => setTargetNote(event.target.value)}
                placeholder="Approved by J. Smith, ticket SEC-1042, valid to 2026-12-31"
                required
              />
            </div>
            {targetError && <Banner tone="danger">{targetError}</Banner>}
            <button type="submit" className="btn-primary">
              Register authorized target
            </button>
          </form>

          {targets && targets.length > 0 && (
            <div className="mt-4 pt-4 border-t border-ink-800 space-y-2">
              {targets.map((target) => (
                <div
                  key={target.id}
                  className="flex items-start justify-between gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-slate-200 font-mono">{target.value}</p>
                    <p className="text-[11px] text-slate-500">
                      {target.name} · {target.authorization_note || 'no note'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <StatusChip status={target.authorized ? 'completed' : 'queued'} />
                    <button
                      className="btn-ghost text-xs text-severity-critical"
                      onClick={async () => {
                        await api.deleteTarget(target.id).catch(() => undefined);
                        reloadTargets();
                      }}
                    >
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Your account">
          <dl className="grid grid-cols-2 gap-4 mb-5">
            <KeyValue label="Username" value={identity?.username} />
            <KeyValue label="Role" value={identity?.role} />
          </dl>
          <form onSubmit={changePassword} className="space-y-3 pt-4 border-t border-ink-800">
            <div>
              <label className="label" htmlFor="current">
                Current password
              </label>
              <input
                id="current"
                type="password"
                className="input"
                value={current}
                onChange={(event) => setCurrent(event.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="next">
                New password
              </label>
              <input
                id="next"
                type="password"
                className="input"
                value={next}
                onChange={(event) => setNext(event.target.value)}
                autoComplete="new-password"
                required
              />
              <p className="mt-1 text-[11px] text-slate-500">
                At least 12 characters with upper case, lower case, a digit and a symbol.
              </p>
            </div>
            {message && <Banner tone={message.tone}>{message.text}</Banner>}
            <button type="submit" className="btn-primary">
              Change password
            </button>
          </form>
        </Panel>

        {isAdmin && (
          <Panel className="xl:col-span-2" title="Users" bodyClassName="p-0">
            {!users?.length ? (
              <EmptyState title="No users" description="Create users via POST /api/auth/users." />
            ) : (
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Full name</th>
                    <th>Role</th>
                    <th>Active</th>
                    <th>Must change password</th>
                    <th>Last login</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td className="text-slate-100">{user.username}</td>
                      <td className="text-xs text-slate-400">{user.full_name ?? '—'}</td>
                      <td className="text-xs text-brand-300">{user.role}</td>
                      <td>
                        <StatusChip status={user.is_active ? 'completed' : 'cancelled'} />
                      </td>
                      <td className="text-xs text-slate-400">
                        {user.must_change_password ? 'yes' : 'no'}
                      </td>
                      <td className="text-xs text-slate-500">{formatDate(user.last_login_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        )}
      </div>
    </>
  );
}
