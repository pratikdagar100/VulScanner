import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Banner } from '@/components/ui';
import { API_BASE_URL, IS_UI_ONLY_BUILD, api } from '@/services/api';

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // null = not yet known, false = the API could not be reached at all.
  const [apiReachable, setApiReachable] = useState<boolean | null>(null);

  useEffect(() => {
    if (IS_UI_ONLY_BUILD) {
      setApiReachable(false);
      return;
    }
    api
      .health()
      .then(() => setApiReachable(true))
      .catch(() => setApiReachable(false));
  }, []);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const pair = await api.login(username, password);
      navigate(pair.must_change_password ? '/settings' : '/', { replace: true });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'Sign in failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center p-6 bg-gradient-to-br from-ink-950 via-ink-900 to-ink-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center">
              <span className="text-white font-bold text-lg">VS</span>
            </div>
            <div className="text-left">
              <h1 className="text-2xl font-bold text-slate-50 leading-tight">VulScanner</h1>
              <p className="text-xs text-slate-500">
                Windows vulnerability &amp; network assessment
              </p>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="panel p-6 space-y-4">
          <div>
            <label className="label" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              className="input"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoFocus
              required
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
              autoComplete="current-password"
              required
            />
          </div>

          {apiReachable === false && (
            <Banner tone="warning">
              <p className="font-semibold">No VulScanner API is reachable.</p>
              <p className="mt-1.5">
                This is the VulScanner interface only. Scanning runs on your own
                machine — the engine needs Windows, PowerShell and local network
                access, so it cannot be hosted publicly.
              </p>
              <p className="mt-1.5">
                Run the platform locally with{' '}
                <code className="font-mono">.\scripts\start.ps1</code> and open{' '}
                <a
                  href="http://localhost:5173"
                  className="underline hover:text-white"
                >
                  localhost:5173
                </a>
                .
                {API_BASE_URL && (
                  <>
                    {' '}
                    This build is configured to talk to{' '}
                    <span className="font-mono">{API_BASE_URL}</span>.
                  </>
                )}
              </p>
            </Banner>
          )}

          {error && <Banner tone="danger">{error}</Banner>}

          <button
            type="submit"
            className="btn-primary w-full"
            disabled={busy || apiReachable === false}
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>

          <p className="text-[11px] leading-relaxed text-slate-500 pt-2 border-t border-ink-800">
            VulScanner assesses only systems and networks you are authorized to
            assess. Every sign-in, scan and finding change is written to the audit
            log.
          </p>
        </form>

        <p className="mt-6 text-center text-[11px] text-slate-600">
          First run? The bootstrap administrator password is printed once in the
          backend console at startup.
        </p>
      </div>
    </div>
  );
}
