/** Small data-fetching hooks. Deliberately dependency free. */

import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError } from '@/services/api';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Runs `loader` on mount and whenever `deps` change.
 * `intervalMs` polls while the component is mounted.
 */
export function useApi<T>(
  loader: () => Promise<T>,
  deps: unknown[] = [],
  intervalMs?: number,
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async () => {
    try {
      const result = await loader();
      if (!mounted.current) return;
      setData(result);
      setError(null);
    } catch (exc) {
      if (!mounted.current) return;
      setError(exc instanceof ApiError ? exc.message : String(exc));
    } finally {
      if (mounted.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    setLoading(true);
    void run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, nonce]);

  useEffect(() => {
    if (!intervalMs) return;
    const timer = window.setInterval(() => void run(), intervalMs);
    return () => window.clearInterval(timer);
  }, [run, intervalMs]);

  return { data, loading, error, reload: () => setNonce((value) => value + 1) };
}

/** Debounces a rapidly changing value (search boxes). */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
