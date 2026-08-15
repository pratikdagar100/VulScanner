/** Live scan progress over WebSocket, with polling as a fallback. */

import { useEffect, useState } from 'react';

import { api, subscribeToScan } from '@/services/api';

export interface ScanProgressState {
  progress: number;
  stage: string;
  message: string;
  status: string;
  stages: Array<{ key: string; label: string; status: string }>;
  live: boolean;
}

const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);

export function useScanProgress(
  scanId: number | null,
  enabled: boolean,
): ScanProgressState {
  const [state, setState] = useState<ScanProgressState>({
    progress: 0,
    stage: '',
    message: '',
    status: 'queued',
    stages: [],
    live: false,
  });

  useEffect(() => {
    if (!scanId || !enabled) return;

    let cancelled = false;

    // Seed from the REST snapshot so the UI is populated immediately.
    void api
      .scanProgress(scanId)
      .then((snapshot) => {
        if (cancelled) return;
        setState((previous) => ({
          ...previous,
          progress: snapshot.progress,
          stage: snapshot.stage,
          message: snapshot.message,
          status: snapshot.status,
          stages: snapshot.stages ?? [],
        }));
      })
      .catch(() => undefined);

    const unsubscribe = subscribeToScan(
      scanId,
      (event) => {
        if (cancelled) return;
        setState((previous) => ({
          ...previous,
          progress: event.progress,
          stage: event.stage,
          message: event.message,
          status: event.status,
          live: true,
        }));
      },
      () => setState((previous) => ({ ...previous, live: false })),
    );

    // Polling backstop: keeps the UI correct if the socket cannot connect.
    const timer = window.setInterval(async () => {
      try {
        const snapshot = await api.scanProgress(scanId);
        if (cancelled) return;
        setState((previous) => ({
          ...previous,
          progress: Math.max(previous.progress, snapshot.progress),
          stage: snapshot.stage || previous.stage,
          status: snapshot.status,
          stages: snapshot.stages ?? previous.stages,
        }));
        if (TERMINAL.has(snapshot.status)) window.clearInterval(timer);
      } catch {
        /* transient failures are ignored; the socket may still be live */
      }
    }, 3000);

    return () => {
      cancelled = true;
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [scanId, enabled]);

  return state;
}
