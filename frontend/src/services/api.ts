/**
 * VulScanner API client.
 *
 * Tokens live in sessionStorage so they are cleared when the tab closes; an
 * expired access token is refreshed transparently once per request.
 */

import type {
  Asset,
  AuditLog,
  CollectorResult,
  DashboardSummary,
  Finding,
  FindingStatus,
  NetworkHost,
  NetworkPort,
  Patch,
  RemediationPlan,
  Report,
  Scan,
  ScanDetail,
  ScanProfileInfo,
  Target,
  TokenPair,
  Topology,
  User,
  Vulnerability,
} from '@/types';

/**
 * Where the VulScanner API lives.
 *
 * Empty (the default) means same-origin, which is what the dev server proxy and
 * a self-hosted deployment behind one reverse proxy both provide. Set
 * VITE_API_BASE_URL at build time to point the UI at an API on another origin.
 */
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

/** True when this build has no API to talk to (a UI-only deployment). */
export const IS_UI_ONLY_BUILD = import.meta.env.VITE_UI_ONLY === 'true';

const ACCESS_KEY = 'vulscanner.access';
const REFRESH_KEY = 'vulscanner.refresh';
const IDENTITY_KEY = 'vulscanner.identity';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** A target refused because it is outside the authorized scope. */
  get isAuthorizationBoundary(): boolean {
    return (
      this.status === 403 &&
      typeof this.body === 'object' &&
      this.body !== null &&
      (this.body as { error?: string }).error === 'target_not_authorized'
    );
  }
}

export const tokens = {
  access: () => sessionStorage.getItem(ACCESS_KEY),
  refresh: () => sessionStorage.getItem(REFRESH_KEY),
  identity(): { username: string; role: string } | null {
    const raw = sessionStorage.getItem(IDENTITY_KEY);
    return raw ? JSON.parse(raw) : null;
  },
  store(pair: TokenPair) {
    sessionStorage.setItem(ACCESS_KEY, pair.access_token);
    sessionStorage.setItem(REFRESH_KEY, pair.refresh_token);
    sessionStorage.setItem(
      IDENTITY_KEY,
      JSON.stringify({ username: pair.username, role: pair.role }),
    );
  },
  clear() {
    sessionStorage.removeItem(ACCESS_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
    sessionStorage.removeItem(IDENTITY_KEY);
  },
};

type Query = Record<string, string | number | boolean | undefined | null>;

function buildUrl(path: string, query?: Query): string {
  const base = API_BASE_URL || window.location.origin;
  const url = new URL(path, base);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }
  // Same-origin requests stay relative so the dev proxy keeps working.
  return API_BASE_URL ? url.toString() : url.pathname + url.search;
}

async function refreshAccessToken(): Promise<boolean> {
  const refresh = tokens.refresh();
  if (!refresh) return false;
  const response = await fetch(buildUrl('/api/auth/refresh'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!response.ok) {
    tokens.clear();
    return false;
  }
  tokens.store((await response.json()) as TokenPair);
  return true;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  query?: Query,
  retry = true,
): Promise<T> {
  const headers = new Headers(init.headers);
  const access = tokens.access();
  if (access) headers.set('Authorization', `Bearer ${access}`);
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(buildUrl(path, query), { ...init, headers });

  if (response.status === 401 && retry && (await refreshAccessToken())) {
    return request<T>(path, init, query, false);
  }

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get('content-type') ?? '';
  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const detail =
      typeof payload === 'object' && payload !== null && 'detail' in payload
        ? String((payload as { detail: unknown }).detail)
        : `Request failed with status ${response.status}`;
    if (response.status === 401) {
      tokens.clear();
      window.dispatchEvent(new CustomEvent('vulscanner:unauthenticated'));
    }
    throw new ApiError(detail, response.status, payload);
  }
  return payload as T;
}

export const api = {
  // -- authentication ---------------------------------------------------
  async login(username: string, password: string): Promise<TokenPair> {
    const pair = await request<TokenPair>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    tokens.store(pair);
    return pair;
  },
  async logout(): Promise<void> {
    try {
      await request('/api/auth/logout', { method: 'POST' });
    } finally {
      tokens.clear();
    }
  },
  me: () => request<User>('/api/auth/me'),
  changePassword: (current_password: string, new_password: string) =>
    request<{ detail: string }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    }),
  users: () => request<User[]>('/api/auth/users'),

  // -- system -----------------------------------------------------------
  health: () => request<Record<string, unknown>>('/api/health'),

  // -- dashboard --------------------------------------------------------
  dashboard: () => request<DashboardSummary>('/api/dashboard'),

  // -- scans ------------------------------------------------------------
  scans: (query?: Query) => request<Scan[]>('/api/scans', {}, query),
  scan: (id: number) => request<ScanDetail>(`/api/scans/${id}`),
  scanResults: (id: number, collector?: string) =>
    request<CollectorResult[]>(`/api/scans/${id}/results`, {}, { collector }),
  scanProgress: (id: number) =>
    request<{
      scan_id: number;
      status: string;
      progress: number;
      stage: string;
      stages: Array<{ key: string; label: string; status: string }>;
      message: string;
    }>(`/api/scans/${id}/progress`),
  createScan: (payload: {
    name?: string;
    target: string;
    profile: string;
    options?: Record<string, unknown>;
    credential?: { username: string; password: string };
  }) =>
    request<Scan>('/api/scans', { method: 'POST', body: JSON.stringify(payload) }),
  cancelScan: (id: number) =>
    request<Scan>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  deleteScan: (id: number) => request<void>(`/api/scans/${id}`, { method: 'DELETE' }),
  scanProfiles: () => request<ScanProfileInfo[]>('/api/scans/profiles'),
  collectors: () =>
    request<
      Array<{
        name: string;
        category: string;
        description: string;
        requires_admin: boolean;
        profiles: string[];
      }>
    >('/api/scans/collectors'),

  // -- assets -----------------------------------------------------------
  assets: (query?: Query) => request<Asset[]>('/api/assets', {}, query),
  asset: (id: number) => request<Asset>(`/api/assets/${id}`),
  assetFindings: (id: number) => request<Finding[]>(`/api/assets/${id}/findings`),
  assetPorts: (id: number) => request<NetworkPort[]>(`/api/assets/${id}/ports`),
  setAssetCriticality: (id: number, criticality: string) =>
    request<Asset>(`/api/assets/${id}/criticality`, { method: 'PATCH' }, { criticality }),

  // -- targets ----------------------------------------------------------
  targets: () => request<Target[]>('/api/targets'),
  createTarget: (payload: {
    name: string;
    value: string;
    description?: string;
    criticality?: string;
    authorized: boolean;
    authorization_note?: string;
  }) => request<Target>('/api/targets', { method: 'POST', body: JSON.stringify(payload) }),
  deleteTarget: (id: number) => request<void>(`/api/targets/${id}`, { method: 'DELETE' }),

  // -- findings ---------------------------------------------------------
  findings: (query?: Query) => request<Finding[]>('/api/findings', {}, query),
  finding: (id: number) => request<Finding>(`/api/findings/${id}`),
  findingsSummary: (query?: Query) =>
    request<{
      total: number;
      by_severity: Record<string, number>;
      by_category: Record<string, number>;
      by_status: Record<string, number>;
      highest_risk_score: number;
    }>('/api/findings/summary', {}, query),
  updateFinding: (id: number, status: FindingStatus, note: string) =>
    request<Finding>(`/api/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, note }),
    }),
  remediation: (query?: Query) =>
    request<RemediationPlan>('/api/findings/remediation', {}, query),

  // -- vulnerabilities --------------------------------------------------
  vulnerabilities: (query?: Query) =>
    request<Vulnerability[]>('/api/vulnerabilities', {}, query),
  cve: (id: string) => request<Record<string, any>>(`/api/vulnerabilities/cve/${id}`),
  intelligence: () =>
    request<Record<string, any>>('/api/vulnerabilities/intelligence'),
  patches: (query?: Query) => request<Patch[]>('/api/patches', {}, query),

  // -- network ----------------------------------------------------------
  topology: (scanId?: number) =>
    request<Topology>('/api/network/topology', {}, { scan_id: scanId }),
  networkHosts: (query?: Query) => request<NetworkHost[]>('/api/network/hosts', {}, query),
  ports: (query?: Query) => request<NetworkPort[]>('/api/network/ports', {}, query),
  connections: (query?: Query) =>
    request<Array<Record<string, any>>>('/api/network/connections', {}, query),
  services: (scanId?: number) =>
    request<Array<{ port: number; protocol: string; service: string; count: number; max_risk_score: number; exposures: string[] }>>(
      '/api/network/services',
      {},
      { scan_id: scanId },
    ),

  // -- reports ----------------------------------------------------------
  reports: (query?: Query) => request<Report[]>('/api/reports', {}, query),
  createReport: (scan_id: number, format: string) =>
    request<Report>('/api/reports', {
      method: 'POST',
      body: JSON.stringify({ scan_id, format }),
    }),
  deleteReport: (id: number) => request<void>(`/api/reports/${id}`, { method: 'DELETE' }),
  reportDownloadUrl: (id: number) => `/api/reports/${id}/download`,
  async downloadReport(report: Report): Promise<void> {
    // The download endpoint requires the bearer token, so fetch then save.
    const response = await fetch(buildUrl(`/api/reports/${report.id}/download`), {
      headers: { Authorization: `Bearer ${tokens.access() ?? ''}` },
    });
    if (!response.ok) throw new ApiError('Download failed', response.status);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = report.file_name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  },

  // -- audit ------------------------------------------------------------
  auditLogs: (query?: Query) => request<AuditLog[]>('/api/audit', {}, query),
};

/** Subscribe to live scan progress over SSE. Returns an unsubscribe function. */
export function subscribeToScan(
  scanId: number,
  onEvent: (event: {
    scan_id: number;
    stage: string;
    progress: number;
    message: string;
    status: string;
  }) => void,
  onError?: () => void,
): () => void {
  // EventSource cannot send headers, so poll when no token is available.
  const access = tokens.access();
  if (!access) {
    onError?.();
    return () => undefined;
  }

  const httpBase = API_BASE_URL || window.location.origin;
  const socketBase = httpBase.replace(/^http/, 'ws');
  const socket = new WebSocket(
    `${socketBase}/api/scans/${scanId}/ws?token=${encodeURIComponent(access)}`,
  );

  socket.onmessage = (message) => {
    try {
      const payload = JSON.parse(message.data);
      if (payload.stage !== 'keep-alive') onEvent(payload);
    } catch {
      /* ignore malformed frames */
    }
  };
  socket.onerror = () => onError?.();

  return () => {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
      socket.close();
    }
  };
}
