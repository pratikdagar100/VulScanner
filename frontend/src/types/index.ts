/** Shared VulScanner API types. Mirrors the backend Pydantic schemas. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'informational';
export type Role = 'administrator' | 'analyst' | 'viewer';
export type ScanStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';
export type FindingStatus =
  | 'open'
  | 'resolved'
  | 'reopened'
  | 'risk_accepted'
  | 'false_positive';

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  role: Role;
  username: string;
  must_change_password: boolean;
}

export interface User {
  id: number;
  username: string;
  email: string | null;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Scan {
  id: number;
  name: string;
  target: string;
  target_type: string;
  profile: string;
  status: ScanStatus;
  progress: number;
  current_stage: string;
  security_score: number | null;
  risk_score: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  asset_count: number;
  vulnerability_count: number;
  scanner_version: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  created_at: string;
}

export interface ScanStage {
  key: string;
  label: string;
  status: 'pending' | 'running' | 'complete';
}

export interface ScanDetail extends Scan {
  options: Record<string, unknown>;
  stages: ScanStage[];
  warnings: string[];
  errors: string[];
  error_message: string;
  results: ScanResultSummary[];
}

export interface ScanResultSummary {
  id: number;
  collector: string;
  category: string;
  status: string;
  collection_method: string;
  collected_at: string | null;
  duration_seconds: number | null;
  warnings: string[];
  errors: string[];
}

export interface CollectorResult extends ScanResultSummary {
  data: Record<string, any>;
}

export interface ProgressEvent {
  scan_id: number;
  stage: string;
  progress: number;
  message: string;
  status: string;
  timestamp: string;
}

export interface Finding {
  id: number;
  finding_uid: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  risk_score: number;
  cvss_score: number | null;
  confidence: Confidence;
  status: FindingStatus;
  description: string;
  impact: string;
  evidence: Record<string, any>;
  evidence_summary: string;
  detection_method: string;
  remediation: string;
  remediation_command: string;
  references: string[];
  risk_factors: Record<string, any>;
  scan_id: number | null;
  asset_id: number | null;
  first_detected_at: string | null;
  last_detected_at: string | null;
  resolved_at: string | null;
  status_note: string;
}

export interface Asset {
  id: number;
  asset_uid: string;
  hostname: string | null;
  ip_address: string | null;
  ip_addresses: string[];
  mac_address: string | null;
  vendor: string | null;
  os_name: string | null;
  os_version: string | null;
  os_build: string | null;
  os_edition: string | null;
  architecture: string | null;
  domain: string | null;
  asset_type: string;
  os_confidence: string;
  criticality: string;
  risk_score: number;
  severity: Severity;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  vulnerability_count: number;
  open_port_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  product: string;
  vendor: string;
  product_version: string;
  affected_versions: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity;
  risk_score: number;
  risk_factors: Record<string, any>;
  kev: boolean;
  confidence: Confidence;
  match_method: string;
  evidence: Record<string, any>;
  patch: string;
  remediation: string;
  references: string[];
  status: string;
  scan_id: number | null;
  asset_id: number | null;
}

export interface NetworkPort {
  id: number;
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  banner: string | null;
  local_address: string | null;
  process_id: number | null;
  process_name: string | null;
  owning_service: string | null;
  exposure: string;
  risk_score: number;
  asset_id: number | null;
  host_id: number | null;
}

export interface NetworkHost {
  id: number;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  discovery_method: string;
  is_up: boolean;
  latency_ms: number | null;
  os_guess: string | null;
  os_confidence: string;
  os_evidence: string[];
  is_gateway: boolean;
  is_local: boolean;
  scan_id: number | null;
  last_seen: string | null;
}

export interface TopologyNode {
  id: string;
  label: string;
  type: 'scanner' | 'host' | 'gateway' | 'switch' | 'internet' | 'subnet';
  ip_address: string;
  mac_address: string;
  hostname: string;
  vendor: string;
  os_guess: string;
  os_confidence: string;
  open_ports: number[];
  risk_score: number;
  severity: Severity;
  metadata: Record<string, any>;
}

export interface TopologyEdge {
  source: string;
  target: string;
  type: string;
  confidence: 'observed' | 'inferred' | 'unknown';
  label: string;
  evidence: Record<string, any>;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  node_count: number;
  edge_count: number;
  observed_edges: number;
  inferred_edges: number;
  confidence_note: string;
  scan_id: number | null;
}

export interface Patch {
  id: number;
  kb_id: string;
  title: string;
  classification: string;
  state: 'installed' | 'missing' | 'unknown';
  installed_on: string | null;
  installed_by: string | null;
  severity: string | null;
  confidence: string;
  evidence: Record<string, any>;
  asset_id: number | null;
  scan_id: number | null;
}

export interface RemediationItem {
  finding_uid: string;
  title: string;
  severity: Severity;
  risk_score: number;
  category: string;
  what_is_wrong: string;
  why_it_matters: string;
  recommended_fix: string;
  verification: string;
  patch_reference: string;
  configuration_recommendation: string;
  command: string;
  references: string[];
  priority: number;
  sla_days: number | null;
  effort: string;
  disruptive: boolean;
  requires_reboot: boolean;
  automated_execution: false;
  execution_note: string;
}

export interface RemediationPlan {
  items: RemediationItem[];
  summary: {
    total_items: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    immediate_action_required: RemediationItem[];
    quick_wins: RemediationItem[];
    requires_reboot_count: number;
    policy: string;
  };
}

export interface Report {
  id: number;
  title: string;
  format: 'html' | 'pdf' | 'json' | 'csv';
  status: string;
  file_name: string;
  size_bytes: number;
  scan_id: number | null;
  generated_at: string | null;
  summary: Record<string, any>;
  error_message: string;
}

export interface AuditLog {
  id: number;
  action: string;
  outcome: string;
  actor_name: string;
  source_ip: string | null;
  entity_type: string | null;
  entity_id: string | null;
  message: string;
  details: Record<string, any>;
  created_at: string;
}

export interface DashboardSummary {
  security_score: number;
  total_assets: number;
  scanned_assets: number;
  total_scans: number;
  running_scans: number;
  severity_counts: Record<Severity, number>;
  open_findings: number;
  resolved_findings: number;
  vulnerability_count: number;
  kev_vulnerability_count: number;
  missing_updates: number;
  exposed_ports: number;
  misconfigurations: number;
  category_distribution: Record<string, number>;
  top_risky_assets: Array<{
    id: number;
    hostname: string | null;
    ip_address: string | null;
    os_name: string | null;
    risk_score: number;
    severity: Severity;
    critical_count: number;
    high_count: number;
    finding_count: number;
  }>;
  exposed_services: Array<{
    port: number;
    service: string;
    count: number;
    max_risk_score: number;
  }>;
  risk_trend: Array<{
    scan_id: number;
    target: string;
    finished_at: string | null;
    security_score: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  patch_status: { installed: number; missing: number; coverage_percent: number };
  last_scan_at: string | null;
  intelligence: {
    online: boolean;
    nvd_api_key_configured: boolean;
    kev_entries: number;
    kev_available: boolean;
    cache_directory: string;
    cache_ttl_hours: number;
  };
}

export interface ScanProfileInfo {
  name: string;
  description: string;
  collectors: string[];
}

export interface Target {
  id: number;
  name: string;
  target_type: string;
  value: string;
  description: string;
  authorized: boolean;
  authorization_note: string;
  authorized_at: string | null;
  criticality: string;
  created_at: string;
}
