"""Asset, finding, vulnerability, network, report and audit schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingStatus


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_uid: str
    hostname: str | None
    ip_address: str | None
    ip_addresses: list[Any]
    mac_address: str | None
    vendor: str | None
    os_name: str | None
    os_version: str | None
    os_build: str | None
    os_edition: str | None
    architecture: str | None
    domain: str | None
    asset_type: str
    os_confidence: str
    criticality: str
    risk_score: float
    severity: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    vulnerability_count: int
    open_port_count: int
    first_seen: datetime | None
    last_seen: datetime | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_uid: str
    rule_id: str
    title: str
    category: str
    severity: str
    risk_score: float
    cvss_score: float | None
    confidence: str
    status: str
    description: str
    impact: str
    evidence: dict[str, Any]
    evidence_summary: str
    detection_method: str
    remediation: str
    remediation_command: str
    references: list[Any]
    risk_factors: dict[str, Any]
    scan_id: int | None
    asset_id: int | None
    first_detected_at: datetime | None
    last_detected_at: datetime | None
    resolved_at: datetime | None
    status_note: str


class FindingUpdate(BaseModel):
    status: FindingStatus
    note: str = Field(default="", max_length=2000)


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    product: str
    vendor: str
    product_version: str
    affected_versions: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    risk_score: float
    risk_factors: dict[str, Any]
    kev: bool
    confidence: str
    match_method: str
    evidence: dict[str, Any]
    patch: str
    remediation: str
    references: list[Any]
    status: str
    scan_id: int | None
    asset_id: int | None


class NetworkPortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service: str | None
    banner: str | None
    local_address: str | None
    process_id: int | None
    process_name: str | None
    owning_service: str | None
    exposure: str
    risk_score: float
    asset_id: int | None
    host_id: int | None


class NetworkHostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    mac_address: str | None
    hostname: str | None
    vendor: str | None
    discovery_method: str
    is_up: bool
    latency_ms: float | None
    os_guess: str | None
    os_confidence: str
    os_evidence: list[Any]
    is_gateway: bool
    is_local: bool
    scan_id: int | None
    last_seen: datetime | None


class TopologyNodeOut(BaseModel):
    id: str
    label: str
    type: str
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    os_confidence: str = "unknown"
    open_ports: list[int] = Field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "informational"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyEdgeOut(BaseModel):
    source: str
    target: str
    type: str
    confidence: str
    label: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class TopologyOut(BaseModel):
    nodes: list[TopologyNodeOut]
    edges: list[TopologyEdgeOut]
    node_count: int
    edge_count: int
    observed_edges: int
    inferred_edges: int
    confidence_note: str
    scan_id: int | None = None


class TargetCreate(BaseModel):
    name: str = Field(max_length=128)
    value: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    criticality: str = Field(default="normal", pattern="^(critical|high|normal|low)$")
    authorized: bool = Field(
        default=False,
        description=(
            "Attestation that the operator is authorized to assess this target. "
            "Scanning is refused unless this is true or the target is inside a "
            "configured authorized scope."
        ),
    )
    authorization_note: str = Field(default="", max_length=2000)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_type: str
    value: str
    description: str
    authorized: bool
    authorization_note: str
    authorized_at: datetime | None
    criticality: str
    created_at: datetime


class ReportCreate(BaseModel):
    scan_id: int
    format: str = Field(default="html", pattern="^(html|pdf|json|csv)$")
    title: str = Field(default="VulScanner Security Assessment Report", max_length=255)


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    format: str
    status: str
    file_name: str
    size_bytes: int
    scan_id: int | None
    generated_at: datetime | None
    summary: dict[str, Any]
    error_message: str


class RemediationOut(BaseModel):
    items: list[dict[str, Any]]
    summary: dict[str, Any]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action: str
    outcome: str
    actor_name: str
    source_ip: str | None
    entity_type: str | None
    entity_id: str | None
    message: str
    details: dict[str, Any]
    created_at: datetime


class DashboardSummary(BaseModel):
    security_score: float
    total_assets: int
    scanned_assets: int
    total_scans: int
    running_scans: int
    severity_counts: dict[str, int]
    open_findings: int
    resolved_findings: int
    vulnerability_count: int
    kev_vulnerability_count: int
    missing_updates: int
    exposed_ports: int
    misconfigurations: int
    category_distribution: dict[str, int]
    top_risky_assets: list[dict[str, Any]]
    exposed_services: list[dict[str, Any]]
    risk_trend: list[dict[str, Any]]
    patch_status: dict[str, Any]
    last_scan_at: datetime | None
    intelligence: dict[str, Any]
