"""Scan schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.scan import ScanProfile


class RemoteCredentialIn(BaseModel):
    """Credentials for an authorized remote assessment.

    Never persisted: used for the duration of the scan and discarded.
    """

    username: str = Field(max_length=128)
    password: str = Field(max_length=256, repr=False)
    auth: str = Field(default="negotiate", pattern="^(negotiate|kerberos|credssp)$")
    port: int | None = Field(default=None, ge=1, le=65535)
    use_ssl: bool = False


class ScanOptions(BaseModel):
    """Everything that can be tuned per scan."""

    ports: str | None = Field(
        default=None,
        description="Port range for discovery, e.g. '22,80,443,8000-8100'.",
    )
    discovery_profile: str = Field(default="safe", pattern="^(safe|standard|custom)$")
    network_discovery: bool = False
    discovery_scope: str | None = None
    max_discovery_hosts: int = Field(default=4096, ge=1, le=65536)
    banner_grab: bool = False
    resolve_names: bool = True
    vulnerability_correlation: bool = True
    cve_product_limit: int = Field(default=20, ge=0, le=200)
    query_windows_update: bool = True
    generate_report: bool = False
    report_format: str = Field(default="html", pattern="^(html|pdf|json|csv)$")
    include_collectors: list[str] | None = None
    exclude_collectors: list[str] | None = None
    collector_timeout: int = Field(default=120, ge=10, le=900)
    fs_max_files: int = Field(default=5000, ge=0, le=100000)
    fs_hash: bool = False


class ScanCreate(BaseModel):
    name: str = Field(default="", max_length=160)
    target: str = Field(min_length=1, max_length=255)
    profile: ScanProfile = ScanProfile.STANDARD
    options: ScanOptions = Field(default_factory=ScanOptions)
    credential: RemoteCredentialIn | None = None

    @field_validator("target")
    @classmethod
    def _trim(cls, value: str) -> str:
        return value.strip()


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target: str
    target_type: str
    profile: str
    status: str
    progress: float
    current_stage: str
    security_score: float | None
    risk_score: float | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    asset_count: int
    vulnerability_count: int
    scanner_version: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    created_at: datetime


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    collector: str
    category: str
    status: str
    collection_method: str
    collected_at: datetime | None
    duration_seconds: float | None
    warnings: list[Any]
    errors: list[Any]


class ScanDetail(ScanOut):
    options: dict[str, Any]
    stages: list[Any]
    warnings: list[Any]
    errors: list[Any]
    error_message: str
    results: list[ScanResultOut] = Field(default_factory=list)


class ScanProgressEvent(BaseModel):
    scan_id: int
    stage: str
    progress: float
    message: str
    status: str
    timestamp: str
