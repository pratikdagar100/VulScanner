"""Scan and per-collector result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.types import JSONList, JSONMap


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    NETWORK = "network"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


TERMINAL_STATUSES = {
    ScanStatus.COMPLETED,
    ScanStatus.PARTIAL,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
}


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))

    target: Mapped[str] = mapped_column(String(255), index=True)
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )

    profile: Mapped[str] = mapped_column(String(24), default=ScanProfile.STANDARD.value)
    status: Mapped[str] = mapped_column(
        String(16), default=ScanStatus.QUEUED.value, index=True
    )

    # Options actually used (port range, discovery flags, module selection...).
    options: Mapped[dict] = mapped_column(JSONMap, default=dict)

    progress: Mapped[float] = mapped_column(Float, default=0.0)
    current_stage: Mapped[str] = mapped_column(String(64), default="")
    stages: Mapped[list] = mapped_column(JSONList, default=list)

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    scanner_version: Mapped[str] = mapped_column(String(32), default="")
    scanner_host: Mapped[str] = mapped_column(String(255), default="")

    # Roll-ups computed when the scan finishes.
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)

    warnings: Mapped[list] = mapped_column(JSONList, default=list)
    errors: Mapped[list] = mapped_column(JSONList, default=list)
    error_message: Mapped[str] = mapped_column(Text, default="")

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan #{self.id} {self.target} {self.status}>"


class ScanResult(Base, TimestampMixin):
    """Raw normalized output of one collector for one scan.

    This is the evidence store: every finding points back at the collector
    result that produced it.
    """

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    collector: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), default="windows")

    # success | partial | failed | skipped
    status: Mapped[str] = mapped_column(String(16), default="success")

    data: Mapped[dict] = mapped_column(JSONMap, default=dict)
    warnings: Mapped[list] = mapped_column(JSONList, default=list)
    errors: Mapped[list] = mapped_column(JSONList, default=list)

    collection_method: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="results")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanResult {self.collector} {self.status}>"
