"""Discovered asset inventory."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.types import JSONList, JSONMap


class Asset(Base, TimestampMixin):
    """A host VulScanner has observed, locally or on an authorized network."""

    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_ip_mac", "ip_address", "mac_address"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    # Stable public identifier used in reports and the UI.
    asset_uid: Mapped[str] = mapped_column(String(36), unique=True, index=True)

    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True)
    ip_addresses: Mapped[list] = mapped_column(JSONList, default=list)
    mac_address: Mapped[str | None] = mapped_column(String(17), index=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)

    os_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_build: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_edition: Mapped[str | None] = mapped_column(String(64), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # local | remote-windows | network-host
    asset_type: Mapped[str] = mapped_column(String(32), default="network-host")
    # How the OS was determined: reported | inferred | unknown
    os_confidence: Mapped[str] = mapped_column(String(16), default="unknown")

    criticality: Mapped[str] = mapped_column(String(16), default="normal")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="informational")

    # Denormalised counters kept in sync by the scan service.
    finding_count: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    high_count: Mapped[int] = mapped_column(default=0)
    medium_count: Mapped[int] = mapped_column(default=0)
    low_count: Mapped[int] = mapped_column(default=0)
    vulnerability_count: Mapped[int] = mapped_column(default=0)
    open_port_count: Mapped[int] = mapped_column(default=0)

    labels: Mapped[dict] = mapped_column(JSONMap, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )

    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan"
    )
    ports: Mapped[list["NetworkPort"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Asset {self.hostname or self.ip_address}>"
