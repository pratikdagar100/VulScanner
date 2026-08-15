"""Network hosts, ports, connections and topology edges."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.types import JSONList, JSONMap


class NetworkHost(Base, TimestampMixin):
    """A host observed during network discovery."""

    __tablename__ = "network_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)

    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # How liveness was established: icmp | arp | tcp-connect | local
    discovery_method: Mapped[str] = mapped_column(String(32), default="")
    is_up: Mapped[bool] = mapped_column(Boolean, default=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # OS guess with an explicit confidence - never presented as fact.
    os_guess: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_confidence: Mapped[str] = mapped_column(String(16), default="unknown")
    os_evidence: Mapped[list] = mapped_column(JSONList, default=list)

    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    is_local: Mapped[bool] = mapped_column(Boolean, default=False)

    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<NetworkHost {self.ip_address}>"


class NetworkPort(Base, TimestampMixin):
    """A listening port / service endpoint."""

    __tablename__ = "network_ports"

    id: Mapped[int] = mapped_column(primary_key=True)

    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")

    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service_source: Mapped[str] = mapped_column(String(24), default="well-known")
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    local_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    owning_service: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # loopback | private | any/all-interfaces | public
    exposure: Mapped[str] = mapped_column(String(24), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True
    )
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_hosts.id", ondelete="CASCADE"), nullable=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )

    asset: Mapped["Asset | None"] = relationship(back_populates="ports")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<NetworkPort {self.protocol}/{self.port} {self.state}>"


class NetworkConnection(Base, TimestampMixin):
    """An observed TCP connection or UDP endpoint on a scanned host."""

    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(primary_key=True)

    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    local_address: Mapped[str] = mapped_column(String(45), default="")
    local_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remote_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str | None] = mapped_column(String(24), nullable=True)

    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    remote_scope: Mapped[str] = mapped_column(String(16), default="unknown")

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )


class NetworkEdge(Base, TimestampMixin):
    """A topology relationship between two nodes.

    ``relationship_confidence`` is mandatory: VulScanner distinguishes observed
    links (ARP, LLDP/CDP, routing table) from inferred ones (same subnet).
    """

    __tablename__ = "network_edges"

    id: Mapped[int] = mapped_column(primary_key=True)

    source_node: Mapped[str] = mapped_column(String(128), index=True)
    target_node: Mapped[str] = mapped_column(String(128), index=True)

    # layer2 | layer3 | gateway | dns | uplink | internet
    edge_type: Mapped[str] = mapped_column(String(24), default="layer3")
    # observed | inferred | unknown
    relationship_confidence: Mapped[str] = mapped_column(String(16), default="inferred")
    evidence: Mapped[dict] = mapped_column(JSONMap, default=dict)
    label: Mapped[str] = mapped_column(String(128), default="")

    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<NetworkEdge {self.source_node}->{self.target_node} "
            f"({self.relationship_confidence})>"
        )
