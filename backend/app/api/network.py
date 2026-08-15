"""Network topology, hosts, ports and connection endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select

from app.api.deps import DbSession, pagination, require
from app.models.asset import Asset
from app.models.network import NetworkConnection, NetworkEdge, NetworkHost, NetworkPort
from app.models.scan import Scan
from app.models.user import User
from app.schemas.security import NetworkHostOut, NetworkPortOut, TopologyOut

router = APIRouter(prefix="/api/network", tags=["Network"])


@router.get("/topology", response_model=TopologyOut)
def get_topology(
    db: DbSession,
    _: Annotated[User, Depends(require("network:read"))],
    scan_id: int | None = Query(
        default=None, description="Defaults to the most recent scan with topology data."
    ),
) -> dict:
    """The network topology graph, with per-edge confidence.

    Nodes are rebuilt from stored hosts and assets; edges carry the evidence and
    confidence recorded at scan time. Inferred edges describe logical
    reachability, not verified physical cabling.
    """
    if scan_id is None:
        latest = db.scalar(
            select(NetworkEdge.scan_id)
            .order_by(desc(NetworkEdge.id))
            .limit(1)
        )
        scan_id = latest

    if scan_id is None:
        return {
            "nodes": [], "edges": [], "node_count": 0, "edge_count": 0,
            "observed_edges": 0, "inferred_edges": 0,
            "confidence_note": "No topology data has been collected yet.",
            "scan_id": None,
        }

    edges = list(
        db.scalars(select(NetworkEdge).where(NetworkEdge.scan_id == scan_id)).all()
    )
    hosts = list(
        db.scalars(select(NetworkHost).where(NetworkHost.scan_id == scan_id)).all()
    )
    scan = db.get(Scan, scan_id)

    ports_by_host: dict[int, list[int]] = {}
    for port in db.scalars(
        select(NetworkPort).where(NetworkPort.scan_id == scan_id)
    ).all():
        if port.host_id is not None:
            ports_by_host.setdefault(port.host_id, []).append(port.port)

    nodes: dict[str, dict] = {}
    for host in hosts:
        node_id = f"host:{host.ip_address}"
        nodes[node_id] = {
            "id": node_id,
            "label": host.hostname or host.ip_address,
            "type": "gateway" if host.is_gateway else "host",
            "ip_address": host.ip_address,
            "mac_address": host.mac_address or "",
            "hostname": host.hostname or "",
            "vendor": host.vendor or "",
            "os_guess": host.os_guess or "",
            "os_confidence": host.os_confidence,
            "open_ports": sorted(ports_by_host.get(host.id, [])),
            "risk_score": 0.0,
            "severity": "informational",
            "metadata": {
                "discovery_method": host.discovery_method,
                "latency_ms": host.latency_ms,
                "is_local": host.is_local,
                "os_evidence": host.os_evidence,
            },
        }

    # The scanning host and any endpoints referenced only by an edge.
    scanner_label = scan.scanner_host if scan else "VulScanner host"
    asset = db.scalar(select(Asset).order_by(desc(Asset.last_seen)).limit(1))
    nodes.setdefault(
        "scanner",
        {
            "id": "scanner",
            "label": (asset.hostname if asset else scanner_label) or "VulScanner host",
            "type": "scanner",
            "ip_address": asset.ip_address if asset else "",
            "mac_address": asset.mac_address if asset else "",
            "hostname": asset.hostname if asset else "",
            "vendor": "",
            "os_guess": asset.os_name if asset else "",
            "os_confidence": "reported" if asset else "unknown",
            "open_ports": [],
            "risk_score": asset.risk_score if asset else 0.0,
            "severity": asset.severity if asset else "informational",
            "metadata": {"scan_id": scan_id},
        },
    )

    for edge in edges:
        for endpoint in (edge.source_node, edge.target_node):
            if endpoint in nodes:
                continue
            kind, _, value = endpoint.partition(":")
            nodes[endpoint] = {
                "id": endpoint,
                "label": value or endpoint,
                "type": {
                    "subnet": "subnet", "switch": "switch", "internet": "internet"
                }.get(kind, "host" if kind == "host" else kind or "host"),
                "ip_address": value if kind == "host" else "",
                "mac_address": "", "hostname": "", "vendor": "",
                "os_guess": "", "os_confidence": "unknown",
                "open_ports": [], "risk_score": 0.0, "severity": "informational",
                "metadata": {"source": "topology edge"},
            }

    edge_list = [
        {
            "source": edge.source_node,
            "target": edge.target_node,
            "type": edge.edge_type,
            "confidence": edge.relationship_confidence,
            "label": edge.label,
            "evidence": edge.evidence,
        }
        for edge in edges
    ]

    return {
        "nodes": list(nodes.values()),
        "edges": edge_list,
        "node_count": len(nodes),
        "edge_count": len(edge_list),
        "observed_edges": sum(1 for e in edge_list if e["confidence"] == "observed"),
        "inferred_edges": sum(1 for e in edge_list if e["confidence"] == "inferred"),
        "confidence_note": (
            "Edges marked 'observed' were directly evidenced (neighbour cache, "
            "routing table or an imported LLDP/CDP announcement). Edges marked "
            "'inferred' are deduced from IP addressing and describe logical "
            "reachability, not verified physical cabling."
        ),
        "scan_id": scan_id,
    }


@router.get("/hosts", response_model=list[NetworkHostOut])
def list_hosts(
    db: DbSession,
    _: Annotated[User, Depends(require("network:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    vendor: str | None = None,
    gateway_only: bool = False,
) -> list[NetworkHost]:
    limit, offset = page
    query = select(NetworkHost)
    if scan_id is not None:
        query = query.where(NetworkHost.scan_id == scan_id)
    if vendor:
        query = query.where(NetworkHost.vendor.ilike(f"%{vendor}%"))
    if gateway_only:
        query = query.where(NetworkHost.is_gateway.is_(True))
    return list(
        db.scalars(
            query.order_by(desc(NetworkHost.last_seen)).limit(limit).offset(offset)
        ).all()
    )


@router.get("/ports", response_model=list[NetworkPortOut])
def list_ports(
    db: DbSession,
    _: Annotated[User, Depends(require("network:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    asset_id: int | None = None,
    exposure: str | None = None,
    port: int | None = None,
    protocol: str | None = Query(default=None, pattern="^(tcp|udp)$"),
) -> list[NetworkPort]:
    limit, offset = page
    query = select(NetworkPort)
    if scan_id is not None:
        query = query.where(NetworkPort.scan_id == scan_id)
    if asset_id is not None:
        query = query.where(NetworkPort.asset_id == asset_id)
    if exposure:
        query = query.where(NetworkPort.exposure == exposure)
    if port is not None:
        query = query.where(NetworkPort.port == port)
    if protocol:
        query = query.where(NetworkPort.protocol == protocol)
    return list(
        db.scalars(
            query.order_by(desc(NetworkPort.risk_score), NetworkPort.port)
            .limit(limit)
            .offset(offset)
        ).all()
    )


@router.get("/connections")
def list_connections(
    db: DbSession,
    _: Annotated[User, Depends(require("network:read"))],
    page: Annotated[tuple[int, int], Depends(pagination)],
    scan_id: int | None = None,
    remote_scope: str | None = None,
) -> list[dict]:
    limit, offset = page
    query = select(NetworkConnection)
    if scan_id is not None:
        query = query.where(NetworkConnection.scan_id == scan_id)
    if remote_scope:
        query = query.where(NetworkConnection.remote_scope == remote_scope)

    return [
        {
            "id": connection.id,
            "protocol": connection.protocol,
            "local_address": connection.local_address,
            "local_port": connection.local_port,
            "remote_address": connection.remote_address,
            "remote_port": connection.remote_port,
            "state": connection.state,
            "process_id": connection.process_id,
            "process_name": connection.process_name,
            "remote_scope": connection.remote_scope,
        }
        for connection in db.scalars(query.limit(limit).offset(offset)).all()
    ]


@router.get("/services")
def service_distribution(
    db: DbSession,
    _: Annotated[User, Depends(require("network:read"))],
    scan_id: int | None = None,
) -> list[dict]:
    """Exposed services aggregated across the assessed estate."""
    query = select(NetworkPort)
    if scan_id is not None:
        query = query.where(NetworkPort.scan_id == scan_id)

    aggregate: dict[tuple[int, str], dict] = {}
    for port in db.scalars(query).all():
        if port.exposure == "loopback":
            continue
        key = (port.port, port.protocol)
        entry = aggregate.setdefault(
            key,
            {
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service or "unknown",
                "count": 0,
                "max_risk_score": 0.0,
                "exposures": set(),
            },
        )
        entry["count"] += 1
        entry["max_risk_score"] = max(entry["max_risk_score"], port.risk_score)
        entry["exposures"].add(port.exposure)

    return sorted(
        (
            {**entry, "exposures": sorted(entry["exposures"])}
            for entry in aggregate.values()
        ),
        key=lambda entry: (-entry["max_risk_score"], -entry["count"]),
    )
