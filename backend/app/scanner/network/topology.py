"""Network topology graph construction.

Every edge carries an explicit ``confidence``:

``observed``  the relationship was directly evidenced (ARP entry, routing table
              next-hop, imported LLDP/CDP announcement);
``inferred``  the relationship is deduced from addressing (same subnet, gateway
              reachability) and may not reflect physical cabling;
``unknown``   the relationship is a placeholder.

VulScanner never presents an inferred link as physical topology.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class TopologyNode:
    id: str
    label: str
    node_type: str  # scanner | host | gateway | switch | internet | subnet
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    os_confidence: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "informational"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "open_ports": self.open_ports,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "metadata": self.metadata,
        }


@dataclass
class TopologyEdge:
    source: str
    target: str
    edge_type: str  # layer2 | layer3 | gateway | uplink | internet | subnet
    confidence: str  # observed | inferred | unknown
    evidence: dict = field(default_factory=dict)
    label: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "label": self.label,
        }


INTERNET_NODE = "internet"


def _node_id(address: str) -> str:
    return f"host:{address}"


def build_topology(
    hosts: Sequence[dict],
    adapters: dict | None = None,
    arp_entries: Sequence[dict] | None = None,
    lldp_neighbours: Sequence[dict] | None = None,
    cdp_neighbours: Sequence[dict] | None = None,
    scanner_hostname: str = "VulScanner host",
) -> dict:
    """Assemble a topology graph from collected evidence.

    ``hosts`` are discovery records (``DiscoveredHost.to_dict()`` shape).
    """
    adapters = adapters or {}
    nodes: dict[str, TopologyNode] = {}
    edges: list[TopologyEdge] = []

    gateways = [g for g in adapters.get("gateways", []) if g]
    local_addresses = adapters.get("ipv4_addresses", [])
    subnets = adapters.get("local_subnets", [])
    arp_by_ip = {e.get("ip_address"): e for e in (arp_entries or []) if e}

    # -- host nodes --------------------------------------------------------
    for host in hosts:
        address = host.get("ip_address", "")
        if not address:
            continue
        node_id = _node_id(address)
        is_gateway = bool(host.get("is_gateway")) or address in gateways
        nodes[node_id] = TopologyNode(
            id=node_id,
            label=host.get("hostname") or address,
            node_type="gateway" if is_gateway else "host",
            ip_address=address,
            mac_address=host.get("mac_address", ""),
            hostname=host.get("hostname", ""),
            vendor=host.get("vendor", ""),
            os_guess=host.get("os_guess", ""),
            os_confidence=host.get("os_confidence", "unknown"),
            open_ports=[p.get("port") for p in host.get("ports", [])],
            risk_score=float(host.get("risk_score", 0.0) or 0.0),
            severity=host.get("severity", "informational"),
            metadata={
                "discovery_method": host.get("discovery_method", ""),
                "latency_ms": host.get("latency_ms"),
                "is_local": bool(host.get("is_local")),
            },
        )

    # -- the scanning host -------------------------------------------------
    scanner_id = "scanner"
    scanner_address = local_addresses[0] if local_addresses else ""
    nodes[scanner_id] = TopologyNode(
        id=scanner_id,
        label=scanner_hostname,
        node_type="scanner",
        ip_address=scanner_address,
        hostname=scanner_hostname,
        metadata={"addresses": local_addresses, "subnets": subnets},
    )

    # -- gateway nodes even when not discovered ----------------------------
    for gateway in gateways:
        node_id = _node_id(gateway)
        if node_id not in nodes:
            arp = arp_by_ip.get(gateway, {})
            nodes[node_id] = TopologyNode(
                id=node_id,
                label=gateway,
                node_type="gateway",
                ip_address=gateway,
                mac_address=arp.get("mac_address", ""),
                vendor=arp.get("vendor", ""),
                metadata={"source": "routing-table"},
            )
        else:
            nodes[node_id].node_type = "gateway"

        # The default route is direct evidence of a layer-3 relationship.
        edges.append(
            TopologyEdge(
                source=scanner_id,
                target=node_id,
                edge_type="gateway",
                confidence="observed",
                evidence={"source": "routing table default route (0.0.0.0/0)"},
                label="default route",
            )
        )
        edges.append(
            TopologyEdge(
                source=node_id,
                target=INTERNET_NODE,
                edge_type="internet",
                confidence="inferred",
                evidence={
                    "source": "The default gateway is assumed to reach the internet; "
                    "upstream connectivity was not verified."
                },
                label="uplink",
            )
        )

    if gateways:
        nodes[INTERNET_NODE] = TopologyNode(
            id=INTERNET_NODE,
            label="Internet",
            node_type="internet",
            metadata={"note": "Represents anything beyond the default gateway."},
        )

    # -- layer-2 adjacency from the ARP cache ------------------------------
    for entry in arp_entries or []:
        address = entry.get("ip_address")
        if not address:
            continue
        node_id = _node_id(address)
        if node_id not in nodes:
            nodes[node_id] = TopologyNode(
                id=node_id,
                label=address,
                node_type="host",
                ip_address=address,
                mac_address=entry.get("mac_address", ""),
                vendor=entry.get("vendor", ""),
                metadata={"source": "neighbour cache"},
            )
        edges.append(
            TopologyEdge(
                source=scanner_id,
                target=node_id,
                edge_type="layer2",
                confidence="observed",
                evidence={
                    "source": "neighbour cache",
                    "mac": entry.get("mac_address", ""),
                    "state": entry.get("state", ""),
                },
                label="same broadcast domain",
            )
        )

    # -- subnet membership (inferred) --------------------------------------
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue
        subnet_id = f"subnet:{subnet}"
        nodes[subnet_id] = TopologyNode(
            id=subnet_id,
            label=subnet,
            node_type="subnet",
            metadata={"note": "Logical grouping, not a physical device."},
        )
        for node in list(nodes.values()):
            if node.node_type not in ("host", "gateway") or not node.ip_address:
                continue
            try:
                if ipaddress.ip_address(node.ip_address) in network:
                    edges.append(
                        TopologyEdge(
                            source=subnet_id,
                            target=node.id,
                            edge_type="subnet",
                            confidence="inferred",
                            evidence={
                                "source": f"Address falls inside the locally "
                                f"configured prefix {subnet}."
                            },
                            label="member",
                        )
                    )
            except ValueError:
                continue

    # -- announced neighbours (observed, when imported) --------------------
    for neighbour in lldp_neighbours or []:
        name = neighbour.get("system_name") or neighbour.get("chassis_id")
        if not name:
            continue
        node_id = f"switch:{name}"
        nodes[node_id] = TopologyNode(
            id=node_id,
            label=name,
            node_type="switch",
            ip_address=neighbour.get("management_address", ""),
            metadata={
                "port_id": neighbour.get("port_id", ""),
                "description": neighbour.get("system_description", ""),
                "protocol": "LLDP",
            },
        )
        edges.append(
            TopologyEdge(
                source=scanner_id,
                target=node_id,
                edge_type="uplink",
                confidence="observed",
                evidence={
                    "source": "LLDP announcement",
                    "local_interface": neighbour.get("local_interface", ""),
                    "remote_port": neighbour.get("port_id", ""),
                },
                label=neighbour.get("port_id", "LLDP"),
            )
        )

    for neighbour in cdp_neighbours or []:
        name = neighbour.get("device_id")
        if not name:
            continue
        node_id = f"switch:{name}"
        nodes.setdefault(
            node_id,
            TopologyNode(
                id=node_id,
                label=name,
                node_type="switch",
                ip_address=neighbour.get("management_address", ""),
                metadata={"platform": neighbour.get("platform", ""), "protocol": "CDP"},
            ),
        )
        edges.append(
            TopologyEdge(
                source=scanner_id,
                target=node_id,
                edge_type="uplink",
                confidence=neighbour.get("confidence", "observed"),
                evidence={
                    "source": "CDP announcement",
                    "local_interface": neighbour.get("local_interface", ""),
                    "remote_port": neighbour.get("remote_port", ""),
                },
                label=neighbour.get("remote_port", "CDP"),
            )
        )

    # Deduplicate edges on (source, target, type).
    unique: dict[tuple[str, str, str], TopologyEdge] = {}
    for edge in edges:
        key = (edge.source, edge.target, edge.edge_type)
        existing = unique.get(key)
        # Prefer the stronger claim when the same link is evidenced twice.
        if existing is None or (
            existing.confidence == "inferred" and edge.confidence == "observed"
        ):
            unique[key] = edge

    node_list = [node.to_dict() for node in nodes.values()]
    edge_list = [edge.to_dict() for edge in unique.values()]

    return {
        "nodes": node_list,
        "edges": edge_list,
        "node_count": len(node_list),
        "edge_count": len(edge_list),
        "observed_edges": sum(1 for e in edge_list if e["confidence"] == "observed"),
        "inferred_edges": sum(1 for e in edge_list if e["confidence"] == "inferred"),
        "confidence_note": (
            "Edges marked 'inferred' are deduced from IP addressing and routing "
            "configuration. They describe logical reachability, not verified "
            "physical cabling."
        ),
    }
