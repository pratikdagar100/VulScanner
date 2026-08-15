"""``vulscanner network`` - authorized network discovery and topology."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.core.permissions import AuthorizationError
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.services.scan_service import scan_service
from cli.output import Console


def register(subparsers: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "network",
        parents=[common],
        help="Discover and assess an authorized network.",
    )
    network_subparsers = parser.add_subparsers(dest="network_command", metavar="<action>")

    discover = network_subparsers.add_parser(
        "discover",
        parents=[common],
        help="Discover live hosts and exposed services in an authorized scope.",
        description=(
            "Discovery uses ordinary TCP connect probes and reverse DNS. VulScanner "
            "implements no stealth, fragmentation or evasion techniques."
        ),
    )
    discover.add_argument(
        "--scope", "-s", required=True, metavar="CIDR",
        help="Authorized network scope, e.g. 192.168.1.0/24.",
    )
    discover.add_argument(
        "--profile", choices=["safe", "standard"], default="safe",
        help="Port set to sweep (default: safe).",
    )
    discover.add_argument("--ports", help="Explicit port range, e.g. '22,80,443'.")
    discover.add_argument(
        "--banner", action="store_true", help="Read service banners on open ports."
    )
    discover.add_argument(
        "--no-resolve", action="store_true", help="Skip reverse DNS lookups."
    )
    discover.add_argument(
        "--max-hosts", type=int, default=4096,
        help="Safety limit on the number of addresses probed (default: 4096).",
    )
    discover.set_defaults(handler=handle_discover)

    topology = network_subparsers.add_parser(
        "topology", parents=[common], help="Show the topology from the latest scan."
    )
    topology.add_argument("--scan-id", type=int, help="Use a specific scan.")
    topology.set_defaults(handler=handle_topology)

    hosts = network_subparsers.add_parser(
        "hosts", parents=[common], help="List discovered hosts."
    )
    hosts.add_argument("--scan-id", type=int)
    hosts.set_defaults(handler=handle_hosts)

    parser.set_defaults(handler=lambda args, console: _no_action(parser, console))


def _no_action(parser: argparse.ArgumentParser, console: Console) -> int:
    parser.print_help()
    return 1


def handle_discover(args: argparse.Namespace, console: Console) -> int:
    from app.core.config import APP_VERSION

    console.banner(APP_VERSION)
    console.header(f"Network discovery: {args.scope}")
    console.key_values(
        [
            ("Scope", args.scope),
            ("Profile", args.profile),
            ("Ports", args.ports or f"{args.profile} port set"),
            ("Banner grabbing", "enabled" if args.banner else "disabled"),
            ("Method", "TCP connect probes (no stealth or evasion)"),
        ]
    )
    console.write("")

    options = {
        "discovery_profile": args.profile,
        "network_discovery": True,
        "discovery_scope": args.scope,
        "banner_grab": bool(args.banner),
        "resolve_names": not args.no_resolve,
        "max_discovery_hosts": args.max_hosts,
        "vulnerability_correlation": False,
    }
    if args.ports:
        options["ports"] = args.ports

    init_db()
    db = SessionLocal()

    def on_progress(stage: str, percent: float, message: str) -> None:
        console.progress(percent, stage, message)

    try:
        scan = scan_service.run_sync(
            db,
            name=f"Network discovery of {args.scope}",
            target=args.scope,
            profile="network",
            options=options,
            actor_name="cli",
            progress_callback=on_progress,
        )
    except AuthorizationError as exc:
        console.end_progress()
        console.error(str(exc))
        return 3

    console.end_progress()

    from sqlalchemy import select

    from app.models.network import NetworkHost, NetworkPort

    hosts = list(
        db.scalars(select(NetworkHost).where(NetworkHost.scan_id == scan.id)).all()
    )
    ports = list(
        db.scalars(select(NetworkPort).where(NetworkPort.scan_id == scan.id)).all()
    )
    ports_by_host: dict[int, list[NetworkPort]] = {}
    for port in ports:
        if port.host_id is not None:
            ports_by_host.setdefault(port.host_id, []).append(port)

    payload = {
        "scan_id": scan.id,
        "scope": args.scope,
        "host_count": len(hosts),
        "hosts": [
            {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "mac_address": host.mac_address,
                "vendor": host.vendor,
                "os_guess": host.os_guess,
                "os_confidence": host.os_confidence,
                "is_gateway": host.is_gateway,
                "discovery_method": host.discovery_method,
                "latency_ms": host.latency_ms,
                "open_ports": [
                    {"port": p.port, "service": p.service, "banner": p.banner}
                    for p in sorted(ports_by_host.get(host.id, []), key=lambda p: p.port)
                ],
            }
            for host in hosts
        ],
    }

    if args.json:
        output = json.dumps(payload, indent=2, default=str)
        _emit(output, args, console)
        return 0
    if args.csv:
        import csv
        import io

        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            ["ip_address", "hostname", "mac_address", "vendor", "os_guess",
             "os_confidence", "gateway", "open_ports"]
        )
        for host in payload["hosts"]:
            writer.writerow(
                [
                    host["ip_address"], host["hostname"] or "", host["mac_address"] or "",
                    host["vendor"] or "", host["os_guess"] or "", host["os_confidence"],
                    "yes" if host["is_gateway"] else "no",
                    " ".join(str(p["port"]) for p in host["open_ports"]),
                ]
            )
        _emit(buffer.getvalue(), args, console)
        return 0

    console.header(f"Discovered {len(hosts)} host(s)")
    console.table(
        ["IP address", "Hostname", "MAC", "Vendor", "OS (inferred)", "Conf.", "Open ports"],
        [
            [
                host["ip_address"],
                host["hostname"] or "-",
                host["mac_address"] or "-",
                host["vendor"] or "-",
                (host["os_guess"] or "unknown") + (" [gw]" if host["is_gateway"] else ""),
                host["os_confidence"],
                ", ".join(
                    f"{p['port']}/{p['service']}" if p["service"] else str(p["port"])
                    for p in host["open_ports"]
                ) or "-",
            ]
            for host in payload["hosts"]
        ],
        max_widths=[16, 24, 18, 20, 22, 9, 48],
    )

    if not hosts:
        console.info(
            "No hosts responded. Firewalls commonly drop probes; this does not "
            "prove the network is empty."
        )

    console.write("")
    console.info(
        console.paint(
            "OS values are inferred from the observed service mix and are labelled "
            "with a confidence level - they are not definitive identification.",
            "grey",
        )
    )
    return 0


def handle_topology(args: argparse.Namespace, console: Console) -> int:
    from sqlalchemy import desc, select

    from app.models.network import NetworkEdge

    init_db()
    db = SessionLocal()

    scan_id = args.scan_id
    if scan_id is None:
        scan_id = db.scalar(select(NetworkEdge.scan_id).order_by(desc(NetworkEdge.id)).limit(1))
    if scan_id is None:
        console.warn("No topology data has been collected yet. Run a scan first.")
        return 0

    edges = list(db.scalars(select(NetworkEdge).where(NetworkEdge.scan_id == scan_id)).all())

    if args.json:
        _emit(
            json.dumps(
                [
                    {
                        "source": e.source_node, "target": e.target_node,
                        "type": e.edge_type, "confidence": e.relationship_confidence,
                        "label": e.label, "evidence": e.evidence,
                    }
                    for e in edges
                ],
                indent=2,
            ),
            args,
            console,
        )
        return 0

    console.header(f"Network topology (scan #{scan_id})")
    console.table(
        ["Source", "Target", "Type", "Confidence", "Evidence"],
        [
            [
                edge.source_node, edge.target_node, edge.edge_type,
                edge.relationship_confidence,
                (edge.evidence or {}).get("source", ""),
            ]
            for edge in edges
        ],
        max_widths=[26, 26, 12, 12, 46],
    )
    observed = sum(1 for e in edges if e.relationship_confidence == "observed")
    console.write("")
    console.info(
        f"{observed} observed edge(s), {len(edges) - observed} inferred. "
        "Inferred edges describe logical reachability, not verified cabling."
    )
    return 0


def handle_hosts(args: argparse.Namespace, console: Console) -> int:
    from sqlalchemy import desc, select

    from app.models.network import NetworkHost

    init_db()
    db = SessionLocal()
    query = select(NetworkHost).order_by(desc(NetworkHost.last_seen))
    if args.scan_id:
        query = query.where(NetworkHost.scan_id == args.scan_id)
    hosts = list(db.scalars(query.limit(500)).all())

    console.header(f"Discovered hosts ({len(hosts)})")
    console.table(
        ["IP address", "Hostname", "MAC", "Vendor", "OS (inferred)", "Scan"],
        [
            [h.ip_address, h.hostname or "-", h.mac_address or "-", h.vendor or "-",
             h.os_guess or "unknown", f"#{h.scan_id}"]
            for h in hosts
        ],
    )
    return 0


def _emit(content: str, args: argparse.Namespace, console: Console) -> None:
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.success(f"Written to {path}")
    else:
        console.always(content)
