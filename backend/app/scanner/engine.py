"""VulScanner scan engine.

Runs the collector set for a profile against an authorized target, then network
discovery when the target is a scope. A failing collector is recorded and the
scan continues - no single collector can abort an assessment.
"""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.config import APP_VERSION
from app.core.logging import get_logger
from app.core.permissions import authorize_target
from app.scanner.base import CollectorResult, CollectorStatus
from app.scanner.context import ScanCancelled, ScanContext
from app.scanner.network.discovery import (
    DISCOVERY_PROFILES,
    NetworkDiscovery,
    expand_scope,
    summarize,
)
from app.scanner.network.topology import build_topology
from app.scanner.registry import collectors_for_profile
from app.scanner.runner import RemoteCredential

logger = get_logger(__name__)

# Stage weights so progress reflects real cost rather than collector count.
STAGE_WEIGHTS = {
    "preflight": 3.0,
    "collection": 60.0,
    "discovery": 25.0,
    "topology": 4.0,
    "analysis": 8.0,
}


@dataclass
class ScanOutput:
    """Everything one engine run produced."""

    target: str
    target_type: str
    profile: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    scanner_version: str = APP_VERSION
    scanner_host: str = ""

    results: list[CollectorResult] = field(default_factory=list)
    discovery: dict[str, Any] = field(default_factory=dict)
    topology: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False
    elevated: bool = False

    # -- lookups -----------------------------------------------------------
    def data(self, collector: str) -> dict:
        for result in self.results:
            if result.collector == collector:
                return result.data or {}
        return {}

    def result(self, collector: str) -> CollectorResult | None:
        return next((r for r in self.results if r.collector == collector), None)

    @property
    def status(self) -> str:
        if self.cancelled:
            return "cancelled"
        if not self.results and not self.discovery:
            return "failed"
        if any(r.status is CollectorStatus.FAILED for r in self.results) or self.errors:
            return "partial"
        if any(r.status is CollectorStatus.PARTIAL for r in self.results):
            return "partial"
        return "completed"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "profile": self.profile,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "scanner_version": self.scanner_version,
            "scanner_host": self.scanner_host,
            "elevated": self.elevated,
            "results": [r.to_dict() for r in self.results],
            "discovery": self.discovery,
            "topology": self.topology,
            "warnings": self.warnings,
            "errors": self.errors,
        }


class ScanEngine:
    """Executes one assessment."""

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    # -- construction ------------------------------------------------------
    @classmethod
    def for_target(
        cls,
        target: str,
        profile: str = "standard",
        options: dict | None = None,
        credential: RemoteCredential | None = None,
        extra_authorized: list[str] | None = None,
        scan_id: int | None = None,
        progress_callback=None,
    ) -> "ScanEngine":
        authorization = authorize_target(target, extra_authorized)
        context = ScanContext(
            authorization=authorization,
            profile=profile,
            options=options or {},
            credential=credential,
            scan_id=scan_id,
        )
        context.progress_callback = progress_callback
        return cls(context)

    # -- execution ---------------------------------------------------------
    def run(self) -> ScanOutput:
        context = self.context
        started = datetime.now(tz=timezone.utc)
        clock = time.perf_counter()

        output = ScanOutput(
            target=context.target,
            target_type=context.target_kind,
            profile=context.profile,
            started_at=started,
            scanner_host=context.scanner_host,
        )

        try:
            self._preflight(output)
            if context.is_network_scope:
                self._run_scanner_context_collectors(output)
            else:
                self._run_collectors(output)
            if self._should_discover():
                self._run_discovery(output)
            self._build_topology(output)
        except ScanCancelled as exc:
            output.cancelled = True
            output.warnings.append(str(exc))
            logger.info("Scan %s cancelled", context.scan_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Scan %s failed", context.scan_id)
            output.errors.append(f"{type(exc).__name__}: {exc}")

        output.finished_at = datetime.now(tz=timezone.utc)
        output.duration_seconds = time.perf_counter() - clock
        context.report_progress("complete", 100.0, "Scan finished")
        return output

    # -- stages ------------------------------------------------------------
    def _preflight(self, output: ScanOutput) -> None:
        context = self.context
        context.report_progress("preflight", 0.0, "Validating target and environment")

        if context.is_network_scope:
            return

        if context.is_local and platform.system() != "Windows":
            output.warnings.append(
                "VulScanner is running on a non-Windows host. Windows collectors "
                "are skipped; network assessment is still available."
            )
            return

        if not context.runner.available:
            output.errors.append(
                "PowerShell could not be located. Windows collection is unavailable."
            )
            return

        output.elevated = context.runner.is_elevated()
        if not output.elevated:
            output.warnings.append(
                "VulScanner is not running with administrative privileges. "
                "Defender preferences, audit policy, the local security policy and "
                "some firewall detail will be incomplete."
            )
        if context.credential:
            output.warnings.append(
                f"Remote assessment of {context.target} over WinRM. Ensure the "
                "operator is authorized to assess this host."
            )
        context.report_progress("preflight", STAGE_WEIGHTS["preflight"], "Ready")

    def _run_collectors(self, output: ScanOutput) -> None:
        context = self.context
        collectors = collectors_for_profile(
            context.profile,
            include=context.option("include_collectors"),
            exclude=context.option("exclude_collectors"),
        )
        if not collectors:
            output.warnings.append(
                f"No collectors are defined for profile '{context.profile}'."
            )
            return

        base = STAGE_WEIGHTS["preflight"]
        span = STAGE_WEIGHTS["collection"]
        total = len(collectors)

        for index, collector_class in enumerate(collectors, start=1):
            context.raise_if_cancelled()
            percent = base + span * (index - 1) / total
            context.report_progress(
                collector_class.name, percent, f"Collecting {collector_class.description}"
            )

            collector = collector_class(context)
            result = collector.run()
            output.results.append(result)

            if result.status is CollectorStatus.FAILED:
                message = f"{collector_class.name}: {'; '.join(result.errors)}"
                output.errors.append(message)
                logger.warning("Collector failed - %s", message)
            elif result.status is CollectorStatus.PARTIAL:
                for warning in result.warnings + result.errors:
                    output.warnings.append(f"{collector_class.name}: {warning}")

        context.report_progress("collection", base + span, "Collection complete")

    def _run_scanner_context_collectors(self, output: ScanOutput) -> None:
        """Collect the scanning host's own network view for a scope scan.

        A CIDR scan runs no Windows collectors against the targets, but the
        machine running VulScanner can describe its own adapters and neighbour
        cache. That local context supplies MAC addresses, vendor attribution and
        gateway identification for the hosts that are discovered.
        """
        context = self.context
        if platform.system() != "Windows":
            return

        from app.core.permissions import authorize_target
        from app.scanner.network.adapters import AdaptersCollector
        from app.scanner.network.arp import ArpCollector

        local_context = ScanContext(
            authorization=authorize_target("local"),
            profile=context.profile,
            options=context.options,
            scan_id=context.scan_id,
        )
        context.report_progress(
            "collection", STAGE_WEIGHTS["preflight"], "Reading local network context"
        )
        for collector_class in (AdaptersCollector, ArpCollector):
            context.raise_if_cancelled()
            result = collector_class(local_context).run()
            output.results.append(result)
            if result.status is CollectorStatus.FAILED:
                output.warnings.append(
                    f"{collector_class.name}: local network context unavailable "
                    f"({'; '.join(result.errors)})"
                )

    def _should_discover(self) -> bool:
        context = self.context
        if context.is_network_scope:
            return True
        return bool(context.option("network_discovery", False))

    def _run_discovery(self, output: ScanOutput) -> None:
        context = self.context
        context.raise_if_cancelled()

        scope = context.option("discovery_scope") or (
            context.authorization.normalized if context.is_network_scope else ""
        )
        if not scope:
            # Fall back to the locally attached subnets we already collected.
            subnets = output.data("adapters").get("local_subnets", [])
            if not subnets:
                output.warnings.append(
                    "Network discovery was requested but no scope could be "
                    "determined."
                )
                return
            scope = subnets[0]
            output.warnings.append(
                f"No discovery scope was supplied; using the locally attached "
                f"subnet {scope}."
            )

        try:
            hosts = expand_scope(
                scope, max_hosts=int(context.option("max_discovery_hosts", 4096))
            )
        except ValueError as exc:
            output.errors.append(str(exc))
            return

        discovery_profile = context.option("discovery_profile", "safe")
        ports = context.option("ports")
        if isinstance(ports, str):
            ports = parse_port_range(ports)

        base = STAGE_WEIGHTS["preflight"] + STAGE_WEIGHTS["collection"]
        span = STAGE_WEIGHTS["discovery"]

        def liveness_progress(done: int, total: int, message: str) -> None:
            context.report_progress(
                "discovery",
                base + span * 0.4 * (done / max(total, 1)),
                f"Sweeping {scope}: {message}",
            )

        def port_progress(done: int, total: int, message: str) -> None:
            context.report_progress(
                "discovery",
                base + span * (0.4 + 0.6 * (done / max(total, 1))),
                f"Service sweep: {message}",
            )

        discovery = NetworkDiscovery(
            profile=discovery_profile,
            ports=ports,
            timeout=float(context.option("portscan_timeout", 0) or 0) or None,
            concurrency=context.option("discovery_concurrency"),
            banner_grab=bool(context.option("banner_grab", False)),
            resolve_names=bool(context.option("resolve_names", True)),
            cancel_check=lambda: context.cancelled,
        )

        context.report_progress("discovery", base, f"Discovering hosts in {scope}")
        live_hosts = discovery.discover(hosts, progress=liveness_progress)
        discovery.scan_all(live_hosts, progress=port_progress)

        adapters = output.data("adapters")
        discovery.enrich(
            live_hosts,
            arp_entries=output.data("arp").get("neighbours", []),
            gateways=adapters.get("gateways", []),
            local_addresses=adapters.get("ipv4_addresses", []),
        )

        host_dicts = [host.to_dict() for host in live_hosts]
        output.discovery = {
            "scope": scope,
            "profile": discovery_profile,
            "addresses_probed": len(hosts),
            "ports_probed": list(
                discovery.ports or DISCOVERY_PROFILES.get(discovery_profile, ())
            ),
            "hosts": host_dicts,
            "summary": summarize(live_hosts),
            "method": (
                "TCP connect probes and reverse DNS. No stealth, fragmentation or "
                "evasion techniques are used."
            ),
        }
        context.report_progress(
            "discovery", base + span, f"{len(live_hosts)} hosts discovered"
        )

    def _build_topology(self, output: ScanOutput) -> None:
        context = self.context
        context.raise_if_cancelled()
        base = (
            STAGE_WEIGHTS["preflight"]
            + STAGE_WEIGHTS["collection"]
            + STAGE_WEIGHTS["discovery"]
        )
        context.report_progress("topology", base, "Building network topology")

        hosts = output.discovery.get("hosts", [])
        adapters = output.data("adapters")
        arp = output.data("arp").get("neighbours", [])

        if not hosts and not adapters and not arp:
            return

        output.topology = build_topology(
            hosts=hosts,
            adapters=adapters,
            arp_entries=arp,
            lldp_neighbours=output.data("lldp").get("neighbours", []),
            cdp_neighbours=output.data("cdp").get("neighbours", []),
            scanner_hostname=output.data("os").get("hostname") or context.scanner_host,
        )
        context.report_progress(
            "topology", base + STAGE_WEIGHTS["topology"], "Topology built"
        )


def parse_port_range(value: str) -> list[int]:
    """Parse ``"22,80,443,8000-8100"`` into a sorted, de-duplicated port list."""
    ports: set[int] = set()
    for chunk in str(value).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            try:
                low, high = int(start), int(end)
            except ValueError:
                continue
            if low > high:
                low, high = high, low
            ports.update(range(max(1, low), min(65535, high) + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)
