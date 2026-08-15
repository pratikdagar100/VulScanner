"""Authorized network discovery and port assessment.

Discovery is deliberately conventional and noisy-by-design: full TCP connect
handshakes and ordinary ICMP echo requests. VulScanner implements no stealth,
fragmentation, decoy or evasion techniques - an assessment must be visible to
the defenders of the network being assessed.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from app.core.config import settings
from app.core.logging import get_logger
from app.scanner.network.oui import lookup_vendor
from app.scanner.network.services import (
    HIGH_RISK_PORTS,
    classify_exposure,
    service_for,
)

logger = get_logger(__name__)

# Ports probed to establish liveness when ICMP is filtered.
LIVENESS_PORTS: tuple[int, ...] = (445, 135, 139, 3389, 22, 80, 443, 5985, 631, 8080)

# Default service sweep for the "safe" profile.
SAFE_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443,
)

# Broader sweep for the "standard" profile.
STANDARD_PORTS: tuple[int, ...] = tuple(
    sorted(
        set(SAFE_PORTS)
        | {
            20, 69, 111, 123, 161, 179, 427, 500, 515, 548, 623, 631, 873, 902,
            1080, 1194, 1521, 1723, 2049, 2179, 2375, 2376, 3000, 3128, 3268,
            3269, 4444, 5000, 5060, 5222, 5357, 5672, 6379, 6443, 7680, 8000,
            8008, 8081, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017, 47001,
        }
    )
)

DISCOVERY_PROFILES: dict[str, tuple[int, ...]] = {
    "safe": SAFE_PORTS,
    "standard": STANDARD_PORTS,
}

# OS hints derived from the observed service mix. Always reported with a
# confidence level - never presented as a definitive identification.
OS_SIGNATURES: list[tuple[str, set[int], str]] = [
    ("Windows", {135, 139, 445}, "high"),
    ("Windows", {3389, 445}, "high"),
    ("Windows", {5985}, "medium"),
    ("Windows", {135}, "low"),
    ("Linux/Unix", {22}, "low"),
    ("Network device / printer", {9100, 515}, "medium"),
    ("Network device", {161, 23}, "low"),
]

ProgressHook = Callable[[int, int, str], None]


@dataclass
class DiscoveredPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    banner: str = ""
    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service or service_for(self.port, self.protocol),
            "service_source": "well-known-port" if not self.banner else "banner",
            "banner": self.banner,
            "latency_ms": self.latency_ms,
            "high_risk_service": HIGH_RISK_PORTS.get(self.port, ("", ""))[0],
        }


@dataclass
class DiscoveredHost:
    ip_address: str
    is_up: bool = True
    discovery_method: str = ""
    latency_ms: float | None = None
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    ports: list[DiscoveredPort] = field(default_factory=list)
    os_guess: str = ""
    os_confidence: str = "unknown"
    os_evidence: list[str] = field(default_factory=list)
    is_gateway: bool = False
    is_local: bool = False

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "is_up": self.is_up,
            "discovery_method": self.discovery_method,
            "latency_ms": self.latency_ms,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "ports": [p.to_dict() for p in self.ports],
            "open_port_count": len(self.ports),
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "os_evidence": self.os_evidence,
            "is_gateway": self.is_gateway,
            "is_local": self.is_local,
        }


def expand_scope(scope: str, max_hosts: int = 4096) -> list[str]:
    """Expand a CIDR or single address into a host list."""
    network = ipaddress.ip_network(scope, strict=False)
    if network.num_addresses > max_hosts:
        raise ValueError(
            f"Scope {scope} contains {network.num_addresses} addresses, above the "
            f"{max_hosts} host safety limit. Scan a smaller range."
        )
    if network.num_addresses <= 2:
        return [str(network.network_address)]
    return [str(host) for host in network.hosts()]


def tcp_probe(
    address: str, port: int, timeout: float
) -> tuple[bool, float | None]:
    """Full TCP connect probe. Returns ``(open, latency_ms)``."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    started = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        return True, (time.perf_counter() - started) * 1000
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None
    finally:
        sock.close()


def grab_banner(address: str, port: int, timeout: float) -> str:
    """Read whatever a service volunteers on connect. Never sends an exploit."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        if port in (80, 8080, 8000, 8008, 8081, 3000, 9090, 10000):
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: VulScanner\r\n\r\n"
                % address.encode("ascii", "ignore")
            )
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip()[:200]
    except OSError:
        return ""
    finally:
        sock.close()


def reverse_dns(address: str, timeout: float = 1.5) -> str:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror):
        return ""
    finally:
        socket.setdefaulttimeout(None)


def guess_os(open_ports: Iterable[int]) -> tuple[str, str, list[str]]:
    """Infer an OS family from the open-port mix, with explicit confidence."""
    ports = set(open_ports)
    if not ports:
        return "", "unknown", ["No open ports were observed."]
    for name, signature, confidence in OS_SIGNATURES:
        if signature.issubset(ports):
            evidence = [
                f"Open ports {sorted(signature)} are characteristic of {name}."
            ]
            return name, confidence, evidence
    return "", "unknown", [f"Open ports {sorted(ports)} match no known signature."]


class NetworkDiscovery:
    """Discovers live hosts and their exposed services on an authorized scope."""

    def __init__(
        self,
        profile: str = "safe",
        ports: Sequence[int] | None = None,
        timeout: float | None = None,
        concurrency: int | None = None,
        banner_grab: bool = False,
        resolve_names: bool = True,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        self.profile = profile
        self.ports = tuple(ports) if ports else DISCOVERY_PROFILES.get(
            profile, SAFE_PORTS
        )
        self.timeout = timeout or settings.portscan_timeout
        self.concurrency = concurrency or settings.discovery_concurrency
        self.banner_grab = banner_grab
        self.resolve_names = resolve_names
        self.cancel_check = cancel_check or (lambda: False)

    # -- liveness ----------------------------------------------------------
    def _probe_host(self, address: str) -> DiscoveredHost | None:
        for port in LIVENESS_PORTS:
            if self.cancel_check():
                return None
            is_open, latency = tcp_probe(address, port, self.timeout)
            if is_open:
                return DiscoveredHost(
                    ip_address=address,
                    discovery_method=f"tcp-connect:{port}",
                    latency_ms=round(latency, 2) if latency else None,
                )
        return None

    def discover(
        self, hosts: Sequence[str], progress: ProgressHook | None = None
    ) -> list[DiscoveredHost]:
        """Find responsive hosts within ``hosts``."""
        found: list[DiscoveredHost] = []
        completed = 0
        total = len(hosts)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.concurrency, max(1, total))
        ) as pool:
            futures = {pool.submit(self._probe_host, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if self.cancel_check():
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    host = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("Host probe failed for %s: %s", futures[future], exc)
                    continue
                if host:
                    found.append(host)
                if progress and completed % 16 == 0:
                    progress(completed, total, f"{len(found)} hosts responding")

        if progress:
            progress(total, total, f"{len(found)} hosts responding")
        found.sort(key=lambda h: ipaddress.ip_address(h.ip_address))
        return found

    # -- service sweep -----------------------------------------------------
    def scan_ports(
        self, host: DiscoveredHost, ports: Sequence[int] | None = None
    ) -> DiscoveredHost:
        targets = tuple(ports) if ports else self.ports
        open_ports: list[DiscoveredPort] = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(settings.portscan_concurrency, max(1, len(targets)))
        ) as pool:
            futures = {
                pool.submit(tcp_probe, host.ip_address, port, self.timeout): port
                for port in targets
            }
            for future in concurrent.futures.as_completed(futures):
                if self.cancel_check():
                    break
                port = futures[future]
                try:
                    is_open, latency = future.result()
                except Exception:  # pragma: no cover - defensive
                    continue
                if is_open:
                    open_ports.append(
                        DiscoveredPort(
                            port=port,
                            service=service_for(port),
                            latency_ms=round(latency, 2) if latency else None,
                        )
                    )

        open_ports.sort(key=lambda p: p.port)
        if self.banner_grab:
            for entry in open_ports:
                if self.cancel_check():
                    break
                entry.banner = grab_banner(host.ip_address, entry.port, self.timeout)

        host.ports = open_ports
        host.os_guess, host.os_confidence, host.os_evidence = guess_os(
            p.port for p in open_ports
        )
        if self.resolve_names and not host.hostname:
            host.hostname = reverse_dns(host.ip_address)
        return host

    def scan_all(
        self, hosts: Sequence[DiscoveredHost], progress: ProgressHook | None = None
    ) -> list[DiscoveredHost]:
        total = len(hosts)
        for index, host in enumerate(hosts, start=1):
            if self.cancel_check():
                break
            self.scan_ports(host)
            if progress:
                progress(index, total, f"{host.ip_address}: {len(host.ports)} open")
        return list(hosts)

    # -- enrichment --------------------------------------------------------
    @staticmethod
    def enrich(
        hosts: Sequence[DiscoveredHost],
        arp_entries: Sequence[dict] | None = None,
        gateways: Sequence[str] | None = None,
        local_addresses: Sequence[str] | None = None,
    ) -> list[DiscoveredHost]:
        """Attach MAC, vendor, gateway and local-host attribution."""
        arp_by_ip = {
            entry.get("ip_address"): entry for entry in (arp_entries or []) if entry
        }
        gateway_set = set(gateways or [])
        local_set = set(local_addresses or [])

        for host in hosts:
            arp = arp_by_ip.get(host.ip_address)
            if arp:
                host.mac_address = arp.get("mac_address", "") or ""
                host.vendor = arp.get("vendor") or lookup_vendor(host.mac_address)[0]
            host.is_gateway = host.ip_address in gateway_set
            host.is_local = host.ip_address in local_set
            if host.is_local and not host.os_guess:
                host.os_guess, host.os_confidence = "Windows", "high"
                host.os_evidence = ["Host is the machine running VulScanner."]
        return list(hosts)


def summarize(hosts: Sequence[DiscoveredHost]) -> dict:
    """Roll discovery output up into report-friendly counters."""
    all_ports = [port for host in hosts for port in host.ports]
    service_counts: dict[str, int] = {}
    for port in all_ports:
        service = port.service or service_for(port.port)
        service_counts[service or f"port-{port.port}"] = (
            service_counts.get(service or f"port-{port.port}", 0) + 1
        )

    return {
        "host_count": len(hosts),
        "hosts_with_open_ports": sum(1 for h in hosts if h.ports),
        "total_open_ports": len(all_ports),
        "unique_ports": sorted({p.port for p in all_ports}),
        "service_distribution": dict(
            sorted(service_counts.items(), key=lambda kv: -kv[1])
        ),
        "high_risk_exposures": [
            {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "port": port.port,
                "service": HIGH_RISK_PORTS[port.port][0],
                "rationale": HIGH_RISK_PORTS[port.port][1],
            }
            for host in hosts
            for port in host.ports
            if port.port in HIGH_RISK_PORTS
        ],
        "os_distribution": {
            guess: sum(1 for h in hosts if (h.os_guess or "Unknown") == guess)
            for guess in sorted({h.os_guess or "Unknown" for h in hosts})
        },
        "vendors": sorted({h.vendor for h in hosts if h.vendor}),
        "exposure_classification": {
            host.ip_address: classify_exposure(host.ip_address) for host in hosts
        },
    }
