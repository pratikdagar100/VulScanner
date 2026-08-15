"""Network exposure detection rules."""

from __future__ import annotations

from typing import Iterator

from app.models.finding import Confidence, FindingCategory, Severity
from app.scanner.network.services import HIGH_RISK_PORTS
from app.services.analyzers.base import AnalysisContext, FindingDraft, analyzer
from app.services.risk_engine import ExposureLevel, exposure_from_binding


@analyzer("listening_ports")
def analyze_listening_ports(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    ports = ctx.data("ports")
    if not ports:
        return

    firewall = ctx.data("firewall")
    firewall_off = bool(firewall.get("disabled_profiles"))

    for port in ports.get("high_risk_ports") or []:
        number = port.get("local_port")
        entry = HIGH_RISK_PORTS.get(number)
        if not entry:
            continue
        service_name, rationale = entry
        exposure = exposure_from_binding(port.get("exposure", ""))
        severity = (
            Severity.HIGH
            if exposure in (ExposureLevel.INTERNET, ExposureLevel.NETWORK)
            else Severity.MEDIUM
        )
        yield FindingDraft(
            rule_id="NET-001",
            instance_key=f"{port.get('protocol')}/{number}",
            title=f"{service_name} is listening on {port.get('protocol')}/{number}",
            category=FindingCategory.EXPOSURE,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{service_name} is bound to {port.get('local_address')} "
                f"({port.get('exposure')} scope)"
                + (
                    f", served by {port.get('process_name')}"
                    if port.get("process_name")
                    else ""
                )
                + f". {rationale}"
                + (
                    " The host firewall is disabled, so this port is not filtered."
                    if firewall_off
                    else ""
                )
            ),
            impact=(
                "Any host that can route to this address can attempt to connect to "
                "this service, and any vulnerability in it is remotely reachable."
            ),
            remediation=(
                f"Confirm {service_name} needs to be reachable from the network. If "
                "not, bind it to 127.0.0.1 or stop the service. If it does, restrict "
                "access with a firewall rule scoped to the specific source addresses "
                "that require it."
            ),
            remediation_command=(
                f"Get-NetTCPConnection -LocalPort {number} -State Listen | "
                "Select-Object LocalAddress,OwningProcess"
            ),
            evidence={
                "port": number,
                "protocol": port.get("protocol"),
                "local_address": port.get("local_address"),
                "exposure": port.get("exposure"),
                "process_name": port.get("process_name"),
                "process_path": port.get("process_path"),
                "process_id": port.get("process_id"),
                "owning_services": port.get("services"),
                "firewall_disabled": firewall_off,
            },
            evidence_summary=(
                f"{port.get('protocol')}/{number} bound to "
                f"{port.get('local_address')} by {port.get('process_name') or 'unknown process'}"
            ),
            detection_method="Get-NetTCPConnection / Get-NetUDPEndpoint with process attribution",
            exposure=exposure,
            service_exposed=True,
            source_collector="ports",
        )

    public = ports.get("publicly_bound_ports") or []
    if public:
        yield FindingDraft(
            rule_id="NET-002",
            title=f"{len(public)} services are bound to a publicly routable address",
            category=FindingCategory.EXPOSURE,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "The following services are listening on an address that is not in "
                "a private range: "
                + ", ".join(
                    f"{p['protocol']}/{p['local_port']} ({p.get('process_name') or 'unknown'})"
                    for p in public[:10]
                )
            ),
            impact=(
                "These services may be reachable directly from the internet rather "
                "than only from the local network."
            ),
            remediation=(
                "Verify whether the address is genuinely internet-facing. Restrict "
                "each service to the interfaces it must serve and filter inbound "
                "access at the network edge."
            ),
            evidence={"ports": public},
            evidence_summary=f"{len(public)} listeners on public addresses.",
            detection_method="Listening socket address classification",
            exposure=ExposureLevel.INTERNET,
            service_exposed=True,
            source_collector="ports",
        )


@analyzer("shares")
def analyze_shares(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    shares = ctx.data("shares")
    if not shares:
        return

    for share in shares.get("world_accessible_shares") or []:
        principals = ", ".join(
            f"{a['account']} ({a['right']})" for a in share.get("broad_access", [])
        )
        yield FindingDraft(
            rule_id="SHARE-001",
            instance_key=share.get("name", ""),
            title=f"SMB share '{share.get('name')}' is accessible to everyone",
            category=FindingCategory.SHARES,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                f"The share '{share.get('name')}' ({share.get('path')}) grants access "
                f"to broad principals: {principals}."
            ),
            impact=(
                "Any authenticated user - and in some configurations any user who "
                "can reach the host - can read, and possibly modify, the contents of "
                "this share."
            ),
            remediation=(
                "Replace the broad grant with permissions for the specific groups "
                "that need access, and confirm the underlying NTFS permissions are "
                "equally restrictive."
            ),
            remediation_command=(
                f"Get-SmbShareAccess -Name '{share.get('name')}'"
            ),
            evidence=share,
            evidence_summary=f"Share access granted to: {principals}",
            detection_method="Get-SmbShare and Get-SmbShareAccess",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="shares",
        )

    config = shares.get("server_configuration") or {}
    if config.get("smb1_enabled"):
        yield FindingDraft(
            rule_id="SHARE-002",
            title="The SMB server has SMBv1 enabled",
            category=FindingCategory.NETWORK,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "Get-SmbServerConfiguration reports EnableSMB1Protocol = true."
            ),
            impact=(
                "SMBv1 has no pre-authentication integrity and is the transport "
                "targeted by EternalBlue-class exploits."
            ),
            remediation="Disable SMBv1 on the server.",
            remediation_command="Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            evidence=config,
            evidence_summary="EnableSMB1Protocol = true",
            detection_method="Get-SmbServerConfiguration",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="shares",
        )


@analyzer("network_profile")
def analyze_network_profile(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    profiles = ctx.data("profiles")
    if not profiles:
        return

    firewall = ctx.data("firewall")
    public_networks = profiles.get("public_networks") or []
    private_networks = profiles.get("private_networks") or []
    sharing = profiles.get("file_and_printer_sharing") or {}
    discovery = profiles.get("network_discovery") or {}

    if public_networks and sharing.get("enabled"):
        # Only material if the Public profile is the one currently active.
        yield FindingDraft(
            rule_id="NETP-001",
            title="File and printer sharing is enabled while connected to a public network",
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                "The host is connected to a network categorised as Public "
                f"({', '.join(p['name'] for p in public_networks)}) and File and "
                "Printer Sharing firewall rules are enabled."
            ),
            impact=(
                "SMB services may be reachable by other devices on an untrusted "
                "network such as a public Wi-Fi hotspot."
            ),
            remediation=(
                "Disable File and Printer Sharing for the Public profile, and keep "
                "untrusted networks categorised as Public."
            ),
            remediation_command=(
                "Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' "
                "-Profile Public -Enabled False"
            ),
            evidence={
                "public_networks": public_networks,
                "file_sharing": sharing,
                "firewall_profiles": firewall.get("profiles", []),
            },
            evidence_summary=(
                f"{sharing.get('enabled_rules')} sharing rules enabled with a Public "
                "network profile active."
            ),
            detection_method="Get-NetConnectionProfile and firewall rule groups",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="profiles",
        )

    if private_networks and discovery.get("enabled"):
        internet_facing = [p for p in private_networks if p.get("internet_connected")]
        if internet_facing:
            yield FindingDraft(
                rule_id="NETP-002",
                title="Network discovery is enabled on an internet-connected private network",
                category=FindingCategory.NETWORK,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    "Network discovery advertises this host to other devices on "
                    f"{', '.join(p['name'] for p in internet_facing)}."
                ),
                impact=(
                    "The host is discoverable by other devices sharing the network, "
                    "which aids reconnaissance if the network is not fully trusted."
                ),
                remediation=(
                    "Disable network discovery on networks that are not fully "
                    "trusted, or categorise them as Public."
                ),
                evidence={"networks": internet_facing, "discovery": discovery},
                evidence_summary="Network Discovery rules enabled on a private profile.",
                detection_method="Get-NetConnectionProfile and Network Discovery rule group",
                configuration_weakness=False,
                source_collector="profiles",
            )


@analyzer("rpc_exposure")
def analyze_rpc(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    rpc = ctx.data("rpc")
    if not rpc:
        return

    services = rpc.get("running_remote_management_services") or []
    remote_registry = next(
        (s for s in services if s["name"] == "RemoteRegistry"), None
    )
    if remote_registry:
        yield FindingDraft(
            rule_id="RPC-001",
            title="The Remote Registry service is running",
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                "RemoteRegistry is running, allowing authorized remote users to read "
                "and modify the registry over the network."
            ),
            impact=(
                "Remote registry access is widely used for reconnaissance and for "
                "reading configuration that assists lateral movement."
            ),
            remediation=(
                "Stop and disable the Remote Registry service unless a management "
                "tool specifically requires it."
            ),
            remediation_command=(
                "Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled"
            ),
            evidence={"service": remote_registry},
            evidence_summary="RemoteRegistry service state = Running",
            detection_method="Get-Service RemoteRegistry",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="rpc",
        )

    spooler = next((s for s in services if s["name"] == "Spooler"), None)
    if spooler:
        yield FindingDraft(
            rule_id="RPC-002",
            title="The Print Spooler service is running",
            category=FindingCategory.NETWORK,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description=(
                "The Print Spooler service is running. It has a long history of "
                "remote code execution and privilege escalation vulnerabilities "
                "(the PrintNightmare family)."
            ),
            impact=(
                "If the host does not need to print or share printers, the spooler "
                "is unnecessary attack surface reachable over RPC."
            ),
            remediation=(
                "Disable the Print Spooler on machines that do not print, and apply "
                "the Point and Print restriction policies where it is required."
            ),
            remediation_command=(
                "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled"
            ),
            evidence={"service": spooler},
            evidence_summary="Spooler service state = Running",
            detection_method="Get-Service Spooler",
            exposure=ExposureLevel.NETWORK,
            configuration_weakness=False,
            source_collector="rpc",
        )


# Services that carry credentials or management access in the clear, or that
# should not normally be reachable on a general-purpose network.
PLAINTEXT_SERVICES = {
    21: ("FTP", "Credentials and file contents traverse the network unencrypted."),
    23: ("Telnet", "Credentials and the entire session traverse the network unencrypted."),
    80: ("HTTP", "Any credentials submitted to this service are sent unencrypted."),
    143: ("IMAP", "Mail credentials are sent unencrypted unless STARTTLS is enforced."),
    110: ("POP3", "Mail credentials are sent unencrypted unless STARTTLS is enforced."),
    161: ("SNMP", "Community strings are sent unencrypted in SNMPv1/v2c."),
    389: ("LDAP", "Directory queries and binds are unencrypted unless StartTLS is used."),
    5900: ("VNC", "Remote control traffic is frequently unencrypted."),
}


@analyzer("unauthenticated_host")
def analyze_unauthenticated_host(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    """Findings for a single host assessed without credentials.

    Without authentication the exposed service surface is the only evidence
    available, so it is reported explicitly rather than leaving the scan empty.
    """
    discovery = ctx.discovery
    if not discovery or ctx.assessment_mode != "remote-unauthenticated":
        return

    hosts = discovery.get("hosts") or []
    if not hosts:
        # The host did not answer on any probed port. That is a result worth
        # recording - it is not the same as "nothing was assessed".
        yield FindingDraft(
            rule_id="UNAUTH-000",
            title=f"Host {discovery.get('scope')} did not respond on any probed port",
            category=FindingCategory.SYSTEM,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.CONFIRMED,
            description=(
                f"No TCP connect probe to {discovery.get('scope')} completed across "
                f"{len(discovery.get('ports_probed') or [])} probed ports. The host "
                "may be offline, firewalled, or exposing only services outside the "
                "probed set."
            ),
            impact=(
                "No conclusion can be drawn about this host's security posture from "
                "an unanswered probe."
            ),
            remediation=(
                "If the host should have been reachable, confirm it is online and "
                "that no firewall between it and the scanner is dropping traffic. "
                "Supply WinRM credentials for an authenticated assessment."
            ),
            evidence={
                "scope": discovery.get("scope"),
                "ports_probed": discovery.get("ports_probed"),
                "method": discovery.get("method"),
            },
            evidence_summary="No probed TCP port accepted a connection.",
            detection_method="TCP connect probe",
            configuration_weakness=False,
            source_collector="discovery",
        )
        return

    host = hosts[0]
    ports = host.get("ports") or []
    address = host.get("ip_address", "")

    # An inventory of what the host exposes, so the assessment is never empty.
    if ports:
        listing = ", ".join(
            f"{p.get('port')}/{p.get('service') or 'unknown'}" for p in ports
        )
        yield FindingDraft(
            rule_id="UNAUTH-001",
            instance_key=address,
            title=f"{len(ports)} service(s) exposed on {host.get('hostname') or address}",
            category=FindingCategory.EXPOSURE,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description=(
                f"An unauthenticated assessment of {address} completed TCP "
                f"connect handshakes to: {listing}."
                + (
                    f" The service mix suggests {host.get('os_guess')} "
                    f"({host.get('os_confidence')} confidence)."
                    if host.get("os_guess")
                    else ""
                )
            ),
            impact=(
                "Each reachable service is attack surface. Without credentials "
                "VulScanner cannot assess the configuration or patch level behind "
                "these services, so this is an outside view only."
            ),
            remediation=(
                "Confirm every exposed service is required on this interface. "
                "Restrict the rest at the host or network firewall, and supply "
                "credentials for an authenticated assessment of what remains."
            ),
            evidence={
                "ip_address": address,
                "hostname": host.get("hostname"),
                "mac_address": host.get("mac_address"),
                "vendor": host.get("vendor"),
                "ports": ports,
                "os_guess": host.get("os_guess"),
                "os_confidence": host.get("os_confidence"),
                "os_evidence": host.get("os_evidence"),
                "discovery_method": host.get("discovery_method"),
                "assessment": "unauthenticated - no credentials supplied",
            },
            evidence_summary=f"Open TCP ports: {listing}",
            detection_method="TCP connect probe with banner reading",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            configuration_weakness=False,
            source_collector="discovery",
        )

    # Cleartext or management services reachable over the network.
    for port in ports:
        number = port.get("port")
        entry = PLAINTEXT_SERVICES.get(number)
        if not entry:
            continue
        name, rationale = entry
        banner = (port.get("banner") or "").strip()
        yield FindingDraft(
            rule_id="UNAUTH-002",
            instance_key=f"{address}:{number}",
            title=f"{name} reachable without transport encryption on {address}",
            category=FindingCategory.EXPOSURE,
            severity=Severity.HIGH if number in (21, 23, 5900) else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{name} answered on {address}:{number}. {rationale}"
                + (f" Service banner: {banner[:160]}" if banner else "")
            ),
            impact=(
                "Anyone able to observe traffic between a client and this service "
                "can read the session, including any credentials it carries."
            ),
            remediation=(
                f"Move {name} to its encrypted equivalent (for example HTTPS, SFTP "
                "or SSH), or restrict it to a management network. If this is a "
                "network appliance, enable HTTPS for its administration interface."
            ),
            evidence={
                "ip_address": address,
                "port": number,
                "service": port.get("service"),
                "banner": banner or None,
                "assessment": "unauthenticated",
            },
            evidence_summary=f"{name} answered on {address}:{number}",
            detection_method="TCP connect probe with banner reading",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="discovery",
        )


@analyzer("discovery_exposure")
def analyze_discovery(ctx: AnalysisContext) -> Iterator[FindingDraft]:
    """Findings raised from network discovery of other hosts."""
    discovery = ctx.discovery
    if not discovery:
        return

    summary = discovery.get("summary") or {}
    exposures = summary.get("high_risk_exposures") or []

    # Group by service so the report does not list one finding per host.
    grouped: dict[str, list[dict]] = {}
    for exposure in exposures:
        grouped.setdefault(exposure["service"], []).append(exposure)

    for service, entries in grouped.items():
        hosts = sorted({e["ip_address"] for e in entries})
        port = entries[0]["port"]
        yield FindingDraft(
            rule_id="DISC-001",
            instance_key=f"{service}:{port}",
            title=f"{service} exposed on {len(hosts)} host(s) in the assessed network",
            category=FindingCategory.EXPOSURE,
            severity=Severity.HIGH if len(hosts) > 1 else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"A TCP connect probe completed successfully to port {port} "
                f"({service}) on: {', '.join(hosts[:15])}"
                + ("..." if len(hosts) > 15 else "")
                + f". {entries[0]['rationale']}"
            ),
            impact=(
                "Every host exposing this service enlarges the network's attack "
                "surface and provides a lateral-movement path between machines."
            ),
            remediation=(
                f"Confirm each host needs to expose {service} to the whole network. "
                "Segment the service behind a firewall or VLAN, and restrict it to "
                "the systems that must reach it."
            ),
            evidence={
                "service": service,
                "port": port,
                "hosts": [
                    {"ip_address": e["ip_address"], "hostname": e.get("hostname", "")}
                    for e in entries
                ],
                "scope": discovery.get("scope"),
                "method": discovery.get("method"),
            },
            evidence_summary=f"Port {port} open on {len(hosts)} host(s) in {discovery.get('scope')}.",
            detection_method="TCP connect probe during authorized network discovery",
            exposure=ExposureLevel.NETWORK,
            service_exposed=True,
            source_collector="discovery",
        )
