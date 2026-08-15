"""Collector registry and scan-profile definitions."""

from __future__ import annotations

from typing import Type

from app.scanner.base import BaseCollector
from app.scanner.network.adapters import AdaptersCollector
from app.scanner.network.arp import ArpCollector
from app.scanner.network.cdp import CDPCollector
from app.scanner.network.connections import ConnectionsCollector
from app.scanner.network.dns import DNSCollector
from app.scanner.network.lldp import LLDPCollector
from app.scanner.network.ports import PortsCollector
from app.scanner.network.profiles import ProfilesCollector
from app.scanner.network.rpc import RPCCollector
from app.scanner.network.shares import SharesCollector
from app.scanner.windows.amsi import AmsiCollector
from app.scanner.windows.antivirus import AntivirusCollector
from app.scanner.windows.audit_policy import AuditPolicyCollector
from app.scanner.windows.autoruns import AutorunsCollector
from app.scanner.windows.certificates import CertificatesCollector
from app.scanner.windows.defender import DefenderCollector
from app.scanner.windows.dotnet import DotNetCollector
from app.scanner.windows.environment import EnvironmentCollector
from app.scanner.windows.filesystem import FilesystemCollector
from app.scanner.windows.firewall import FirewallCollector
from app.scanner.windows.group_policy import GroupPolicyCollector
from app.scanner.windows.hotfixes import HotfixesCollector
from app.scanner.windows.local_groups import LocalGroupsCollector
from app.scanner.windows.local_users import LocalUsersCollector
from app.scanner.windows.ntlm import NTLMCollector
from app.scanner.windows.os import OSCollector
from app.scanner.windows.powershell import PowerShellCollector
from app.scanner.windows.powershell_history import PowerShellHistoryCollector
from app.scanner.windows.rdp import RDPCollector
from app.scanner.windows.secure_boot import SecureBootCollector
from app.scanner.windows.software import SoftwareCollector
from app.scanner.windows.sysmon import SysmonCollector
from app.scanner.windows.uac import UACCollector
from app.scanner.windows.updates import UpdatesCollector

# Registration order is also execution order: cheap, foundational collectors
# first so the UI shows meaningful data early.
COLLECTORS: list[Type[BaseCollector]] = [
    OSCollector,
    HotfixesCollector,
    SoftwareCollector,
    AntivirusCollector,
    DefenderCollector,
    AmsiCollector,
    FirewallCollector,
    UACCollector,
    LocalUsersCollector,
    LocalGroupsCollector,
    RDPCollector,
    NTLMCollector,
    SecureBootCollector,
    AuditPolicyCollector,
    GroupPolicyCollector,
    PowerShellCollector,
    DotNetCollector,
    SysmonCollector,
    AutorunsCollector,
    CertificatesCollector,
    UpdatesCollector,
    EnvironmentCollector,
    PowerShellHistoryCollector,
    FilesystemCollector,
    # Network-side collectors run against the same host.
    AdaptersCollector,
    ProfilesCollector,
    PortsCollector,
    ConnectionsCollector,
    SharesCollector,
    ArpCollector,
    DNSCollector,
    RPCCollector,
    LLDPCollector,
    CDPCollector,
]

COLLECTORS_BY_NAME: dict[str, Type[BaseCollector]] = {
    collector.name: collector for collector in COLLECTORS
}


PROFILE_DESCRIPTIONS: dict[str, str] = {
    "quick": (
        "Fast posture check: OS, patches, software, antivirus/Defender, firewall, "
        "UAC, accounts, RDP, adapters, ports and shares."
    ),
    "standard": (
        "Full Windows security audit without deep filesystem or update-agent "
        "queries. The default profile."
    ),
    "full": (
        "Everything: adds the Windows Update agent query, filesystem metadata "
        "audit, PowerShell history analysis and LLDP/CDP collection."
    ),
    "network": (
        "Network discovery and service assessment across an authorized scope. "
        "Windows collectors are skipped."
    ),
    "compliance": (
        "Configuration and policy focused: audit policy, group policy, "
        "authentication hardening, boot integrity and logging."
    ),
    "custom": "Operator-selected collectors.",
}


def collectors_for_profile(
    profile: str, include: list[str] | None = None, exclude: list[str] | None = None
) -> list[Type[BaseCollector]]:
    """Resolve the collector set for a profile with optional overrides."""
    if profile == "custom" and include:
        selected = [
            COLLECTORS_BY_NAME[name] for name in include if name in COLLECTORS_BY_NAME
        ]
    else:
        selected = [c for c in COLLECTORS if profile in c.profiles]
        if include:
            for name in include:
                collector = COLLECTORS_BY_NAME.get(name)
                if collector and collector not in selected:
                    selected.append(collector)

    if exclude:
        excluded = set(exclude)
        selected = [c for c in selected if c.name not in excluded]
    return selected


def unknown_collector_names(names: list[str] | None) -> list[str]:
    return [name for name in (names or []) if name not in COLLECTORS_BY_NAME]


def describe_collectors() -> list[dict]:
    return [
        {
            "name": collector.name,
            "category": collector.category,
            "description": collector.description,
            "requires_admin": collector.requires_admin,
            "profiles": list(collector.profiles),
        }
        for collector in COLLECTORS
    ]
