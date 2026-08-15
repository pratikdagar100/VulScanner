"""Mock collector data for tests and demonstrations.

IMPORTANT
---------
This module exists so VulScanner can be exercised and demonstrated without an
actually vulnerable machine. It is imported **only by the test suite**. The
application never loads it, and no scan result shown to an operator is ever
sourced from here.

The values are deliberately synthetic (RFC 5737 documentation addresses, a
fictional hostname) so they can never be mistaken for a real assessment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

MOCK_MARKER = "MOCK-DATA-NOT-A-REAL-ASSESSMENT"

# RFC 5737 TEST-NET-1, reserved for documentation.
MOCK_IP = "192.0.2.10"
MOCK_GATEWAY = "192.0.2.1"
MOCK_HOSTNAME = "EXAMPLE-WORKSTATION"


OS_DATA: dict[str, Any] = {
    "hostname": MOCK_HOSTNAME,
    "os_name": "Microsoft Windows 11 Pro",
    "product_name": "Windows 11 Pro",
    "edition": "Professional",
    "version": "10.0.22621",
    "display_version": "22H2",
    "build": 22621,
    "ubr": 3007,
    "full_build": "22621.3007",
    "architecture": "64-bit",
    "domain": "WORKGROUP",
    "part_of_domain": False,
    "manufacturer": "Example Corp",
    "model": "Example Model",
    "uptime_days": 12.4,
    "supported_build": True,
    # 22621 is past its servicing date, which the patch rule should detect.
    "end_of_servicing": "2024-06-11",
    "virtual_machine": False,
    "bios": {"manufacturer": "Example", "version": "1.0", "smbios_version": "3.4"},
    "_source": MOCK_MARKER,
}

DEFENDER_DATA: dict[str, Any] = {
    "installed": True,
    "service_enabled": True,
    "antivirus_enabled": True,
    "real_time_protection": False,          # -> DEF-001
    "tamper_protection": False,             # -> DEF-002
    "signatures": {
        "antivirus_version": "1.403.1.0",
        "last_updated": "2026-01-02T10:00:00+00:00",
        "out_of_date": True,                # -> DEF-004
    },
    "scans": {"quick_scan_age_days": 3, "full_scan_age_days": 40},
    "cloud_protection": {"maps_reporting": "Disabled", "maps_raw": 0},  # -> DEF-005
    "features": {
        "controlled_folder_access": "Disabled",
        "script_scanning_disabled": False,
    },
    "exclusions": {
        "paths": ["C:\\", "C:\\Users\\Public\\legit"],
        "extensions": [],
        "processes": [],
        "ip_addresses": [],
    },
    "exclusion_count": 2,
    "broad_exclusions": ["C:\\"],           # -> DEF-003
    "asr_rules": [],
    "_source": MOCK_MARKER,
}

FIREWALL_DATA: dict[str, Any] = {
    "profiles": [
        {"name": "Domain", "enabled": True, "log_blocked": True},
        {"name": "Private", "enabled": True, "log_blocked": False},
        {"name": "Public", "enabled": False, "log_blocked": False},  # -> FW-001
    ],
    "disabled_profiles": ["Public"],
    "all_profiles_enabled": False,
    "rules": [],
    "rule_count": 1,
    "risky_rules": [                                                  # -> FW-002
        {
            "name": "AllowRDPAnywhere",
            "display_name": "Allow RDP from anywhere",
            "direction": "Inbound",
            "action": "Allow",
            "protocol": "TCP",
            "local_ports": ["3389"],
            "remote_addresses": ["Any"],
            "profiles": ["Public", "Private"],
            "program": "",
            "service": "",
            "risk_reason": "Allows inbound traffic from any remote address to 3389 (Remote Desktop).",
        }
    ],
    "risky_rule_count": 1,
    "_source": MOCK_MARKER,
}

RDP_DATA: dict[str, Any] = {
    "enabled": True,
    "deny_connections_raw": 0,
    "port": 3389,
    "nla_enabled": False,                   # -> RDP-001
    "security_layer": "RDP Security Layer (legacy)",
    "security_layer_raw": 0,                # -> RDP-003
    "firewall_allows_inbound": True,
    "firewall_profiles_allowing": ["Public"],
    "listening_endpoints": [{"address": "0.0.0.0", "port": 3389}],
    "listening_on_all_interfaces": True,
    "network_exposed": True,                # -> RDP-002
    "sessions": [],
    "saved_destinations": [],
    "_source": MOCK_MARKER,
}

USERS_DATA: dict[str, Any] = {
    "users": [
        {
            "name": "Guest",
            "enabled": True,
            "sid": "S-1-5-21-1111111111-2222222222-3333333333-501",
            "builtin_role": "Guest",
            "password_required": True,
            "password_never_expires": True,
        },
        {
            "name": "svc_backup",
            "enabled": True,
            "sid": "S-1-5-21-1111111111-2222222222-3333333333-1004",
            "builtin_role": "",
            "password_required": False,
            "password_never_expires": True,
        },
    ],
    "user_count": 2,
    "enabled_count": 2,
    "guest_enabled": True,                                  # -> ACC-001
    "accounts_without_password_required": ["svc_backup"],   # -> ACC-002
    "accounts_password_never_expires": ["Guest", "svc_backup"],
    "password_policy": {
        "min_password_length": 6,                           # -> ACC-003
        "lockout_threshold": 0,                             # -> ACC-004
        "max_password_age_days": 42,
    },
    "auto_logon": {
        "enabled": True,
        "default_username": "kiosk",
        "stored_password_present": True,                    # -> ACC-005
    },
    "_source": MOCK_MARKER,
}

GROUPS_DATA: dict[str, Any] = {
    "groups": [],
    "group_count": 3,
    "administrators": {
        "members": [
            {"name": "EXAMPLE\\Administrator", "sid": "S-1-5-21-1-2-3-500", "object_class": "User"},
            {"name": "EXAMPLE\\alice", "sid": "S-1-5-21-1-2-3-1001", "object_class": "User"},
            {"name": "EXAMPLE\\bob", "sid": "S-1-5-21-1-2-3-1002", "object_class": "User"},
        ],
        "member_count": 3,
        "unexpected_members": [
            {"name": "EXAMPLE\\alice", "sid": "S-1-5-21-1-2-3-1001", "object_class": "User"},
            {"name": "EXAMPLE\\bob", "sid": "S-1-5-21-1-2-3-1002", "object_class": "User"},
        ],
        "unexpected_count": 2,                              # -> ACC-006
    },
    "_source": MOCK_MARKER,
}

PORTS_DATA: dict[str, Any] = {
    "ports": [
        {
            "protocol": "tcp", "local_address": "0.0.0.0", "local_port": 445,
            "state": "Listen", "process_id": 4, "process_name": "System",
            "process_path": "", "services": [], "service": "microsoft-ds",
            "service_source": "well-known-port", "exposure": "all-interfaces",
            "risk_score": 70.0, "risk_rationale": "SMB reachable on all interfaces.",
            "high_risk_service": "SMB",
        },
        {
            "protocol": "tcp", "local_address": "127.0.0.1", "local_port": 5432,
            "state": "Listen", "process_id": 900, "process_name": "postgres.exe",
            "process_path": "", "services": [], "service": "postgresql",
            "service_source": "well-known-port", "exposure": "loopback",
            "risk_score": 0.0, "risk_rationale": "Bound to loopback only.",
            "high_risk_service": "",
        },
    ],
    "port_count": 2,
    "network_reachable_ports": [],
    "network_reachable_count": 1,
    "high_risk_ports": [],
    "publicly_bound_ports": [],
    "_source": MOCK_MARKER,
}
PORTS_DATA["network_reachable_ports"] = [PORTS_DATA["ports"][0]]
PORTS_DATA["high_risk_ports"] = [PORTS_DATA["ports"][0]]      # -> NET-001

SHARES_DATA: dict[str, Any] = {
    "shares": [],
    "share_count": 2,
    "user_shares": [],
    "world_accessible_shares": [                              # -> SHARE-001
        {
            "name": "Public",
            "path": "C:\\Shared",
            "administrative": False,
            "encrypt_data": False,
            "access": [{"account": "Everyone", "right": "Full", "type": "Allow"}],
            "broad_access": [{"account": "Everyone", "right": "Full", "type": "Allow"}],
            "world_accessible": True,
        }
    ],
    "server_configuration": {
        "smb1_enabled": True,                                 # -> SHARE-002
        "smb2_enabled": True,
        "signing_required": False,
    },
    "active_sessions": [],
    "_source": MOCK_MARKER,
}

UAC_DATA: dict[str, Any] = {
    "enabled": True,
    "enable_lua_raw": 1,
    "admin_prompt_behavior": "Elevate without prompting",
    "admin_prompt_raw": 0,                                    # -> UAC-002
    "secure_desktop": False,                                  # -> UAC-003
    "local_account_token_filter_policy": 1,
    "remote_uac_filtering_disabled": True,                    # -> UAC-004
    "_source": MOCK_MARKER,
}

NTLM_DATA: dict[str, Any] = {
    "lm_compatibility_level": 1,                              # -> AUTH-003
    "smb1_enabled": None,
    "wdigest_plaintext_credentials": True,                    # -> AUTH-002
    "smb_server_signing_required": False,                     # -> AUTH-004
    "lsa_protection_ppl": False,                              # -> AUTH-005
    "_source": MOCK_MARKER,
}

UPDATES_DATA: dict[str, Any] = {
    "queried_update_agent": True,
    "evidence_quality": "windows-update-agent",
    "automatic_updates": {"disabled": True, "behaviour": "Never check for updates"},
    "service": {"status": "Stopped", "start_type": "Disabled", "disabled": True},
    "pending_updates": [                                      # -> PATCH-001
        {
            "title": "2026-01 Cumulative Update for Windows 11 (KB5099999)",
            "kbs": ["KB5099999"],
            "msrc_severity": "Critical",
            "mandatory": True,
            "reboot_required": True,
            "categories": ["Security Updates"],
            "is_security_update": True,
            "support_url": "",
        }
    ],
    "pending_count": 1,
    "pending_security_count": 1,
    "pending_reboot": True,                                   # -> PATCH-002
    "history": [],
    "failed_installs": [],
    "_source": MOCK_MARKER,
}

HOTFIXES_DATA: dict[str, Any] = {
    "hotfixes": [
        {
            "kb": "KB5034123",
            "description": "Security Update",
            "installed_on": "2025-12-10T00:00:00+00:00",
            "installed_by": "NT AUTHORITY\\SYSTEM",
            "source": "Win32_QuickFixEngineering",
        }
    ],
    "kb_ids": ["KB5034123"],
    "hotfix_count": 1,
    "latest_install_date": "2025-12-10T00:00:00+00:00",
    "_source": MOCK_MARKER,
}

SOFTWARE_DATA: dict[str, Any] = {
    "applications": [
        {
            "name": "Google Chrome", "version": "120.0.6099.71",
            "publisher": "Google LLC", "architecture": "x64", "scope": "machine",
            "correlation_candidate": True, "microsoft_product": False,
            "registry_key": "GoogleChrome",
        },
        {
            "name": "7-Zip 22.01", "version": "22.01", "publisher": "Igor Pavlov",
            "architecture": "x64", "scope": "machine",
            "correlation_candidate": True, "microsoft_product": False,
            "registry_key": "7-Zip",
        },
    ],
    "application_count": 2,
    "correlation_candidates": [],
    "missing_version_count": 0,
    "_source": MOCK_MARKER,
}
SOFTWARE_DATA["correlation_candidates"] = SOFTWARE_DATA["applications"]

ADAPTERS_DATA: dict[str, Any] = {
    "adapters": [
        {
            "name": "Ethernet", "interface_index": 5, "status": "Up",
            "mac_address": "00:1B:21:AA:BB:CC", "virtual": False,
            "ipv4": [{"address": MOCK_IP, "prefix_length": 24, "family": "IPv4", "scope": "private"}],
            "ipv6": [], "gateways": [MOCK_GATEWAY], "dns_servers": ["192.0.2.53"],
        }
    ],
    "adapter_count": 1,
    "ipv4_addresses": [MOCK_IP],
    "gateways": [MOCK_GATEWAY],
    "dns_servers": ["192.0.2.53"],
    "local_subnets": ["192.0.2.0/24"],
    "routes": [],
    "_source": MOCK_MARKER,
}

ARP_DATA: dict[str, Any] = {
    "neighbours": [
        {
            "ip_address": MOCK_GATEWAY, "mac_address": "00:00:0C:11:22:33",
            "state": "Reachable", "vendor": "Cisco", "vendor_oui": "00000C",
            "locally_administered": False, "source": "Get-NetNeighbor",
        }
    ],
    "neighbour_count": 1,
    "_source": MOCK_MARKER,
}

DISCOVERY_DATA: dict[str, Any] = {
    "scope": "192.0.2.0/24",
    "profile": "safe",
    "addresses_probed": 254,
    "ports_probed": [22, 80, 443, 445, 3389],
    "hosts": [
        {
            "ip_address": MOCK_GATEWAY, "is_up": True,
            "discovery_method": "tcp-connect:80", "latency_ms": 1.2,
            "hostname": "gateway.example", "mac_address": "00:00:0C:11:22:33",
            "vendor": "Cisco",
            "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
            "open_port_count": 1, "os_guess": "", "os_confidence": "unknown",
            "os_evidence": [], "is_gateway": True, "is_local": False,
        },
        {
            "ip_address": MOCK_IP, "is_up": True,
            "discovery_method": "tcp-connect:445", "latency_ms": 0.4,
            "hostname": MOCK_HOSTNAME, "mac_address": "00:1B:21:AA:BB:CC",
            "vendor": "Intel",
            "ports": [
                {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds"},
                {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server"},
            ],
            "open_port_count": 2, "os_guess": "Windows", "os_confidence": "high",
            "os_evidence": ["Open ports [445, 3389] are characteristic of Windows."],
            "is_gateway": False, "is_local": True,
        },
    ],
    "summary": {
        "host_count": 2,
        "hosts_with_open_ports": 2,
        "total_open_ports": 3,
        "unique_ports": [80, 445, 3389],
        "service_distribution": {"microsoft-ds": 1, "ms-wbt-server": 1, "http": 1},
        "high_risk_exposures": [
            {
                "ip_address": MOCK_IP, "hostname": MOCK_HOSTNAME, "port": 445,
                "service": "SMB",
                "rationale": "Primary lateral-movement and ransomware propagation path.",
            },
            {
                "ip_address": MOCK_IP, "hostname": MOCK_HOSTNAME, "port": 3389,
                "service": "RDP",
                "rationale": "Prime target for credential attacks and known RCE flaws.",
            },
        ],
        "os_distribution": {"Windows": 1, "Unknown": 1},
        "vendors": ["Cisco", "Intel"],
        "exposure_classification": {MOCK_IP: "private", MOCK_GATEWAY: "private"},
    },
    "method": "TCP connect probes (mock data)",
    "_source": MOCK_MARKER,
}

COLLECTOR_DATA: dict[str, dict] = {
    "os": OS_DATA,
    "defender": DEFENDER_DATA,
    "firewall": FIREWALL_DATA,
    "rdp": RDP_DATA,
    "local_users": USERS_DATA,
    "local_groups": GROUPS_DATA,
    "ports": PORTS_DATA,
    "shares": SHARES_DATA,
    "uac": UAC_DATA,
    "ntlm": NTLM_DATA,
    "updates": UPDATES_DATA,
    "hotfixes": HOTFIXES_DATA,
    "software": SOFTWARE_DATA,
    "adapters": ADAPTERS_DATA,
    "arp": ARP_DATA,
}


def build_analysis_context():
    """An AnalysisContext populated with the mock collector data."""
    from app.services.analyzers.base import AnalysisContext

    return AnalysisContext(
        collector_data=dict(COLLECTOR_DATA),
        collector_status={name: "success" for name in COLLECTOR_DATA},
        discovery=DISCOVERY_DATA,
        profile="full",
        elevated=True,
    )


def build_mock_scan_output():
    """A ScanOutput that mirrors what a real engine run produces."""
    from app.core.permissions import TargetAuthorization
    from app.scanner.base import CollectorResult, CollectorStatus
    from app.scanner.engine import ScanOutput
    from app.scanner.network.topology import build_topology

    now = datetime.now(tz=timezone.utc)
    output = ScanOutput(
        target="local",
        target_type="local",
        profile="full",
        started_at=now,
        finished_at=now,
        scanner_host="TEST-RUNNER",
        elevated=True,
    )
    for name, data in COLLECTOR_DATA.items():
        output.results.append(
            CollectorResult(
                collector=name,
                status=CollectorStatus.SUCCESS,
                data=data,
                collection_method=f"mock provider ({MOCK_MARKER})",
                collected_at=now,
                category="network" if name in {"adapters", "arp", "ports", "shares"} else "windows",
            )
        )
    output.discovery = DISCOVERY_DATA
    output.topology = build_topology(
        hosts=DISCOVERY_DATA["hosts"],
        adapters=ADAPTERS_DATA,
        arp_entries=ARP_DATA["neighbours"],
        scanner_hostname=MOCK_HOSTNAME,
    )
    return output


__all__ = [
    "ADAPTERS_DATA",
    "ARP_DATA",
    "COLLECTOR_DATA",
    "DISCOVERY_DATA",
    "MOCK_GATEWAY",
    "MOCK_HOSTNAME",
    "MOCK_IP",
    "MOCK_MARKER",
    "build_analysis_context",
    "build_mock_scan_output",
]
