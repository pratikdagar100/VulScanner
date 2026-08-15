"""Network connection profiles (Domain / Private / Public categorisation)."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

SCRIPT = r"""
$profiles = @()
try {
  $profiles = Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Name=$_.Name; InterfaceAlias=$_.InterfaceAlias; InterfaceIndex=$_.InterfaceIndex
      NetworkCategory=[string]$_.NetworkCategory
      IPv4Connectivity=[string]$_.IPv4Connectivity
      IPv6Connectivity=[string]$_.IPv6Connectivity
      DomainAuthenticationKind=[string]$_.DomainAuthenticationKind
    }
  }
} catch {}

$discovery = $null
try {
  $rules = Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction Stop
  $discovery = [pscustomobject]@{
    EnabledCount = @($rules | Where-Object { $_.Enabled -eq 'True' }).Count
    TotalCount   = @($rules).Count
  }
} catch {}

$sharing = $null
try {
  $rules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction Stop
  $sharing = [pscustomobject]@{
    EnabledCount = @($rules | Where-Object { $_.Enabled -eq 'True' }).Count
    TotalCount   = @($rules).Count
  }
} catch {}

[pscustomobject]@{ Profiles=$profiles; NetworkDiscovery=$discovery; FileSharing=$sharing }
"""


class ProfilesCollector(BaseCollector):
    name = "profiles"
    category = "network"
    description = "Network connection profiles and discovery/sharing exposure"
    profiles = ("quick", "standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetConnectionProfile and the Network Discovery / File and Printer "
            "Sharing firewall rule groups"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Network profile query returned nothing")
            return

        raw = ps.data
        profiles = []
        for record in dicts(get(raw, "Profiles")):
            category = text(get(record, "NetworkCategory"))
            profiles.append(
                {
                    "name": text(get(record, "Name")),
                    "interface_alias": text(get(record, "InterfaceAlias")),
                    "interface_index": integer(get(record, "InterfaceIndex")),
                    "category": category,
                    "ipv4_connectivity": text(get(record, "IPv4Connectivity")),
                    "ipv6_connectivity": text(get(record, "IPv6Connectivity")),
                    "domain_authentication": text(
                        get(record, "DomainAuthenticationKind")
                    ),
                    "internet_connected": text(get(record, "IPv4Connectivity"))
                    == "Internet",
                }
            )

        discovery = get(raw, "NetworkDiscovery") or {}
        sharing = get(raw, "FileSharing") or {}
        private_on_internet = [
            p
            for p in profiles
            if p["category"] == "Private" and p["internet_connected"]
        ]

        result.data = {
            "profiles": profiles,
            "profile_count": len(profiles),
            "categories": sorted({p["category"] for p in profiles if p["category"]}),
            "public_networks": [p for p in profiles if p["category"] == "Public"],
            "private_networks": [p for p in profiles if p["category"] == "Private"],
            "domain_networks": [
                p for p in profiles if p["category"] == "DomainAuthenticated"
            ],
            "private_profile_on_internet_facing_link": private_on_internet,
            "network_discovery": {
                "enabled_rules": integer(get(discovery, "EnabledCount"), 0),
                "total_rules": integer(get(discovery, "TotalCount"), 0),
                "enabled": (integer(get(discovery, "EnabledCount"), 0) or 0) > 0,
            },
            "file_and_printer_sharing": {
                "enabled_rules": integer(get(sharing, "EnabledCount"), 0),
                "total_rules": integer(get(sharing, "TotalCount"), 0),
                "enabled": (integer(get(sharing, "EnabledCount"), 0) or 0) > 0,
            },
        }

        if not profiles:
            result.warn("No active network connection profiles were found.")
