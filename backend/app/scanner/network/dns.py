"""DNS client configuration and resolver cache metadata."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import as_list, boolean, dicts, get, integer, text

SCRIPT = r"""
$servers = @()
try {
  $servers = Get-DnsClientServerAddress -ErrorAction Stop |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object {
      [pscustomobject]@{
        InterfaceAlias=$_.InterfaceAlias; InterfaceIndex=$_.InterfaceIndex
        AddressFamily=[string]$_.AddressFamily; ServerAddresses=@($_.ServerAddresses)
      }
    }
} catch {}

$clients = @()
try {
  $clients = Get-DnsClient -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      InterfaceAlias=$_.InterfaceAlias; ConnectionSpecificSuffix=$_.ConnectionSpecificSuffix
      RegisterThisConnectionsAddress=$_.RegisterThisConnectionsAddress
      UseSuffixWhenRegistering=$_.UseSuffixWhenRegistering
    }
  }
} catch {}

$global = $null
try {
  $g = Get-DnsClientGlobalSetting -ErrorAction Stop
  $global = [pscustomobject]@{
    SuffixSearchList=@($g.SuffixSearchList); UseDevolution=$g.UseDevolution
    DevolutionLevel=$g.DevolutionLevel
  }
} catch {}

# Cache metadata only - record names and types, never payload contents.
$cache = @()
try {
  $cache = Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Entry=$_.Entry; Name=$_.Name; Type=[string]$_.Type; Status=[string]$_.Status
      TimeToLive=$_.TimeToLive; Section=[string]$_.Section
    }
  } | Select-Object -First 500
} catch {}

$netbios = $null
try {
  $netbios = (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
    Select-Object -First 1).TcpipNetbiosOptions
} catch {}

$llmnr = $null
try { $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction Stop).EnableMulticast } catch {}

$doh = @()
try {
  $doh = Get-DnsClientDohServerAddress -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ ServerAddress=$_.ServerAddress; DohTemplate=$_.DohTemplate; AllowFallbackToUdp=$_.AllowFallbackToUdp }
  }
} catch {}

[pscustomobject]@{
  Servers=$servers; Clients=$clients; Global=$global; Cache=$cache
  NetbiosOptions=$netbios; EnableMulticast=$llmnr; Doh=$doh
}
"""

NETBIOS_OPTIONS = {
    0: "Use DHCP setting",
    1: "Enabled",
    2: "Disabled",
}

# Public resolvers, reported for transparency (not a finding by themselves).
PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}


class DNSCollector(BaseCollector):
    name = "dns"
    category = "network"
    description = "DNS client configuration, resolver cache metadata and DoH settings"
    profiles = ("standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Get-DnsClientServerAddress, Get-DnsClient, Get-DnsClientCache and "
            "DNSClient policy keys"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "DNS query returned nothing")
            return

        raw = ps.data
        servers = []
        all_addresses: list[str] = []
        for record in dicts(get(raw, "Servers")):
            addresses = [text(a) for a in as_list(get(record, "ServerAddresses")) if text(a)]
            all_addresses.extend(addresses)
            servers.append(
                {
                    "interface_alias": text(get(record, "InterfaceAlias")),
                    "interface_index": integer(get(record, "InterfaceIndex")),
                    "family": text(get(record, "AddressFamily")),
                    "servers": addresses,
                }
            )

        cache = []
        for record in dicts(get(raw, "Cache")):
            cache.append(
                {
                    "name": text(get(record, "Name")),
                    "entry": text(get(record, "Entry")),
                    "type": text(get(record, "Type")),
                    "status": text(get(record, "Status")),
                    "ttl": integer(get(record, "TimeToLive")),
                    "section": text(get(record, "Section")),
                }
            )

        global_settings = get(raw, "Global") or {}
        netbios = integer(get(raw, "NetbiosOptions"))
        llmnr = boolean(get(raw, "EnableMulticast"), None)

        result.data = {
            "server_configurations": servers,
            "resolvers": sorted(set(all_addresses)),
            "public_resolvers_in_use": {
                address: PUBLIC_RESOLVERS[address]
                for address in set(all_addresses)
                if address in PUBLIC_RESOLVERS
            },
            "suffix_search_list": [
                text(s) for s in as_list(get(global_settings, "SuffixSearchList"))
            ],
            "connection_suffixes": [
                {
                    "interface": text(get(record, "InterfaceAlias")),
                    "suffix": text(get(record, "ConnectionSpecificSuffix")),
                    "registers_address": bool(
                        get(record, "RegisterThisConnectionsAddress")
                    ),
                }
                for record in dicts(get(raw, "Clients"))
            ],
            "cache_entries": cache,
            "cache_entry_count": len(cache),
            "cache_truncated": len(cache) >= 500,
            "netbios_over_tcpip": NETBIOS_OPTIONS.get(
                netbios if netbios is not None else -1, "Unknown"
            ),
            "netbios_disabled": netbios == 2,
            "llmnr_enabled": llmnr is not False,
            "llmnr_policy_value": llmnr,
            "doh_servers": [
                {
                    "server": text(get(record, "ServerAddress")),
                    "template": text(get(record, "DohTemplate")),
                    "allows_udp_fallback": bool(get(record, "AllowFallbackToUdp")),
                }
                for record in dicts(get(raw, "Doh"))
            ],
        }

        if not all_addresses:
            result.warn("No DNS servers are configured on any interface.")
