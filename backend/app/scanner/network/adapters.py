"""Network adapter, address and route inventory."""

from __future__ import annotations

import ipaddress

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import as_list, dicts, get, integer, normalize_mac, text

SCRIPT = r"""
$adapters = @()
try {
  $adapters = Get-NetAdapter -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Name=$_.Name; InterfaceIndex=$_.ifIndex; InterfaceDescription=$_.InterfaceDescription
      Status=[string]$_.Status; MacAddress=$_.MacAddress; LinkSpeed=$_.LinkSpeed
      MediaType=$_.MediaType; PhysicalMediaType=$_.PhysicalMediaType
      Virtual=$_.Virtual; DriverVersion=$_.DriverVersion; DriverDate=$_.DriverDate
    }
  }
} catch {}

$addresses = @()
try {
  $addresses = Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      InterfaceIndex=$_.InterfaceIndex; InterfaceAlias=$_.InterfaceAlias
      IPAddress=$_.IPAddress; PrefixLength=$_.PrefixLength
      AddressFamily=[string]$_.AddressFamily; PrefixOrigin=[string]$_.PrefixOrigin
      SuffixOrigin=[string]$_.SuffixOrigin; AddressState=[string]$_.AddressState
    }
  }
} catch {}

$routes = @()
try {
  $routes = Get-NetRoute -ErrorAction Stop |
    Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } |
    ForEach-Object {
      [pscustomobject]@{
        InterfaceIndex=$_.InterfaceIndex; DestinationPrefix=$_.DestinationPrefix
        NextHop=$_.NextHop; RouteMetric=$_.RouteMetric; Protocol=[string]$_.Protocol
      }
    }
} catch {}

$dnsServers = @()
try {
  $dnsServers = Get-DnsClientServerAddress -ErrorAction Stop |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object {
      [pscustomobject]@{
        InterfaceIndex=$_.InterfaceIndex; InterfaceAlias=$_.InterfaceAlias
        AddressFamily=[string]$_.AddressFamily; ServerAddresses=@($_.ServerAddresses)
      }
    }
} catch {}

# Fallback for hosts without the NetTCPIP module.
$legacy = @()
if (-not $adapters) {
  try {
    $legacy = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
      ForEach-Object {
        [pscustomobject]@{
          Name=$_.Description; InterfaceIndex=$_.InterfaceIndex; MacAddress=$_.MACAddress
          IPAddress=@($_.IPAddress); Gateway=@($_.DefaultIPGateway); DNS=@($_.DNSServerSearchOrder)
          DHCPEnabled=$_.DHCPEnabled; DHCPServer=$_.DHCPServer
        }
      }
  } catch {}
}

[pscustomobject]@{ Adapters=$adapters; Addresses=$addresses; Routes=$routes; DnsServers=$dnsServers; Legacy=$legacy }
"""


def scope_of(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    return "public"


class AdaptersCollector(BaseCollector):
    name = "adapters"
    category = "network"
    description = "Network adapters, IP addresses, routes and DNS servers"
    profiles = ("quick", "standard", "full", "compliance", "network")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetAdapter, Get-NetIPAddress, Get-NetRoute and "
            "Get-DnsClientServerAddress"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Adapter query returned nothing")
            return

        raw = ps.data
        addresses_by_index: dict[int, list[dict]] = {}
        for record in dicts(get(raw, "Addresses")):
            index = integer(get(record, "InterfaceIndex"))
            if index is None:
                continue
            address = text(get(record, "IPAddress"))
            addresses_by_index.setdefault(index, []).append(
                {
                    "address": address,
                    "prefix_length": integer(get(record, "PrefixLength")),
                    "family": "IPv6"
                    if ":" in address
                    else "IPv4",
                    "origin": text(get(record, "PrefixOrigin")),
                    "state": text(get(record, "AddressState")),
                    "scope": scope_of(address),
                }
            )

        gateways_by_index: dict[int, list[str]] = {}
        routes = []
        for record in dicts(get(raw, "Routes")):
            index = integer(get(record, "InterfaceIndex"))
            next_hop = text(get(record, "NextHop"))
            destination = text(get(record, "DestinationPrefix"))
            routes.append(
                {
                    "interface_index": index,
                    "destination": destination,
                    "next_hop": next_hop,
                    "metric": integer(get(record, "RouteMetric")),
                    "protocol": text(get(record, "Protocol")),
                    "default_route": destination in ("0.0.0.0/0", "::/0"),
                }
            )
            if destination in ("0.0.0.0/0", "::/0") and index is not None:
                gateways_by_index.setdefault(index, []).append(next_hop)

        dns_by_index: dict[int, list[str]] = {}
        for record in dicts(get(raw, "DnsServers")):
            index = integer(get(record, "InterfaceIndex"))
            if index is None:
                continue
            dns_by_index.setdefault(index, []).extend(
                text(server) for server in as_list(get(record, "ServerAddresses"))
            )

        adapters = []
        for record in dicts(get(raw, "Adapters")):
            index = integer(get(record, "InterfaceIndex"))
            adapter_addresses = addresses_by_index.get(index or -1, [])
            adapters.append(
                {
                    "name": text(get(record, "Name")),
                    "interface_index": index,
                    "description": text(get(record, "InterfaceDescription")),
                    "status": text(get(record, "Status")),
                    "mac_address": normalize_mac(get(record, "MacAddress")),
                    "link_speed": text(get(record, "LinkSpeed")),
                    "media_type": text(get(record, "MediaType")),
                    "physical_media": text(get(record, "PhysicalMediaType")),
                    "virtual": bool(get(record, "Virtual")),
                    "driver_version": text(get(record, "DriverVersion")),
                    "ipv4": [a for a in adapter_addresses if a["family"] == "IPv4"],
                    "ipv6": [a for a in adapter_addresses if a["family"] == "IPv6"],
                    "gateways": gateways_by_index.get(index or -1, []),
                    "dns_servers": dns_by_index.get(index or -1, []),
                }
            )

        # Legacy fallback for hosts without the NetTCPIP module.
        for record in dicts(get(raw, "Legacy")):
            index = integer(get(record, "InterfaceIndex"))
            ips = [text(a) for a in as_list(get(record, "IPAddress"))]
            adapters.append(
                {
                    "name": text(get(record, "Name")),
                    "interface_index": index,
                    "description": text(get(record, "Name")),
                    "status": "Up",
                    "mac_address": normalize_mac(get(record, "MacAddress")),
                    "link_speed": "",
                    "media_type": "",
                    "physical_media": "",
                    "virtual": False,
                    "driver_version": "",
                    "ipv4": [
                        {"address": ip, "family": "IPv4", "scope": scope_of(ip)}
                        for ip in ips
                        if ":" not in ip
                    ],
                    "ipv6": [
                        {"address": ip, "family": "IPv6", "scope": scope_of(ip)}
                        for ip in ips
                        if ":" in ip
                    ],
                    "gateways": [text(g) for g in as_list(get(record, "Gateway"))],
                    "dns_servers": [text(d) for d in as_list(get(record, "DNS"))],
                    "source": "Win32_NetworkAdapterConfiguration",
                }
            )

        active = [a for a in adapters if a["status"].lower() == "up"]

        # Order addresses by usefulness so the first entry is the address that
        # actually identifies this host: routable first, APIPA last.
        scope_rank = {"public": 0, "private": 1, "link-local": 2, "unknown": 3}
        ipv4_entries = [
            (adapter, addr)
            for adapter in adapters
            for addr in adapter["ipv4"]
            if addr["scope"] != "loopback"
        ]
        ipv4_entries.sort(
            key=lambda pair: (
                scope_rank.get(pair[1]["scope"], 4),
                0 if pair[0]["status"].lower() == "up" else 1,
                0 if not pair[0]["virtual"] else 1,
            )
        )
        all_ipv4 = [addr["address"] for _, addr in ipv4_entries]
        local_subnets = []
        for adapter in adapters:
            for addr in adapter["ipv4"]:
                prefix = addr.get("prefix_length")
                if addr["scope"] in ("private", "public") and prefix:
                    try:
                        network = ipaddress.ip_network(
                            f"{addr['address']}/{prefix}", strict=False
                        )
                        local_subnets.append(str(network))
                    except ValueError:
                        continue

        result.data = {
            "adapters": adapters,
            "adapter_count": len(adapters),
            "active_adapters": active,
            "active_adapter_count": len(active),
            "ipv4_addresses": all_ipv4,
            "ipv6_addresses": [
                addr["address"]
                for adapter in adapters
                for addr in adapter["ipv6"]
                if addr["scope"] not in ("loopback", "link-local")
            ],
            "public_addresses": [
                addr["address"]
                for adapter in adapters
                for addr in adapter["ipv4"] + adapter["ipv6"]
                if addr["scope"] == "public"
            ],
            "gateways": sorted({g for a in adapters for g in a["gateways"] if g}),
            "dns_servers": sorted({d for a in adapters for d in a["dns_servers"] if d}),
            "local_subnets": sorted(set(local_subnets)),
            "routes": routes,
            "default_routes": [r for r in routes if r["default_route"]],
        }

        if not adapters:
            result.warn("No network adapters were returned.")
