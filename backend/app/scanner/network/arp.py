"""ARP / neighbour cache collection with OUI vendor resolution."""

from __future__ import annotations

import ipaddress

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.network.oui import lookup_vendor
from app.scanner.util import dicts, get, integer, normalize_mac, text

SCRIPT = r"""
$neighbors = @()
try {
  $neighbors = Get-NetNeighbor -ErrorAction Stop |
    Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress } |
    ForEach-Object {
      [pscustomobject]@{
        IPAddress=$_.IPAddress; LinkLayerAddress=$_.LinkLayerAddress
        State=[string]$_.State; InterfaceIndex=$_.InterfaceIndex
        InterfaceAlias=$_.InterfaceAlias; AddressFamily=[string]$_.AddressFamily
        Source='Get-NetNeighbor'
      }
    }
} catch {
  # Fallback to the arp table on hosts without the NetTCPIP module.
  $text = (& arp.exe -a 2>&1 | Out-String)
  $neighbors = @([pscustomobject]@{ RawArp = $text; Source='arp.exe' })
}
,@($neighbors)
"""

# Multicast / broadcast link-layer addresses are not hosts.
NON_HOST_MACS = {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}


def is_host_address(address: str) -> bool:
    """Whether a neighbour-cache entry refers to an actual host.

    The neighbour cache also holds multicast group registrations (224.0.0.0/4,
    ff00::/8) and the broadcast address. Those are protocol machinery, not
    devices, and must never appear in the asset inventory or topology.
    """
    value = (address or "").split("%")[0].strip()
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.version == 4 and value == "255.255.255.255":
        return False
    return True


def parse_arp_text(raw: str) -> list[dict]:
    """Parse ``arp -a`` output as a fallback."""
    entries: list[dict] = []
    interface = ""
    for line in (raw or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("interface:"):
            parts = stripped.split()
            interface = parts[1] if len(parts) > 1 else ""
            continue
        parts = stripped.split()
        if len(parts) >= 3 and parts[0].count(".") == 3:
            mac = normalize_mac(parts[1])
            if not mac:
                continue
            entries.append(
                {
                    "ip_address": parts[0],
                    "mac_address": mac,
                    "state": parts[2].capitalize(),
                    "interface_alias": interface,
                    "source": "arp.exe",
                }
            )
    return entries


class ArpCollector(BaseCollector):
    name = "arp"
    category = "network"
    description = "ARP / neighbour cache with vendor resolution"
    profiles = ("standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetNeighbor (falling back to arp.exe -a)"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        entries: list[dict] = []
        for record in dicts(records):
            raw_arp = text(get(record, "RawArp"))
            if raw_arp:
                entries.extend(parse_arp_text(raw_arp))
                continue
            mac = normalize_mac(get(record, "LinkLayerAddress"))
            address = text(get(record, "IPAddress"))
            if not mac or mac in NON_HOST_MACS or not is_host_address(address):
                continue
            entries.append(
                {
                    "ip_address": address,
                    "mac_address": mac,
                    "state": text(get(record, "State")),
                    "interface_index": integer(get(record, "InterfaceIndex")),
                    "interface_alias": text(get(record, "InterfaceAlias")),
                    "address_family": text(get(record, "AddressFamily")),
                    "source": "Get-NetNeighbor",
                }
            )

        # Deduplicate on (ip, mac) and attach vendor information.
        seen: set[tuple[str, str]] = set()
        neighbours: list[dict] = []
        for entry in entries:
            mac = entry.get("mac_address") or ""
            address = entry.get("ip_address", "")
            key = (address, mac)
            if key in seen or mac in NON_HOST_MACS or not is_host_address(address):
                continue
            seen.add(key)
            vendor, matched = lookup_vendor(mac)
            neighbours.append(
                {
                    **entry,
                    "vendor": vendor,
                    "vendor_oui": matched,
                    "locally_administered": bool(
                        mac and int(mac.split(":")[0], 16) & 0b10
                    ),
                }
            )

        result.data = {
            "neighbours": neighbours,
            "neighbour_count": len(neighbours),
            "reachable_count": sum(
                1 for n in neighbours if n.get("state", "").lower() == "reachable"
            ),
            "unique_macs": sorted({n["mac_address"] for n in neighbours}),
            "vendors": sorted({n["vendor"] for n in neighbours if n["vendor"]}),
            "randomized_macs": [
                n for n in neighbours if n["locally_administered"]
            ],
        }

        if not neighbours:
            result.warn(
                "The neighbour cache is empty. It only holds recently contacted "
                "hosts, so this does not mean the network is empty."
            )
