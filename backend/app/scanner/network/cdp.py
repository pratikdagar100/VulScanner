"""CDP (Cisco Discovery Protocol) neighbour information.

Windows has no CDP stack. Rather than fabricate switch relationships, this
collector records that CDP is unavailable and reports the indirect evidence it
*can* verify: whether a Cisco-attributable device is present in the neighbour
cache and whether the default gateway's MAC maps to a known network-equipment
vendor.

An operator-supplied CDP export (``cdp_import_path``) is ingested when present
and labelled as externally observed.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.network.oui import lookup_vendor
from app.scanner.util import dicts, get, normalize_mac, text

SCRIPT = r"""
$gateways = @()
try {
  $gateways = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ NextHop=$_.NextHop; InterfaceIndex=$_.InterfaceIndex } }
} catch {}

$neighbors = @()
try {
  $neighbors = Get-NetNeighbor -ErrorAction Stop |
    Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' } |
    ForEach-Object { [pscustomobject]@{ IPAddress=$_.IPAddress; LinkLayerAddress=$_.LinkLayerAddress } }
} catch {}

[pscustomobject]@{ Gateways=$gateways; Neighbors=$neighbors }
"""

# Vendors that indicate managed network infrastructure rather than an endpoint.
NETWORK_EQUIPMENT_VENDORS = (
    "cisco", "juniper", "aruba", "ubiquiti", "netgear", "tp-link", "d-link",
    "mikrotik", "hewlett packard", "extreme", "fortinet", "watchguard", "hitron",
    "comtrend", "sercomm",
)


class CDPCollector(BaseCollector):
    name = "cdp"
    category = "network"
    description = "CDP neighbour information (imported) and infrastructure inference"
    profiles = ("full", "network")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Default route next-hop and neighbour-cache vendor attribution"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Gateway query returned nothing")
            return

        raw = ps.data
        gateway_ips = {
            text(get(record, "NextHop")) for record in dicts(get(raw, "Gateways"))
        } - {""}

        infrastructure = []
        gateway_devices = []
        for record in dicts(get(raw, "Neighbors")):
            ip_address = text(get(record, "IPAddress"))
            mac = normalize_mac(get(record, "LinkLayerAddress"))
            if not mac:
                continue
            vendor, oui = lookup_vendor(mac)
            entry = {
                "ip_address": ip_address,
                "mac_address": mac,
                "vendor": vendor,
                "oui": oui,
                # This is an inference from the OUI, not a protocol announcement.
                "confidence": "inferred",
            }
            if ip_address in gateway_ips:
                entry["role"] = "gateway"
                gateway_devices.append(entry)
            if vendor and any(
                token in vendor.lower() for token in NETWORK_EQUIPMENT_VENDORS
            ):
                infrastructure.append(entry)

        neighbours, import_note = self._import_neighbours()

        result.data = {
            "cdp_supported": False,
            "neighbours": neighbours,
            "neighbour_count": len(neighbours),
            "gateway_addresses": sorted(gateway_ips),
            "gateway_devices": gateway_devices,
            "inferred_infrastructure_devices": infrastructure,
            "limitation": (
                "Windows does not implement CDP. Devices listed here are inferred "
                "from MAC vendor attribution of the neighbour cache and are marked "
                "with confidence 'inferred'. They are not CDP announcements."
            ),
            "import_note": import_note,
        }

        if not neighbours:
            result.warn(
                "CDP neighbour data is unavailable on Windows. Switch relationships "
                "are reported as inferred only."
            )

    # -- helpers -----------------------------------------------------------
    def _import_neighbours(self) -> tuple[list[dict], str]:
        configured = self.context.option("cdp_import_path")
        if not configured:
            return [], "No CDP import file configured."
        path = Path(str(configured))
        if not path.exists():
            return [], f"Configured CDP import file was not found: {path}"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [], f"CDP import file could not be read: {exc}"

        entries = payload if isinstance(payload, list) else payload.get("neighbours", [])
        neighbours = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            neighbours.append(
                {
                    "device_id": text(get(entry, "device_id", "DeviceId")),
                    "local_interface": text(get(entry, "local_interface", "LocalInterface")),
                    "remote_port": text(get(entry, "remote_port", "PortId")),
                    "platform": text(get(entry, "platform", "Platform")),
                    "capabilities": text(get(entry, "capabilities", "Capabilities")),
                    "management_address": text(
                        get(entry, "management_address", "ManagementAddress")
                    ),
                    "source": "observed-external",
                    "confidence": "observed",
                }
            )
        return neighbours, f"Imported {len(neighbours)} CDP records from {path}"
