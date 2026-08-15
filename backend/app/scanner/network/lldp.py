"""LLDP (Link Layer Discovery Protocol) neighbour information.

Windows has no built-in LLDP neighbour table: the in-box LLDP agent transmits
and receives frames for the Link Layer Topology Discovery stack, but it does not
expose learned neighbours through a public API. VulScanner therefore reports
what it *can* verify - whether the agent and protocol drivers are enabled per
adapter - and marks neighbour discovery as unavailable rather than inventing
topology.

If the operator has an LLDP-aware utility that writes a JSON neighbour export,
point ``lldp_import_path`` at it and those entries are ingested and labelled as
externally observed.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import boolean, dicts, get, text

SCRIPT = r"""
$agents = @()
try {
  $agents = Get-NetLldpAgent -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ NetAdapterName=$_.NetAdapterName; Enabled=$_.Enabled }
  }
} catch {}

$bindings = @()
try {
  $bindings = Get-NetAdapterBinding -ErrorAction Stop |
    Where-Object { $_.ComponentID -match 'lldp|rspndr|lltdio' } |
    ForEach-Object {
      [pscustomobject]@{
        Name=$_.Name; DisplayName=$_.DisplayName; ComponentID=$_.ComponentID; Enabled=$_.Enabled
      }
    }
} catch {}

$service = $null
try {
  $svc = Get-Service lltdsvc -ErrorAction Stop
  $service = [pscustomobject]@{ Status=[string]$svc.Status; StartType=[string]$svc.StartType }
} catch {}

[pscustomobject]@{ Agents=$agents; Bindings=$bindings; Service=$service }
"""


class LLDPCollector(BaseCollector):
    name = "lldp"
    category = "network"
    description = "LLDP agent state and (optionally imported) neighbour information"
    profiles = ("full", "network")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetLldpAgent, Get-NetAdapterBinding (LLDP/LLTD components) and the "
            "Link-Layer Topology Discovery service"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "LLDP query returned nothing")
            return

        raw = ps.data
        agents = [
            {
                "adapter": text(get(record, "NetAdapterName")),
                "enabled": boolean(get(record, "Enabled"), False),
            }
            for record in dicts(get(raw, "Agents"))
        ]
        bindings = [
            {
                "adapter": text(get(record, "Name")),
                "component": text(get(record, "ComponentID")),
                "display_name": text(get(record, "DisplayName")),
                "enabled": boolean(get(record, "Enabled"), False),
            }
            for record in dicts(get(raw, "Bindings"))
        ]
        service = get(raw, "Service") or {}

        neighbours, import_note = self._import_neighbours()

        result.data = {
            "agents": agents,
            "agent_enabled_adapters": [a["adapter"] for a in agents if a["enabled"]],
            "protocol_bindings": bindings,
            "lltd_service": {
                "status": text(get(service, "Status")),
                "start_type": text(get(service, "StartType")),
            },
            "neighbours": neighbours,
            "neighbour_count": len(neighbours),
            "neighbour_discovery_supported": bool(neighbours),
            "limitation": (
                "Windows does not expose an LLDP neighbour table through a public "
                "API. Neighbour entries are only present when imported from an "
                "external LLDP-aware capture, and are labelled 'observed-external'."
            ),
            "import_note": import_note,
        }

        if not neighbours:
            result.warn(
                "No LLDP neighbours are available on this platform. Switch and "
                "uplink relationships will be shown as inferred, not observed."
            )

    # -- helpers -----------------------------------------------------------
    def _import_neighbours(self) -> tuple[list[dict], str]:
        """Ingest an operator-supplied LLDP neighbour export, if configured."""
        configured = self.context.option("lldp_import_path")
        if not configured:
            return [], "No LLDP import file configured."
        path = Path(str(configured))
        if not path.exists():
            return [], f"Configured LLDP import file was not found: {path}"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [], f"LLDP import file could not be read: {exc}"

        entries = payload if isinstance(payload, list) else payload.get("neighbours", [])
        neighbours = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            neighbours.append(
                {
                    "local_interface": text(get(entry, "local_interface", "LocalInterface")),
                    "chassis_id": text(get(entry, "chassis_id", "ChassisId")),
                    "port_id": text(get(entry, "port_id", "PortId")),
                    "system_name": text(get(entry, "system_name", "SystemName")),
                    "system_description": text(
                        get(entry, "system_description", "SystemDescription")
                    ),
                    "management_address": text(
                        get(entry, "management_address", "ManagementAddress")
                    ),
                    "source": "observed-external",
                }
            )
        return neighbours, f"Imported {len(neighbours)} neighbour records from {path}"
