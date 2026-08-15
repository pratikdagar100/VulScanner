"""Active TCP connections and their remote peers."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.network.services import remote_scope, service_for
from app.scanner.util import dicts, get, integer, iso, text

SCRIPT = r"""
$processes = @{}
try {
  Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    $processes[[int]$_.ProcessId] = [pscustomobject]@{ Name=$_.Name; Path=$_.ExecutablePath }
  }
} catch {}

$connections = @()
try {
  $connections = Get-NetTCPConnection -ErrorAction Stop |
    Where-Object { $_.State -ne 'Listen' } |
    ForEach-Object {
      $p = $processes[[int]$_.OwningProcess]
      [pscustomobject]@{
        LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
        RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort
        State=[string]$_.State; ProcessId=$_.OwningProcess
        ProcessName=if ($p) { $p.Name } else { $null }
        ProcessPath=if ($p) { $p.Path } else { $null }
        CreationTime=$_.CreationTime
      }
    }
} catch {}
,@($connections)
"""


class ConnectionsCollector(BaseCollector):
    name = "connections"
    category = "network"
    description = "Established and pending TCP connections with remote peers"
    profiles = ("standard", "full", "network")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetTCPConnection (non-listening states) joined with Win32_Process"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        connections = []
        for record in dicts(records):
            remote_address = text(get(record, "RemoteAddress"))
            remote_port = integer(get(record, "RemotePort"), 0) or 0
            scope = remote_scope(remote_address)
            connections.append(
                {
                    "protocol": "tcp",
                    "local_address": text(get(record, "LocalAddress")),
                    "local_port": integer(get(record, "LocalPort"), 0) or 0,
                    "remote_address": remote_address,
                    "remote_port": remote_port,
                    "remote_service": service_for(remote_port, "tcp"),
                    "remote_scope": scope,
                    "state": text(get(record, "State")),
                    "process_id": integer(get(record, "ProcessId")),
                    "process_name": text(get(record, "ProcessName")),
                    "process_path": text(get(record, "ProcessPath")),
                    "created": iso(get(record, "CreationTime")),
                }
            )

        established = [c for c in connections if c["state"].lower() == "established"]
        external = [c for c in established if c["remote_scope"] == "public"]

        # Which processes talk to the internet, and on which ports.
        by_process: dict[str, dict] = {}
        for connection in external:
            name = connection["process_name"] or f"pid {connection['process_id']}"
            entry = by_process.setdefault(
                name, {"process": name, "connection_count": 0, "remote_ports": set()}
            )
            entry["connection_count"] += 1
            entry["remote_ports"].add(connection["remote_port"])

        result.data = {
            "connections": connections,
            "connection_count": len(connections),
            "established": established,
            "established_count": len(established),
            "external_connections": external,
            "external_connection_count": len(external),
            "internal_connections": [
                c for c in established if c["remote_scope"] == "private"
            ],
            "unique_remote_addresses": sorted(
                {c["remote_address"] for c in established if c["remote_address"]}
            ),
            "external_talkers": [
                {**entry, "remote_ports": sorted(entry["remote_ports"])}
                for entry in sorted(
                    by_process.values(), key=lambda e: -e["connection_count"]
                )
            ],
            "states": {
                state: sum(1 for c in connections if c["state"] == state)
                for state in sorted({c["state"] for c in connections})
            },
        }
