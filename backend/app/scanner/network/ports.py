"""Listening TCP/UDP endpoints on the scanned host, mapped to processes."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.network.services import (
    HIGH_RISK_PORTS,
    classify_exposure,
    port_risk,
    service_for,
)
from app.scanner.util import dicts, get, integer, text

SCRIPT = r"""
$processes = @{}
try {
  Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    $processes[[int]$_.ProcessId] = [pscustomobject]@{ Name=$_.Name; Path=$_.ExecutablePath }
  }
} catch {
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $processes[[int]$_.Id] = [pscustomobject]@{ Name=$_.ProcessName; Path=$_.Path }
  }
}

$svcByPid = @{}
try {
  Get-CimInstance Win32_Service -Filter "ProcessId <> 0" -ErrorAction Stop | ForEach-Object {
    $key = [int]$_.ProcessId
    if (-not $svcByPid.ContainsKey($key)) { $svcByPid[$key] = @() }
    $svcByPid[$key] += $_.Name
  }
} catch {}

$tcp = @()
try {
  $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
    $p = $processes[[int]$_.OwningProcess]
    [pscustomobject]@{
      Protocol='tcp'; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
      State=[string]$_.State; ProcessId=$_.OwningProcess
      ProcessName=if ($p) { $p.Name } else { $null }
      ProcessPath=if ($p) { $p.Path } else { $null }
      Services=if ($svcByPid.ContainsKey([int]$_.OwningProcess)) { $svcByPid[[int]$_.OwningProcess] } else { @() }
    }
  }
} catch {}

$udp = @()
try {
  $udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
    $p = $processes[[int]$_.OwningProcess]
    [pscustomobject]@{
      Protocol='udp'; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
      State='Listen'; ProcessId=$_.OwningProcess
      ProcessName=if ($p) { $p.Name } else { $null }
      ProcessPath=if ($p) { $p.Path } else { $null }
      Services=if ($svcByPid.ContainsKey([int]$_.OwningProcess)) { $svcByPid[[int]$_.OwningProcess] } else { @() }
    }
  }
} catch {}

$fallback = $null
if (-not $tcp -and -not $udp) {
  $fallback = (& netstat.exe -ano 2>&1 | Out-String)
}

[pscustomobject]@{ Tcp=$tcp; Udp=$udp; Fallback=$fallback }
"""


def parse_netstat(raw: str) -> list[dict]:
    """Parse ``netstat -ano`` as a fallback when NetTCPIP is unavailable."""
    entries: list[dict] = []
    for line in (raw or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].lower() not in ("tcp", "udp"):
            continue
        protocol = parts[0].lower()
        local = parts[1]
        if protocol == "tcp":
            if len(parts) < 5 or parts[3].upper() != "LISTENING":
                continue
            pid = parts[4]
        else:
            pid = parts[-1]
        address, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        entries.append(
            {
                "protocol": protocol,
                "local_address": address.strip("[]"),
                "local_port": int(port),
                "state": "Listen",
                "process_id": int(pid) if pid.isdigit() else None,
                "process_name": "",
                "process_path": "",
                "services": [],
            }
        )
    return entries


class PortsCollector(BaseCollector):
    name = "ports"
    category = "network"
    description = "Listening TCP and UDP endpoints with owning processes"
    profiles = ("quick", "standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Get-NetTCPConnection, Get-NetUDPEndpoint, Win32_Process and Win32_Service"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Port enumeration returned nothing")
            return

        raw = ps.data
        records = dicts(get(raw, "Tcp")) + dicts(get(raw, "Udp"))
        normalized: list[dict] = []

        if records:
            for record in records:
                normalized.append(
                    {
                        "protocol": text(get(record, "Protocol")) or "tcp",
                        "local_address": text(get(record, "LocalAddress")),
                        "local_port": integer(get(record, "LocalPort"), 0) or 0,
                        "state": text(get(record, "State")) or "Listen",
                        "process_id": integer(get(record, "ProcessId")),
                        "process_name": text(get(record, "ProcessName")),
                        "process_path": text(get(record, "ProcessPath")),
                        "services": [
                            text(s) for s in (get(record, "Services") or []) if text(s)
                        ],
                    }
                )
        else:
            fallback = text(get(raw, "Fallback"))
            normalized = parse_netstat(fallback)
            if normalized:
                result.warn(
                    "NetTCPIP cmdlets were unavailable; ports were parsed from "
                    "netstat, so process and service attribution is limited."
                )

        ports: list[dict] = []
        seen: set[tuple[str, str, int]] = set()
        for entry in normalized:
            key = (entry["protocol"], entry["local_address"], entry["local_port"])
            if key in seen:
                continue
            seen.add(key)
            exposure = classify_exposure(entry["local_address"])
            score, rationale = port_risk(entry["local_port"], exposure)
            risky = HIGH_RISK_PORTS.get(entry["local_port"])
            ports.append(
                {
                    **entry,
                    "service": service_for(entry["local_port"], entry["protocol"]),
                    "service_source": "well-known-port",
                    "exposure": exposure,
                    "risk_score": score,
                    "risk_rationale": rationale,
                    "high_risk_service": risky[0] if risky else "",
                }
            )

        ports.sort(key=lambda p: (-p["risk_score"], p["local_port"]))
        network_reachable = [
            p for p in ports if p["exposure"] in ("all-interfaces", "private", "public")
        ]

        result.data = {
            "ports": ports,
            "port_count": len(ports),
            "tcp_ports": [p for p in ports if p["protocol"] == "tcp"],
            "udp_ports": [p for p in ports if p["protocol"] == "udp"],
            "listening_port_numbers": sorted({p["local_port"] for p in ports}),
            "network_reachable_ports": network_reachable,
            "network_reachable_count": len(network_reachable),
            "loopback_only_count": sum(1 for p in ports if p["exposure"] == "loopback"),
            "high_risk_ports": [p for p in network_reachable if p["high_risk_service"]],
            "publicly_bound_ports": [p for p in ports if p["exposure"] == "public"],
            "unattributed_ports": [p for p in ports if not p["process_name"]],
        }

        if not ports:
            result.warn("No listening ports were enumerated.")
