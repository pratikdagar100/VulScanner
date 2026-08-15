"""RPC endpoint mapper exposure and related service configuration."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

SCRIPT = r"""
$service = $null
try {
  $svc = Get-Service RpcSs -ErrorAction Stop
  $service = [pscustomobject]@{ Status=[string]$svc.Status; StartType=[string]$svc.StartType }
} catch {}

$endpointMapper = @()
try {
  $endpointMapper = @(Get-NetTCPConnection -State Listen -LocalPort 135 -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort } })
} catch {}

$policy = $null
try {
  $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -ErrorAction Stop |
    Select-Object RestrictRemoteClients, EnableAuthEpResolution
} catch {}

$portRange = $null
try {
  $portRange = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Rpc\Internet' -ErrorAction Stop |
    Select-Object Ports, PortsInternetAvailable, UseInternetPorts
} catch {}

# Services that expose remote management surfaces over RPC/DCOM.
$related = @()
foreach ($name in @('RemoteRegistry','WinRM','Winmgmt','LanmanServer','Spooler','Schedule','TermService')) {
  try {
    $svc = Get-Service $name -ErrorAction Stop
    $related += [pscustomobject]@{ Name=$name; Status=[string]$svc.Status; StartType=[string]$svc.StartType }
  } catch {}
}

$dcom = $null
try {
  $dcom = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Ole' -ErrorAction Stop |
    Select-Object EnableDCOM, LegacyAuthenticationLevel, LegacyImpersonationLevel
} catch {}

$firewall135 = @()
try {
  $firewall135 = Get-NetFirewallPortFilter -ErrorAction Stop |
    Where-Object { $_.LocalPort -eq 135 } |
    ForEach-Object {
      $rule = $_ | Get-NetFirewallRule -ErrorAction SilentlyContinue
      if ($rule -and $rule.Enabled -eq 'True' -and $rule.Direction -eq 'Inbound') {
        [pscustomobject]@{ Name=$rule.DisplayName; Action=[string]$rule.Action; Profile=[string]$rule.Profile }
      }
    }
} catch {}

[pscustomobject]@{
  Service=$service; EndpointMapper=$endpointMapper; Policy=$policy
  PortRange=$portRange; RelatedServices=$related; Dcom=$dcom; FirewallRules=$firewall135
}
"""

RESTRICT_REMOTE_CLIENTS = {
    0: "None - all remote anonymous calls allowed",
    1: "Authenticated - anonymous calls rejected (Windows default)",
    2: "Authenticated without exceptions",
}

# Services that meaningfully widen the remote attack surface when running.
NOTABLE_SERVICES = {
    "RemoteRegistry": "Allows remote reading of the registry.",
    "WinRM": "Remote PowerShell / WS-Management endpoint.",
    "Spooler": "Print Spooler has a long history of remote code execution flaws.",
    "TermService": "Remote Desktop service.",
}


class RPCCollector(BaseCollector):
    name = "rpc"
    category = "network"
    description = "RPC endpoint mapper exposure, DCOM and remote-management services"
    profiles = ("standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "RpcSs service state, port 135 listeners, RPC policy keys and DCOM "
            "configuration"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "RPC query returned nothing")
            return

        raw = ps.data
        service = get(raw, "Service") or {}
        policy = get(raw, "Policy") or {}
        port_range = get(raw, "PortRange") or {}
        dcom = get(raw, "Dcom") or {}

        endpoints = [
            {
                "address": text(get(record, "LocalAddress")),
                "port": integer(get(record, "LocalPort"), 135),
            }
            for record in dicts(get(raw, "EndpointMapper"))
        ]
        exposed = any(
            e["address"] in ("0.0.0.0", "::", "*") for e in endpoints
        )

        related = []
        for record in dicts(get(raw, "RelatedServices")):
            name = text(get(record, "Name"))
            related.append(
                {
                    "name": name,
                    "status": text(get(record, "Status")),
                    "start_type": text(get(record, "StartType")),
                    "running": text(get(record, "Status")).lower() == "running",
                    "note": NOTABLE_SERVICES.get(name, ""),
                }
            )

        restrict = integer(get(policy, "RestrictRemoteClients"))
        result.data = {
            "service": {
                "status": text(get(service, "Status")),
                "start_type": text(get(service, "StartType")),
            },
            "endpoint_mapper_listeners": endpoints,
            "endpoint_mapper_exposed": exposed,
            "restrict_remote_clients": restrict,
            "restrict_remote_clients_description": RESTRICT_REMOTE_CLIENTS.get(
                restrict if restrict is not None else -1,
                "Not configured (Windows default is 1)",
            ),
            "auth_endpoint_resolution": integer(get(policy, "EnableAuthEpResolution")),
            "internet_port_range": text(get(port_range, "Ports")),
            "uses_internet_ports": text(get(port_range, "UseInternetPorts")) == "Y",
            "dcom": {
                "enabled": text(get(dcom, "EnableDCOM")).upper() != "N",
                "legacy_authentication_level": integer(
                    get(dcom, "LegacyAuthenticationLevel")
                ),
                "legacy_impersonation_level": integer(
                    get(dcom, "LegacyImpersonationLevel")
                ),
            },
            "related_services": related,
            "running_remote_management_services": [
                s for s in related if s["running"] and s["note"]
            ],
            "inbound_firewall_rules_port_135": [
                {
                    "name": text(get(record, "Name")),
                    "action": text(get(record, "Action")),
                    "profile": text(get(record, "Profile")),
                }
                for record in dicts(get(raw, "FirewallRules"))
            ],
        }
