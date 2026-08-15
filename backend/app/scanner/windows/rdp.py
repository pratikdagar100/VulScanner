"""Remote Desktop configuration, exposure and session metadata.

Credentials are never read. Saved-destination metadata is limited to the server
names recorded in the RDP client MRU list.
"""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

SCRIPT = r"""
$ts = $null; $rdpTcp = $null
try { $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop } catch {}
try { $rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop } catch {}

$service = $null
try {
  $svc = Get-Service TermService -ErrorAction Stop
  $service = [pscustomobject]@{ Status=[string]$svc.Status; StartType=[string]$svc.StartType }
} catch {}

$fwRules = @()
try {
  $fwRules = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop |
    ForEach-Object {
      [pscustomobject]@{ Name=$_.DisplayName; Enabled=[string]$_.Enabled; Profile=[string]$_.Profile; Action=[string]$_.Action; Direction=[string]$_.Direction }
    }
} catch {}

$listening = @()
try {
  $port = if ($rdpTcp -and $rdpTcp.PortNumber) { $rdpTcp.PortNumber } else { 3389 }
  $listening = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort } })
} catch {}

# Server names only - no credentials are read from the client MRU.
$saved = @()
try {
  $servers = Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction Stop
  $saved = $servers | ForEach-Object {
    $u = $null
    try { $u = (Get-ItemProperty $_.PSPath -ErrorAction Stop).UsernameHint } catch {}
    [pscustomobject]@{ Server=$_.PSChildName; UsernameHintPresent=[bool]$u }
  }
} catch {}

$sessions = @()
try {
  $raw = (& quser.exe 2>&1 | Out-String)
  $sessions = @($raw)
} catch {}

$nlaPolicy = $null
try {
  $nlaPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction Stop)
} catch {}

[pscustomobject]@{
  DenyTSConnections   = $ts.fDenyTSConnections
  UserAuthentication  = $rdpTcp.UserAuthentication
  SecurityLayer       = $rdpTcp.SecurityLayer
  MinEncryptionLevel  = $rdpTcp.MinEncryptionLevel
  PortNumber          = $rdpTcp.PortNumber
  MaxIdleTime         = $rdpTcp.MaxIdleTime
  MaxDisconnectionTime= $rdpTcp.MaxDisconnectionTime
  PolicyUserAuth      = $nlaPolicy.UserAuthentication
  PolicySecurityLayer = $nlaPolicy.SecurityLayer
  Service             = $service
  FirewallRules       = $fwRules
  Listening           = $listening
  SavedServers        = $saved
  SessionText         = ($sessions -join "`n")
}
"""

SECURITY_LAYERS = {0: "RDP Security Layer (legacy)", 1: "Negotiate", 2: "SSL/TLS"}
ENCRYPTION_LEVELS = {
    1: "Low", 2: "Client Compatible", 3: "High", 4: "FIPS Compliant"
}


def parse_quser(raw: str) -> list[dict]:
    """Parse ``quser`` output into session records."""
    lines = [line.rstrip() for line in (raw or "").splitlines() if line.strip()]
    if len(lines) < 2 or "USERNAME" not in lines[0].upper():
        return []
    sessions = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        # A leading '>' marks the current session.
        current = line.lstrip().startswith(">")
        if current:
            parts[0] = parts[0].lstrip(">")
        sessions.append(
            {
                "username": parts[0],
                "session_name": parts[1] if not parts[1].isdigit() else "",
                "state": next(
                    (p for p in parts if p.lower() in ("active", "disc", "listen")), ""
                ),
                "current_session": current,
                "raw": line.strip(),
            }
        )
    return sessions


class RDPCollector(BaseCollector):
    name = "rdp"
    category = "windows"
    description = "Remote Desktop configuration, exposure and sessions"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Terminal Server registry keys, TermService state, firewall group "
            "'Remote Desktop' and Get-NetTCPConnection"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "RDP configuration returned nothing")
            return

        raw = ps.data
        deny = integer(get(raw, "DenyTSConnections"))
        enabled = deny == 0
        nla_raw = get(raw, "UserAuthentication")
        nla_policy = get(raw, "PolicyUserAuth")
        nla = integer(nla_policy if nla_policy is not None else nla_raw)
        security_layer = integer(
            get(raw, "PolicySecurityLayer")
            if get(raw, "PolicySecurityLayer") is not None
            else get(raw, "SecurityLayer")
        )
        port = integer(get(raw, "PortNumber"), 3389) or 3389

        firewall_rules = []
        for record in dicts(get(raw, "FirewallRules")):
            firewall_rules.append(
                {
                    "name": text(get(record, "Name")),
                    "enabled": text(get(record, "Enabled")) in ("True", "1"),
                    "profile": text(get(record, "Profile")),
                    "action": text(get(record, "Action")),
                    "direction": text(get(record, "Direction")),
                }
            )
        allowing_rules = [
            r
            for r in firewall_rules
            if r["enabled"] and r["action"] == "Allow" and r["direction"] == "Inbound"
        ]

        listening = [
            {
                "address": text(get(record, "LocalAddress")),
                "port": integer(get(record, "LocalPort")),
            }
            for record in dicts(get(raw, "Listening"))
        ]
        all_interfaces = any(
            entry["address"] in ("0.0.0.0", "::", "*") for entry in listening
        )

        service = get(raw, "Service") or {}
        sessions = parse_quser(text(get(raw, "SessionText")))

        result.data = {
            "enabled": enabled,
            "deny_connections_raw": deny,
            "port": port,
            "non_standard_port": port != 3389,
            "nla_enabled": nla == 1,
            "nla_source": "group policy" if nla_policy is not None else "registry",
            "security_layer": SECURITY_LAYERS.get(
                security_layer if security_layer is not None else -1, "Unknown"
            ),
            "security_layer_raw": security_layer,
            "min_encryption_level": ENCRYPTION_LEVELS.get(
                integer(get(raw, "MinEncryptionLevel"), -1) or -1, "Unknown"
            ),
            "max_idle_minutes": (integer(get(raw, "MaxIdleTime"), 0) or 0) // 60000,
            "max_disconnection_minutes": (
                integer(get(raw, "MaxDisconnectionTime"), 0) or 0
            )
            // 60000,
            "service": {
                "status": text(get(service, "Status")),
                "start_type": text(get(service, "StartType")),
            },
            "firewall_rules": firewall_rules,
            "firewall_allows_inbound": bool(allowing_rules),
            "firewall_profiles_allowing": sorted(
                {r["profile"] for r in allowing_rules if r["profile"]}
            ),
            "listening_endpoints": listening,
            "listening_on_all_interfaces": all_interfaces,
            "network_exposed": enabled and bool(allowing_rules) and bool(listening),
            "sessions": sessions,
            "session_count": len(sessions),
            "saved_destinations": [
                {
                    "server": text(get(record, "Server")),
                    "username_hint_present": bool(get(record, "UsernameHintPresent")),
                }
                for record in dicts(get(raw, "SavedServers"))
            ],
        }

        if deny is None:
            result.warn(
                "fDenyTSConnections was not readable; RDP state could not be "
                "confirmed."
            )
