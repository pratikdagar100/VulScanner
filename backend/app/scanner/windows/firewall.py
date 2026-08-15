"""Windows Defender Firewall profiles and rules."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import as_list, boolean, dicts, enum_name, get, text

PROFILE_SCRIPT = r"""
try {
  Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Name=$_.Name; Enabled=$_.Enabled
      DefaultInboundAction=$_.DefaultInboundAction
      DefaultOutboundAction=$_.DefaultOutboundAction
      AllowInboundRules=$_.AllowInboundRules
      AllowLocalFirewallRules=$_.AllowLocalFirewallRules
      AllowLocalIPsecRules=$_.AllowLocalIPsecRules
      NotifyOnListen=$_.NotifyOnListen
      LogAllowed=$_.LogAllowed; LogBlocked=$_.LogBlocked
      LogFileName=$_.LogFileName; LogMaxSizeKilobytes=$_.LogMaxSizeKilobytes
    }
  }
} catch {
  # Fallback for hosts without the NetSecurity module.
  $out = @()
  foreach ($p in @('DomainProfile','StandardProfile','PublicProfile')) {
    try {
      $k = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p" -ErrorAction Stop
      $out += [pscustomobject]@{ Name=$p; Enabled=$k.EnableFirewall; Source='registry' }
    } catch {}
  }
  $out
}
"""

RULE_SCRIPT = r"""
$limit = __LIMIT__
try {
  $rules = Get-NetFirewallRule -Enabled True -ErrorAction Stop
} catch {
  return @()
}

$portFilters = @{}
try {
  Get-NetFirewallPortFilter -ErrorAction Stop | ForEach-Object {
    $portFilters[$_.InstanceID] = $_
  }
} catch {}
$addrFilters = @{}
try {
  Get-NetFirewallAddressFilter -ErrorAction Stop | ForEach-Object {
    $addrFilters[$_.InstanceID] = $_
  }
} catch {}
$appFilters = @{}
try {
  Get-NetFirewallApplicationFilter -ErrorAction Stop | ForEach-Object {
    $appFilters[$_.InstanceID] = $_
  }
} catch {}
$svcFilters = @{}
try {
  Get-NetFirewallServiceFilter -ErrorAction Stop | ForEach-Object {
    $svcFilters[$_.InstanceID] = $_
  }
} catch {}

$rules | Select-Object -First $limit | ForEach-Object {
  $id = $_.InstanceID
  $pf = $portFilters[$id]; $af = $addrFilters[$id]; $ap = $appFilters[$id]; $sf = $svcFilters[$id]
  [pscustomobject]@{
    Name=$_.Name; DisplayName=$_.DisplayName; Group=$_.DisplayGroup
    Direction=[string]$_.Direction; Action=[string]$_.Action
    Enabled=[string]$_.Enabled; Profile=[string]$_.Profile
    EdgeTraversalPolicy=[string]$_.EdgeTraversalPolicy
    Protocol=if ($pf) { [string]$pf.Protocol } else { $null }
    LocalPort=if ($pf) { @($pf.LocalPort) } else { @() }
    RemotePort=if ($pf) { @($pf.RemotePort) } else { @() }
    LocalAddress=if ($af) { @($af.LocalAddress) } else { @() }
    RemoteAddress=if ($af) { @($af.RemoteAddress) } else { @() }
    Program=if ($ap) { $ap.Program } else { $null }
    Service=if ($sf) { $sf.Service } else { $null }
  }
}
"""

DIRECTIONS = {1: "Inbound", 2: "Outbound"}
ACTIONS = {2: "Allow", 4: "Block", 3: "Allow", 0: "NotConfigured"}
PROFILE_FLAGS = {1: "Domain", 2: "Private", 4: "Public"}

# Ports that should not be reachable from arbitrary remote addresses.
SENSITIVE_PORTS = {
    "3389": "Remote Desktop",
    "445": "SMB",
    "139": "NetBIOS Session",
    "135": "RPC Endpoint Mapper",
    "5985": "WinRM HTTP",
    "5986": "WinRM HTTPS",
    "1433": "SQL Server",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "23": "Telnet",
    "21": "FTP",
    "5900": "VNC",
}

ANY_ADDRESS = {"any", "*", "0.0.0.0/0", "::/0", "0.0.0.0-255.255.255.255"}


def profile_names(value: object) -> list[str]:
    raw = text(value)
    if not raw:
        return []
    if raw.isdigit():
        flags = int(raw)
        if flags in (0, 2147483647):
            return ["Domain", "Private", "Public"]
        return [name for bit, name in PROFILE_FLAGS.items() if flags & bit]
    return [part.strip() for part in raw.split(",") if part.strip()]


class FirewallCollector(BaseCollector):
    name = "firewall"
    category = "windows"
    description = "Firewall profiles, rules and risky exposure"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        runner = self.context.runner
        result.collection_method = runner.describe_method(
            "Get-NetFirewallProfile / Get-NetFirewallRule with port, address, "
            "application and service filters"
        )

        profiles_raw, profile_ps = runner.run_list(PROFILE_SCRIPT, depth=4)
        if not profile_ps.ok:
            result.fail(profile_ps.friendly_error())
            return

        profiles = []
        for record in dicts(profiles_raw):
            profiles.append(
                {
                    "name": text(get(record, "Name")),
                    "enabled": boolean(get(record, "Enabled"), None),
                    "default_inbound": enum_name(
                        get(record, "DefaultInboundAction"),
                        {0: "NotConfigured", 2: "Allow", 4: "Block"},
                    ),
                    "default_outbound": enum_name(
                        get(record, "DefaultOutboundAction"),
                        {0: "NotConfigured", 2: "Allow", 4: "Block"},
                    ),
                    "allow_inbound_rules": boolean(get(record, "AllowInboundRules")),
                    "allow_local_rules": boolean(get(record, "AllowLocalFirewallRules")),
                    "notify_on_listen": boolean(get(record, "NotifyOnListen")),
                    "log_allowed": boolean(get(record, "LogAllowed"), False),
                    "log_blocked": boolean(get(record, "LogBlocked"), False),
                    "log_file": text(get(record, "LogFileName")),
                    "source": text(get(record, "Source")) or "netsecurity-module",
                }
            )

        limit = int(self.context.option("firewall_rule_limit", 1500))
        include_rules = self.context.profile in {"standard", "full", "compliance"}
        rules: list[dict] = []
        risky: list[dict] = []

        if include_rules:
            rules_raw, rule_ps = runner.run_list(
                RULE_SCRIPT.replace("__LIMIT__", str(limit)), depth=5
            )
            if not rule_ps.ok:
                result.degrade(f"Firewall rules unavailable: {rule_ps.friendly_error()}")
            for record in dicts(rules_raw):
                rule = self._normalize_rule(record)
                rules.append(rule)
                reason = self._risk_reason(rule)
                if reason:
                    risky.append({**rule, "risk_reason": reason})

        disabled = [p["name"] for p in profiles if p["enabled"] is False]
        result.data = {
            "profiles": profiles,
            "disabled_profiles": disabled,
            "all_profiles_enabled": bool(profiles) and not disabled,
            "rules": rules,
            "rule_count": len(rules),
            "rules_truncated": len(rules) >= limit,
            "inbound_allow_count": sum(
                1
                for r in rules
                if r["direction"] == "Inbound" and r["action"] == "Allow"
            ),
            "risky_rules": risky,
            "risky_rule_count": len(risky),
            "logging_disabled_profiles": [
                p["name"] for p in profiles if not p["log_blocked"]
            ],
        }

        if not profiles:
            result.warn("No firewall profiles could be read.")
        if include_rules and len(rules) >= limit:
            result.warn(
                f"Firewall rule enumeration was capped at {limit} rules; the "
                "reported rule analysis is therefore partial."
            )

    # -- helpers -----------------------------------------------------------
    def _normalize_rule(self, record: dict) -> dict:
        return {
            "name": text(get(record, "Name")),
            "display_name": text(get(record, "DisplayName")),
            "group": text(get(record, "Group")),
            "direction": enum_name(get(record, "Direction"), DIRECTIONS),
            "action": enum_name(get(record, "Action"), ACTIONS),
            "enabled": text(get(record, "Enabled")) in ("True", "1", "Enabled"),
            "profiles": profile_names(get(record, "Profile")),
            "protocol": text(get(record, "Protocol")) or "Any",
            "local_ports": [text(p) for p in as_list(get(record, "LocalPort")) if text(p)],
            "remote_ports": [text(p) for p in as_list(get(record, "RemotePort")) if text(p)],
            "local_addresses": [
                text(a) for a in as_list(get(record, "LocalAddress")) if text(a)
            ],
            "remote_addresses": [
                text(a) for a in as_list(get(record, "RemoteAddress")) if text(a)
            ],
            "program": text(get(record, "Program")),
            "service": text(get(record, "Service")),
            "edge_traversal": enum_name(
                get(record, "EdgeTraversalPolicy"),
                {0: "Block", 1: "Allow", 2: "DeferToUser", 3: "DeferToApp"},
            ),
        }

    def _risk_reason(self, rule: dict) -> str:
        """Explain why an inbound allow rule is risky, or return an empty string."""
        if rule["direction"] != "Inbound" or rule["action"] != "Allow":
            return ""
        remote_any = not rule["remote_addresses"] or any(
            addr.lower() in ANY_ADDRESS for addr in rule["remote_addresses"]
        )
        if not remote_any:
            return ""

        ports = {p.lower() for p in rule["local_ports"]}
        sensitive = [
            f"{port} ({SENSITIVE_PORTS[port]})" for port in ports if port in SENSITIVE_PORTS
        ]
        if sensitive:
            scope = ", ".join(rule["profiles"]) or "all profiles"
            return (
                f"Allows inbound traffic from any remote address to "
                f"{', '.join(sorted(sensitive))} on {scope}."
            )
        if "any" in ports and not rule["program"] and not rule["service"]:
            return (
                "Allows inbound traffic on any port from any remote address, with no "
                "program or service restriction."
            )
        if "Public" in rule["profiles"] and rule["edge_traversal"] == "Allow":
            return (
                "Permits edge traversal (NAT/firewall traversal) on the Public "
                "profile."
            )
        return ""
