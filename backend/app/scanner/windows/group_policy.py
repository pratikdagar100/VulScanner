"""Applied Group Policy objects and local security policy export."""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, iso, text

SCRIPT = r"""
$applied = @()
try {
  foreach ($scope in @('Machine','User')) {
    $base = if ($scope -eq 'Machine') {
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    } else {
      'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    }
    if (Test-Path $base) {
      Get-ChildItem $base -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
          $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
          if ($p -and $p.DisplayName) {
            $applied += [pscustomobject]@{
              Scope=$scope; DisplayName=$p.DisplayName; GPOName=$p.GPOName
              Extension=$p.Extension; Link=$p.Link; Version=$p.Version
            }
          }
        }
    }
  }
} catch {}

$state = $null
try {
  $state = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine' -ErrorAction Stop |
    Select-Object LastGPOTime, PreviousPolicyAreas
} catch {}

# secedit exports the effective local security policy without altering it.
$secpol = $null
$secpolError = $null
if (__EXPORT__) {
  $tmp = Join-Path $env:TEMP ("vulscanner_secpol_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
  try {
    $null = & secedit.exe /export /cfg $tmp /quiet 2>&1
    if (Test-Path $tmp) { $secpol = Get-Content $tmp -Raw -ErrorAction Stop }
  } catch { $secpolError = $_.Exception.Message }
  finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}

[pscustomobject]@{ Applied=$applied; State=$state; SecPol=$secpol; SecPolError=$secpolError }
"""

# Security policy values worth surfacing, mapped to friendly names.
SECPOL_KEYS = {
    "MinimumPasswordAge": "minimum_password_age_days",
    "MaximumPasswordAge": "maximum_password_age_days",
    "MinimumPasswordLength": "minimum_password_length",
    "PasswordComplexity": "password_complexity",
    "PasswordHistorySize": "password_history_size",
    "LockoutBadCount": "lockout_threshold",
    "LockoutDuration": "lockout_duration_minutes",
    "ResetLockoutCount": "lockout_window_minutes",
    "ClearTextPassword": "reversible_encryption",
    "EnableGuestAccount": "guest_account_enabled",
    "NewAdministratorName": "administrator_renamed_to",
    "NewGuestName": "guest_renamed_to",
    "ForceLogoffWhenHourExpire": "force_logoff_when_hours_expire",
}


def parse_secpol(raw: str) -> dict:
    """Parse the ``[System Access]`` section of a secedit export."""
    values: dict[str, object] = {}
    if not raw:
        return values
    in_section = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped.lower() == "[system access]"
            continue
        if not in_section or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        friendly = SECPOL_KEYS.get(key.strip())
        if not friendly:
            continue
        value = value.strip().strip('"')
        parsed = integer(value)
        values[friendly] = parsed if parsed is not None else value
    return values


class GroupPolicyCollector(BaseCollector):
    name = "group_policy"
    category = "windows"
    description = "Applied Group Policy objects and local security policy"
    requires_admin = True
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        export = self.context.profile in {"full", "compliance", "standard"}
        script = SCRIPT.replace("__EXPORT__", "$true" if export else "$false")

        ps = self.context.runner.run(script, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Group Policy History registry keys"
            + (" and secedit /export" if export else "")
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Group Policy query returned nothing")
            return

        applied = []
        for record in dicts(get(ps.data, "Applied")):
            applied.append(
                {
                    "scope": text(get(record, "Scope")),
                    "display_name": text(get(record, "DisplayName")),
                    "gpo_name": text(get(record, "GPOName")),
                    "extension": text(get(record, "Extension")),
                    "link": text(get(record, "Link")),
                    "version": integer(get(record, "Version")),
                }
            )

        state = get(ps.data, "State") or {}
        policy = parse_secpol(text(get(ps.data, "SecPol")))

        result.data = {
            "applied_gpos": applied,
            "applied_gpo_count": len({g["display_name"] for g in applied}),
            "domain_managed": bool(applied),
            "last_policy_apply": iso(get(state, "LastGPOTime")),
            "security_policy": policy,
            "security_policy_available": bool(policy),
            "password_complexity_enabled": policy.get("password_complexity") == 1,
            "reversible_encryption_enabled": policy.get("reversible_encryption") == 1,
            "account_lockout_configured": bool(policy.get("lockout_threshold")),
            "administrator_renamed": bool(
                policy.get("administrator_renamed_to")
                and str(policy["administrator_renamed_to"]).lower() != "administrator"
            ),
        }

        error = text(get(ps.data, "SecPolError"))
        if error:
            result.degrade(f"secedit export failed: {error}")
        elif export and not policy:
            result.warn(
                "The local security policy could not be exported. secedit requires "
                "an elevated session."
            )
