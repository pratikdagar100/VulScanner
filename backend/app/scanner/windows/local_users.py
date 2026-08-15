"""Local user accounts and password policy metadata.

Passwords and password hashes are never read. Only account metadata that
Windows exposes through normal management interfaces is collected.
"""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import boolean, dicts, get, integer, iso, text

SCRIPT = r"""
$users = @()
try {
  $users = Get-LocalUser -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Name=$_.Name; FullName=$_.FullName; Description=$_.Description
      Enabled=$_.Enabled; SID=$_.SID.Value
      PasswordRequired=$_.PasswordRequired
      PasswordChangeableDate=$_.PasswordChangeableDate
      PasswordExpires=$_.PasswordExpires
      PasswordLastSet=$_.PasswordLastSet
      UserMayChangePassword=$_.UserMayChangePassword
      LastLogon=$_.LastLogon
      AccountExpires=$_.AccountExpires
      PrincipalSource=[string]$_.PrincipalSource
      Source='Get-LocalUser'
    }
  }
} catch {
  $users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue |
    ForEach-Object {
      [pscustomobject]@{
        Name=$_.Name; FullName=$_.FullName; Description=$_.Description
        Enabled=(-not $_.Disabled); SID=$_.SID
        PasswordRequired=$_.PasswordRequired
        PasswordExpires=$_.PasswordExpires
        PasswordChangeable=$_.PasswordChangeable
        Lockout=$_.Lockout
        Source='Win32_UserAccount'
      }
    }
}

# net accounts exposes the effective password policy without touching secrets.
$netAccounts = $null
try { $netAccounts = (& net.exe accounts 2>&1 | Out-String) } catch {}

$profiles = @()
try {
  $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
    Where-Object { -not $_.Special } |
    ForEach-Object {
      [pscustomobject]@{ SID=$_.SID; LocalPath=$_.LocalPath; LastUseTime=$_.LastUseTime; Loaded=$_.Loaded }
    }
} catch {}

$autoLogon = $null
try {
  $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
  # Only the *presence* of a stored credential is recorded, never its value.
  $autoLogon = [pscustomobject]@{
    AutoAdminLogon = $wl.AutoAdminLogon
    DefaultUserName = $wl.DefaultUserName
    DefaultPasswordPresent = [bool]($wl.PSObject.Properties.Name -contains 'DefaultPassword')
  }
} catch {}

[pscustomobject]@{ Users=$users; NetAccounts=$netAccounts; Profiles=$profiles; AutoLogon=$autoLogon }
"""

BUILTIN_SIDS = {
    "-500": "Built-in Administrator",
    "-501": "Guest",
    "-503": "DefaultAccount",
    "-504": "WDAGUtilityAccount",
    "-505": "Storage replica admin",
}

POLICY_PATTERNS = {
    "min_password_age_days": r"Minimum password age \(days\):\s*(\S+)",
    "max_password_age_days": r"Maximum password age \(days\):\s*(\S+)",
    "min_password_length": r"Minimum password length:\s*(\S+)",
    "password_history_length": r"Length of password history maintained:\s*(\S+)",
    "lockout_threshold": r"Lockout threshold:\s*(\S+)",
    "lockout_duration_minutes": r"Lockout duration \(minutes\):\s*(\S+)",
    "lockout_window_minutes": r"Lockout observation window \(minutes\):\s*(\S+)",
}


def parse_net_accounts(raw: str) -> dict:
    """Parse ``net accounts`` output into a policy dictionary."""
    policy: dict[str, object] = {}
    if not raw:
        return policy
    for key, pattern in POLICY_PATTERNS.items():
        match = re.search(pattern, raw, re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if value.lower() in ("never", "unlimited", "none"):
            policy[key] = None
            policy[f"{key}_raw"] = value
        else:
            policy[key] = integer(value)
    return policy


class LocalUsersCollector(BaseCollector):
    name = "local_users"
    category = "windows"
    description = "Local user accounts and effective password policy"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-LocalUser / Win32_UserAccount, net accounts and Win32_UserProfile"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Local user query returned nothing")
            return

        users = []
        for record in dicts(get(ps.data, "Users")):
            sid = text(get(record, "SID"))
            builtin = next(
                (label for suffix, label in BUILTIN_SIDS.items() if sid.endswith(suffix)),
                "",
            )
            password_last_set = iso(get(record, "PasswordLastSet"))
            users.append(
                {
                    "name": text(get(record, "Name")),
                    "full_name": text(get(record, "FullName")),
                    "description": text(get(record, "Description")),
                    "enabled": boolean(get(record, "Enabled"), None),
                    "sid": sid,
                    "builtin_role": builtin,
                    "password_required": boolean(get(record, "PasswordRequired"), None),
                    "password_expires": iso(get(record, "PasswordExpires")),
                    "password_never_expires": get(record, "PasswordExpires") is None,
                    "password_last_set": password_last_set,
                    "user_may_change_password": boolean(
                        get(record, "UserMayChangePassword"), None
                    ),
                    "last_logon": iso(get(record, "LastLogon")),
                    "account_expires": iso(get(record, "AccountExpires")),
                    "source": text(get(record, "Source")),
                }
            )

        policy = parse_net_accounts(text(get(ps.data, "NetAccounts")))
        auto_logon = get(ps.data, "AutoLogon") or {}

        profiles = []
        for record in dicts(get(ps.data, "Profiles")):
            profiles.append(
                {
                    "sid": text(get(record, "SID")),
                    "path": text(get(record, "LocalPath")),
                    "last_use": iso(get(record, "LastUseTime")),
                    "loaded": bool(get(record, "Loaded")),
                }
            )

        enabled_users = [u for u in users if u["enabled"]]
        result.data = {
            "users": users,
            "user_count": len(users),
            "enabled_count": len(enabled_users),
            "disabled_count": len(users) - len(enabled_users),
            "guest_enabled": any(
                u["enabled"] and u["builtin_role"] == "Guest" for u in users
            ),
            "builtin_administrator_enabled": any(
                u["enabled"] and u["builtin_role"] == "Built-in Administrator"
                for u in users
            ),
            "accounts_without_password_required": [
                u["name"] for u in enabled_users if u["password_required"] is False
            ],
            "accounts_password_never_expires": [
                u["name"] for u in enabled_users if u["password_never_expires"]
            ],
            "password_policy": policy,
            "profiles": profiles,
            "auto_logon": {
                "enabled": text(get(auto_logon, "AutoAdminLogon")) == "1",
                "default_username": text(get(auto_logon, "DefaultUserName")),
                # The stored password itself is deliberately never read.
                "stored_password_present": bool(
                    get(auto_logon, "DefaultPasswordPresent")
                ),
            },
        }

        if not users:
            result.warn("No local users were returned.")
