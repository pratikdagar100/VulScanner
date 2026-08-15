"""SMB share inventory and permission metadata."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import boolean, dicts, get, integer, text

SCRIPT = r"""
$shares = @()
try {
  $shares = Get-SmbShare -ErrorAction Stop | ForEach-Object {
    $access = @()
    try {
      $access = @(Get-SmbShareAccess -Name $_.Name -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ AccountName=$_.AccountName; AccessRight=[string]$_.AccessRight; AccessControlType=[string]$_.AccessControlType }
      })
    } catch {}
    [pscustomobject]@{
      Name=$_.Name; Path=$_.Path; Description=$_.Description
      ShareType=[string]$_.ShareType; ShareState=[string]$_.ShareState
      Special=$_.Special; EncryptData=$_.EncryptData
      FolderEnumerationMode=[string]$_.FolderEnumerationMode
      CurrentUsers=$_.CurrentUsers; Access=$access; Source='Get-SmbShare'
    }
  }
} catch {
  $shares = Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      Name=$_.Name; Path=$_.Path; Description=$_.Description
      ShareType=[string]$_.Type; Special=($_.Name -match '\$$'); Access=@(); Source='Win32_Share'
    }
  }
}

$server = $null
try {
  $c = Get-SmbServerConfiguration -ErrorAction Stop
  $server = [pscustomobject]@{
    EnableSMB1Protocol=$c.EnableSMB1Protocol; EnableSMB2Protocol=$c.EnableSMB2Protocol
    RequireSecuritySignature=$c.RequireSecuritySignature
    EnableSecuritySignature=$c.EnableSecuritySignature
    EncryptData=$c.EncryptData; RejectUnencryptedAccess=$c.RejectUnencryptedAccess
    AutoShareServer=$c.AutoShareServer; AutoShareWorkstation=$c.AutoShareWorkstation
    EnableAuthenticateUserSharing=$c.EnableAuthenticateUserSharing
  }
} catch {}

$sessions = @()
try {
  $sessions = Get-SmbSession -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ ClientComputerName=$_.ClientComputerName; ClientUserName=$_.ClientUserName
                       NumOpens=$_.NumOpens; Dialect=$_.Dialect }
  }
} catch {}

[pscustomobject]@{ Shares=$shares; ServerConfig=$server; Sessions=$sessions }
"""

# Principals that make a share readable by anyone who can reach the host.
EVERYONE_PRINCIPALS = {
    "everyone",
    "builtin\\users",
    "nt authority\\authenticated users",
    "authenticated users",
    "anonymous logon",
    "nt authority\\anonymous logon",
    "guests",
    "builtin\\guests",
}


class SharesCollector(BaseCollector):
    name = "shares"
    category = "network"
    description = "SMB shares, permissions and server protocol configuration"
    profiles = ("quick", "standard", "full", "network", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Get-SmbShare, Get-SmbShareAccess and Get-SmbServerConfiguration"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Share query returned nothing")
            return

        raw = ps.data
        shares = []
        for record in dicts(get(raw, "Shares")):
            access = []
            for entry in dicts(get(record, "Access")):
                account = text(get(entry, "AccountName"))
                access.append(
                    {
                        "account": account,
                        "right": text(get(entry, "AccessRight")),
                        "type": text(get(entry, "AccessControlType")),
                    }
                )
            name = text(get(record, "Name"))
            special = bool(get(record, "Special")) or name.endswith("$")
            broad = [
                a
                for a in access
                if a["account"].lower() in EVERYONE_PRINCIPALS
                and a["type"].lower() == "allow"
            ]
            shares.append(
                {
                    "name": name,
                    "path": text(get(record, "Path")),
                    "description": text(get(record, "Description")),
                    "share_type": text(get(record, "ShareType")),
                    "state": text(get(record, "ShareState")),
                    "administrative": special,
                    "encrypt_data": boolean(get(record, "EncryptData"), False),
                    "folder_enumeration_mode": text(
                        get(record, "FolderEnumerationMode")
                    ),
                    "current_users": integer(get(record, "CurrentUsers"), 0),
                    "access": access,
                    "broad_access": broad,
                    "world_accessible": bool(broad) and not special,
                    "source": text(get(record, "Source")),
                }
            )

        config = get(raw, "ServerConfig") or {}
        user_shares = [s for s in shares if not s["administrative"]]

        result.data = {
            "shares": shares,
            "share_count": len(shares),
            "user_shares": user_shares,
            "user_share_count": len(user_shares),
            "administrative_shares": [s for s in shares if s["administrative"]],
            "world_accessible_shares": [s for s in shares if s["world_accessible"]],
            "unencrypted_shares": [
                s for s in user_shares if not s["encrypt_data"]
            ],
            "server_configuration": {
                "smb1_enabled": boolean(get(config, "EnableSMB1Protocol"), None),
                "smb2_enabled": boolean(get(config, "EnableSMB2Protocol"), None),
                "signing_required": boolean(
                    get(config, "RequireSecuritySignature"), None
                ),
                "signing_enabled": boolean(
                    get(config, "EnableSecuritySignature"), None
                ),
                "encryption_enabled": boolean(get(config, "EncryptData"), None),
                "rejects_unencrypted_access": boolean(
                    get(config, "RejectUnencryptedAccess"), None
                ),
                "auto_share_workstation": boolean(
                    get(config, "AutoShareWorkstation"), None
                ),
            },
            "active_sessions": [
                {
                    "client": text(get(record, "ClientComputerName")),
                    "user": text(get(record, "ClientUserName")),
                    "open_files": integer(get(record, "NumOpens"), 0),
                    "dialect": text(get(record, "Dialect")),
                }
                for record in dicts(get(raw, "Sessions"))
            ],
        }

        if not shares:
            result.warn("No SMB shares were reported on this host.")
