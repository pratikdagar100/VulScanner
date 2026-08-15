"""Environment variables and PATH hygiene.

Values that look like secrets are redacted before they leave the collector.
"""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, text

SCRIPT = r"""
$machine = [Environment]::GetEnvironmentVariables('Machine')
$user    = [Environment]::GetEnvironmentVariables('User')

$vars = New-Object System.Collections.ArrayList
foreach ($scope in @(@{N='Machine';V=$machine}, @{N='User';V=$user})) {
  foreach ($k in $scope.V.Keys) {
    [void]$vars.Add([pscustomobject]@{ Scope=$scope.N; Name=$k; Value=[string]$scope.V[$k] })
  }
}

$pathEntries = @()
$rawPath = [Environment]::GetEnvironmentVariable('Path','Machine')
if ($rawPath) {
  $pathEntries = $rawPath -split ';' | Where-Object { $_ } | ForEach-Object {
    $expanded = [Environment]::ExpandEnvironmentVariables($_.Trim())
    $writable = $false
    $exists = Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue
    if ($exists) {
      try {
        $acl = Get-Acl -LiteralPath $expanded -ErrorAction Stop
        foreach ($ace in $acl.Access) {
          if ($ace.AccessControlType -eq 'Allow' -and
              $ace.IdentityReference -match 'Everyone|Users|Authenticated Users|INTERACTIVE' -and
              $ace.FileSystemRights -match 'Write|Modify|FullControl') {
            $writable = $true
          }
        }
      } catch {}
    }
    [pscustomobject]@{ Entry=$_.Trim(); Expanded=$expanded; Exists=$exists; UserWritable=$writable }
  }
}

[pscustomobject]@{ Variables=$vars; PathEntries=$pathEntries; ComputerName=$env:COMPUTERNAME }
"""

SECRET_NAME = re.compile(
    r"(?i)(pass|pwd|secret|token|key|credential|auth|api|conn|sas|jwt|private)"
)
SECRET_VALUE = re.compile(
    r"(?i)(password\s*=|pwd\s*=|api[_-]?key|bearer\s+[a-z0-9._-]{16,}|"
    r"[a-z0-9/+]{40,}={0,2})"
)
REDACTED = "[REDACTED BY VULSCANNER]"

# Environment names that are safe to report verbatim.
SAFE_NAMES = {
    "path", "pathext", "os", "processor_architecture", "processor_identifier",
    "number_of_processors", "computername", "windir", "systemroot", "systemdrive",
    "programfiles", "programdata", "comspec", "temp", "tmp", "username", "userdomain",
    "logonserver", "psmodulepath", "driverdata",
}


class EnvironmentCollector(BaseCollector):
    name = "environment"
    category = "windows"
    description = "Environment variables (secrets redacted) and PATH hygiene"
    profiles = ("standard", "full")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "[Environment]::GetEnvironmentVariables and Get-Acl on PATH entries"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Environment query returned nothing")
            return

        variables = []
        suspected_secrets = []
        for record in dicts(get(ps.data, "Variables")):
            name = text(get(record, "Name"))
            value = text(get(record, "Value"))
            looks_secret = bool(
                name.lower() not in SAFE_NAMES
                and (SECRET_NAME.search(name) or SECRET_VALUE.search(value))
            )
            entry = {
                "scope": text(get(record, "Scope")),
                "name": name,
                "value": REDACTED if looks_secret else value,
                "redacted": looks_secret,
                "length": len(value),
            }
            variables.append(entry)
            if looks_secret:
                suspected_secrets.append(
                    {
                        "scope": entry["scope"],
                        "name": name,
                        "reason": "Variable name or value matches a credential pattern.",
                    }
                )

        path_entries = []
        for record in dicts(get(ps.data, "PathEntries")):
            path_entries.append(
                {
                    "entry": text(get(record, "Entry")),
                    "expanded": text(get(record, "Expanded")),
                    "exists": bool(get(record, "Exists")),
                    "user_writable": bool(get(record, "UserWritable")),
                }
            )

        result.data = {
            "variables": variables,
            "variable_count": len(variables),
            "suspected_secret_variables": suspected_secrets,
            "path_entries": path_entries,
            "path_entry_count": len(path_entries),
            "writable_path_entries": [p for p in path_entries if p["user_writable"]],
            "missing_path_entries": [p for p in path_entries if not p["exists"]],
        }

        if suspected_secrets:
            result.warn(
                f"{len(suspected_secrets)} environment variables look like they hold "
                "credentials. Their values were redacted and never stored."
            )
