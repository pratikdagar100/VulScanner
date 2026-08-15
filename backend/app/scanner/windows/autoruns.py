"""Autorun / persistence-location inventory.

Discovered executables are inspected as files only - VulScanner never launches
anything it finds.
"""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, iso, text

SCRIPT = r"""
$items = New-Object System.Collections.ArrayList

$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
  try {
    $props = Get-ItemProperty $key -ErrorAction Stop
    foreach ($p in $props.PSObject.Properties) {
      if ($p.Name -notmatch '^PS' -and $p.Value) {
        [void]$items.Add([pscustomobject]@{
          Location=$key; Kind='registry-run'; Name=$p.Name; Command=[string]$p.Value
        })
      }
    }
  } catch {}
}

foreach ($folder in @(
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
  "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
  if (Test-Path $folder) {
    Get-ChildItem $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
      [void]$items.Add([pscustomobject]@{
        Location=$folder; Kind='startup-folder'; Name=$_.Name; Command=$_.FullName
      })
    }
  }
}

# Services with a non-standard binary path and automatic start.
try {
  Get-CimInstance Win32_Service -ErrorAction Stop |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } |
    ForEach-Object {
      [void]$items.Add([pscustomobject]@{
        Location='Win32_Service'; Kind='service'; Name=$_.Name; Command=$_.PathName
        State=$_.State; StartName=$_.StartName
      })
    }
} catch {}

# Scheduled tasks that run at logon or boot.
try {
  Get-ScheduledTask -ErrorAction Stop |
    Where-Object { $_.State -ne 'Disabled' -and ($_.Triggers | Where-Object {
        $_.CimClass.CimClassName -match 'LogonTrigger|BootTrigger' }) } |
    ForEach-Object {
      $action = ($_.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
      if ($action) {
        [void]$items.Add([pscustomobject]@{
          Location=$_.TaskPath; Kind='scheduled-task'; Name=$_.TaskName
          Command=("{0} {1}" -f $action.Execute, $action.Arguments).Trim()
          StartName=$_.Principal.UserId
        })
      }
    }
} catch {}

# Resolve each command to a file and read its signature metadata (read-only).
$resolved = foreach ($item in $items) {
  $cmd = [string]$item.Command
  $path = $null
  if ($cmd -match '^"([^"]+)"') { $path = $matches[1] }
  elseif ($cmd -match '^([^\s]+\.(exe|dll|bat|cmd|ps1|vbs|js|scr))') { $path = $matches[1] }
  else { $path = ($cmd -split '\s+')[0] }
  if ($path) { $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"')) }

  $exists = $false; $sigStatus = $null; $signer = $null; $size = $null; $modified = $null
  if ($path -and (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue)) {
    $exists = $true
    try {
      $f = Get-Item -LiteralPath $path -ErrorAction Stop
      $size = $f.Length; $modified = $f.LastWriteTimeUtc
      $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
      $sigStatus = [string]$sig.Status
      if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
    } catch {}
  }

  [pscustomobject]@{
    Location=$item.Location; Kind=$item.Kind; Name=$item.Name; Command=$cmd
    Path=$path; Exists=$exists; SignatureStatus=$sigStatus; Signer=$signer
    Size=$size; Modified=$modified; State=$item.State; StartName=$item.StartName
  }
}
,@($resolved)
"""

# Directories that are user-writable and therefore weak locations for autoruns.
WRITABLE_LOCATIONS = re.compile(
    r"(\\users\\|\\appdata\\|\\temp\\|\\downloads\\|\\public\\|\\programdata\\)",
    re.IGNORECASE,
)

CN_PATTERN = re.compile(r"CN=([^,]+)")


def extract_publisher(subject: str) -> str:
    match = CN_PATTERN.search(subject or "")
    return match.group(1).strip() if match else (subject or "").strip()


class AutorunsCollector(BaseCollector):
    name = "autoruns"
    category = "windows"
    description = "Autorun locations, services and logon-triggered scheduled tasks"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Run/RunOnce registry keys, Startup folders, auto-start services, "
            "logon/boot scheduled tasks and Get-AuthenticodeSignature"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        entries: list[dict] = []
        for record in dicts(records):
            path = text(get(record, "Path"))
            signature = text(get(record, "SignatureStatus"))
            signer = extract_publisher(text(get(record, "Signer")))
            exists = bool(get(record, "Exists"))

            risk, reasons = self._assess(path, signature, exists, signer)
            entries.append(
                {
                    "location": text(get(record, "Location")),
                    "kind": text(get(record, "Kind")),
                    "name": text(get(record, "Name")),
                    "command": text(get(record, "Command")),
                    "path": path,
                    "exists": exists,
                    "signature_status": signature or "Unknown",
                    "signed": signature == "Valid",
                    "publisher": signer,
                    "size_bytes": integer(get(record, "Size")),
                    "modified": iso(get(record, "Modified")),
                    "run_as": text(get(record, "StartName")),
                    "service_state": text(get(record, "State")),
                    "risk": risk,
                    "risk_reasons": reasons,
                }
            )

        entries.sort(key=lambda e: ({"high": 0, "medium": 1, "low": 2}[e["risk"]], e["name"]))

        result.data = {
            "entries": entries,
            "entry_count": len(entries),
            "by_kind": {
                kind: sum(1 for e in entries if e["kind"] == kind)
                for kind in sorted({e["kind"] for e in entries})
            },
            "unsigned_entries": [e for e in entries if e["exists"] and not e["signed"]],
            "unsigned_count": sum(1 for e in entries if e["exists"] and not e["signed"]),
            "missing_targets": [e for e in entries if e["path"] and not e["exists"]],
            "user_writable_entries": [
                e for e in entries if "user-writable location" in " ".join(e["risk_reasons"])
            ],
            "high_risk_entries": [e for e in entries if e["risk"] == "high"],
        }

        if not entries:
            result.warn("No autorun entries were discovered.")

    # -- helpers -----------------------------------------------------------
    def _assess(
        self, path: str, signature: str, exists: bool, signer: str
    ) -> tuple[str, list[str]]:
        reasons: list[str] = []
        if not path:
            return "low", ["Command could not be resolved to a file path."]
        if not exists:
            reasons.append("Target file does not exist (stale or hijackable entry).")
        if exists and signature != "Valid":
            reasons.append(
                f"Executable is not validly signed (signature status: {signature or 'Unknown'})."
            )
        if WRITABLE_LOCATIONS.search(path):
            reasons.append("Executable resides in a user-writable location.")
        if exists and " " in path and not path.startswith('"') and path.lower().endswith(".exe"):
            # Unquoted path with spaces is only relevant for service entries.
            pass

        if not reasons:
            return "low", [f"Validly signed by {signer}." if signer else "Validly signed."]
        high = sum(
            1
            for reason in reasons
            if "not validly signed" in reason or "user-writable" in reason
        )
        return ("high" if high >= 2 else "medium"), reasons
