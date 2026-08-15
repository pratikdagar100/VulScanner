"""Sysmon presence, service state and configuration metadata."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

SCRIPT = r"""
$services = @()
try {
  $services = Get-CimInstance Win32_Service -ErrorAction Stop |
    Where-Object { $_.Name -match '^Sysmon' } |
    ForEach-Object {
      [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; State=$_.State
                         StartMode=$_.StartMode; PathName=$_.PathName }
    }
} catch {}

$driver = $null
try {
  $d = Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
       Where-Object { $_.Name -match 'SysmonDrv' } | Select-Object -First 1
  if ($d) { $driver = [pscustomobject]@{ Name=$d.Name; State=$d.State; StartMode=$d.StartMode } }
} catch {}

$config = $null
foreach ($p in @('HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64\Parameters',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters')) {
  try {
    $k = Get-ItemProperty $p -ErrorAction Stop
    $config = [pscustomobject]@{
      Path=$p
      HashingAlgorithm=$k.HashingAlgorithm
      CheckRevocation=$k.CheckRevocation
      ConfigHash=$k.ConfigHash
      # Rules are a binary blob; only its size is recorded.
      RulesSize=if ($k.Rules) { $k.Rules.Length } else { 0 }
    }
    break
  } catch {}
}

$log = $null
try {
  $l = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $log = [pscustomobject]@{
    IsEnabled=$l.IsEnabled; RecordCount=$l.RecordCount
    MaximumSizeInBytes=$l.MaximumSizeInBytes; LogMode=[string]$l.LogMode
  }
} catch {}

$binary = $null
foreach ($candidate in @("$env:SystemRoot\Sysmon64.exe", "$env:SystemRoot\Sysmon.exe")) {
  if (Test-Path $candidate) {
    $f = Get-Item $candidate
    $sig = Get-AuthenticodeSignature $candidate -ErrorAction SilentlyContinue
    $binary = [pscustomobject]@{
      Path=$candidate; Version=$f.VersionInfo.FileVersion
      SignatureStatus=[string]$sig.Status; Signer=$sig.SignerCertificate.Subject
    }
    break
  }
}

[pscustomobject]@{ Services=$services; Driver=$driver; Config=$config; Log=$log; Binary=$binary }
"""


class SysmonCollector(BaseCollector):
    name = "sysmon"
    category = "windows"
    description = "Sysmon installation, service state and configuration metadata"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Win32_Service, SysmonDrv driver state, Sysmon parameter registry keys "
            "and the Sysmon operational log"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Sysmon query returned nothing")
            return

        raw = ps.data
        services = [
            {
                "name": text(get(record, "Name")),
                "display_name": text(get(record, "DisplayName")),
                "state": text(get(record, "State")),
                "start_mode": text(get(record, "StartMode")),
                "path": text(get(record, "PathName")),
            }
            for record in dicts(get(raw, "Services"))
        ]
        driver = get(raw, "Driver") or {}
        config = get(raw, "Config") or {}
        log = get(raw, "Log") or {}
        binary = get(raw, "Binary") or {}

        running = any(s["state"].lower() == "running" for s in services)
        installed = bool(services or binary or driver)

        result.data = {
            "installed": installed,
            "running": running,
            "services": services,
            "driver": {
                "name": text(get(driver, "Name")),
                "state": text(get(driver, "State")),
                "start_mode": text(get(driver, "StartMode")),
            },
            "binary": {
                "path": text(get(binary, "Path")),
                "version": text(get(binary, "Version")),
                "signature_status": text(get(binary, "SignatureStatus")),
                "signer": text(get(binary, "Signer")),
            },
            "configuration": {
                "registry_path": text(get(config, "Path")),
                "hashing_algorithm": text(get(config, "HashingAlgorithm")),
                "check_revocation": bool(get(config, "CheckRevocation")),
                "config_hash": text(get(config, "ConfigHash")),
                "rules_size_bytes": integer(get(config, "RulesSize"), 0),
                "rules_configured": (integer(get(config, "RulesSize"), 0) or 0) > 0,
            },
            "operational_log": {
                "enabled": bool(get(log, "IsEnabled")),
                "record_count": integer(get(log, "RecordCount")),
                "max_size_bytes": integer(get(log, "MaximumSizeInBytes")),
                "mode": text(get(log, "LogMode")),
            },
        }

        if not installed:
            result.data["note"] = (
                "Sysmon is an optional Sysinternals tool. Its absence is not a "
                "vulnerability, but it materially reduces endpoint telemetry."
            )
