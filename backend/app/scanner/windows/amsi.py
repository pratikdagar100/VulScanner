"""AMSI (Antimalware Scan Interface) provider inventory."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, text

SCRIPT = r"""
$providers = @()
try {
  $providers = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction Stop |
    ForEach-Object {
      $clsid = $_.PSChildName
      $server = $null; $name = $null
      try {
        $server = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction Stop).'(default)'
      } catch {}
      try {
        $name = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -ErrorAction Stop).'(default)'
      } catch {}
      $exists = $false
      if ($server) {
        $expanded = [Environment]::ExpandEnvironmentVariables($server)
        $exists = Test-Path $expanded -ErrorAction SilentlyContinue
      }
      [pscustomobject]@{ CLSID=$clsid; Name=$name; Server=$server; ServerExists=$exists }
    }
} catch {}

$amsiDll = $null
try {
  $f = Get-Item "$env:SystemRoot\System32\amsi.dll" -ErrorAction Stop
  $amsiDll = [pscustomobject]@{ Present=$true; Version=$f.VersionInfo.FileVersion; Modified=$f.LastWriteTimeUtc }
} catch { $amsiDll = [pscustomobject]@{ Present=$false } }

[pscustomobject]@{ Providers=$providers; AmsiDll=$amsiDll }
"""

WELL_KNOWN_PROVIDERS = {
    "{2781761e-28e0-4109-99fe-b9d127c57afe}": "Microsoft Defender Antivirus",
    "{a7c452ef-8e9f-42eb-9f2b-245613ca0dc9}": "AMSI sample provider",
}


class AmsiCollector(BaseCollector):
    name = "amsi"
    category = "windows"
    description = "AMSI providers registered on the system"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers and CLSID registration"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "AMSI provider query returned nothing")
            return

        providers = []
        for record in dicts(get(ps.data, "Providers")):
            clsid = text(get(record, "CLSID")).lower()
            providers.append(
                {
                    "clsid": clsid,
                    "name": text(get(record, "Name"))
                    or WELL_KNOWN_PROVIDERS.get(clsid, "Unknown provider"),
                    "server": text(get(record, "Server")),
                    "server_exists": bool(get(record, "ServerExists")),
                    "known": clsid in WELL_KNOWN_PROVIDERS,
                }
            )

        dll = get(ps.data, "AmsiDll") or {}
        result.data = {
            "providers": providers,
            "provider_count": len(providers),
            "defender_provider_registered": any(
                p["clsid"] in WELL_KNOWN_PROVIDERS and "Defender" in p["name"]
                for p in providers
            ),
            "dangling_providers": [
                p for p in providers if p["server"] and not p["server_exists"]
            ],
            "amsi_dll": {
                "present": bool(get(dll, "Present")),
                "version": text(get(dll, "Version")),
            },
        }
        if not providers:
            result.warn(
                "No AMSI providers are registered. Script content is therefore not "
                "submitted to an antimalware engine for inspection."
            )
