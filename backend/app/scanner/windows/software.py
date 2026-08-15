"""Installed software inventory used for CVE correlation.

Reads the uninstall registry hives rather than Win32_Product, which triggers an
MSI consistency check on every installed package and can take minutes.
"""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, iso, text

SCRIPT = r"""
$paths = @(
  @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='x64'; Scope='machine' },
  @{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='x86'; Scope='machine' },
  @{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch='x64'; Scope='user' }
)

$apps = New-Object System.Collections.ArrayList
foreach ($entry in $paths) {
  try {
    Get-ItemProperty $entry.Path -ErrorAction Stop | ForEach-Object {
      if ($_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName) {
        [void]$apps.Add([pscustomobject]@{
          DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion
          Publisher=$_.Publisher; InstallDate=$_.InstallDate
          InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString
          EstimatedSize=$_.EstimatedSize; Architecture=$entry.Arch; Scope=$entry.Scope
          RegistryKey=$_.PSChildName
        })
      }
    }
  } catch {}
}

# Store / provisioned packages participate in CVE correlation too.
$store = @()
if (__STORE__) {
  try {
    $store = Get-AppxPackage -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        DisplayName=$_.Name; DisplayVersion=$_.Version; Publisher=$_.Publisher
        Architecture=[string]$_.Architecture; Scope='appx'; RegistryKey=$_.PackageFullName
      }
    }
  } catch {}
}

[pscustomobject]@{ Applications=$apps; StoreApps=$store }
"""

# Products whose version string is meaningful to CVE correlation. Everything is
# still inventoried; this only drives the "correlation candidate" flag.
CORRELATION_HINTS = re.compile(
    r"(chrome|firefox|edge|java|jre|jdk|python|node|acrobat|reader|7-zip|winrar|"
    r"vlc|zoom|teams|office|openssl|openssh|putty|filezilla|notepad\+\+|git|"
    r"mysql|postgres|mongodb|apache|nginx|tomcat|wireshark|virtualbox|vmware|"
    r"docker|slack|thunderbird|libreoffice|winscp|teamviewer|anydesk|curl)",
    re.IGNORECASE,
)

MICROSOFT_PUBLISHERS = re.compile(r"microsoft", re.IGNORECASE)


def parse_install_date(value: object) -> str | None:
    """Uninstall keys store dates as ``YYYYMMDD`` strings."""
    raw = text(value)
    if len(raw) == 8 and raw.isdigit():
        return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
    return iso(value)


class SoftwareCollector(BaseCollector):
    name = "software"
    category = "windows"
    description = "Installed application inventory"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        include_store = self.context.profile in {"full", "compliance"}
        # Enumerating Store packages is comparatively slow, so the query is only
        # emitted for the deeper profiles.
        script = SCRIPT.replace("__STORE__", "$true" if include_store else "$false")

        ps = self.context.runner.run(script, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Uninstall registry hives (HKLM 64/32-bit, HKCU)"
            + (" and Get-AppxPackage" if include_store else "")
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Software inventory returned nothing")
            return

        applications: list[dict] = []
        seen: set[tuple[str, str]] = set()

        records = dicts(get(ps.data, "Applications"))
        if include_store:
            records += dicts(get(ps.data, "StoreApps"))

        for record in records:
            name = text(get(record, "DisplayName"))
            version = text(get(record, "DisplayVersion"))
            if not name:
                continue
            key = (name.lower(), version.lower())
            if key in seen:
                continue
            seen.add(key)

            publisher = text(get(record, "Publisher"))
            applications.append(
                {
                    "name": name,
                    "version": version,
                    "publisher": publisher,
                    "architecture": text(get(record, "Architecture")),
                    "scope": text(get(record, "Scope")),
                    "install_date": parse_install_date(get(record, "InstallDate")),
                    "install_location": text(get(record, "InstallLocation")),
                    "estimated_size_kb": integer(get(record, "EstimatedSize")),
                    "registry_key": text(get(record, "RegistryKey")),
                    "correlation_candidate": bool(
                        version and CORRELATION_HINTS.search(name)
                    ),
                    "microsoft_product": bool(MICROSOFT_PUBLISHERS.search(publisher)),
                }
            )

        applications.sort(key=lambda a: a["name"].lower())
        no_version = [a["name"] for a in applications if not a["version"]]

        result.data = {
            "applications": applications,
            "application_count": len(applications),
            "correlation_candidates": [
                a for a in applications if a["correlation_candidate"]
            ],
            "publishers": sorted(
                {a["publisher"] for a in applications if a["publisher"]}
            ),
            "missing_version_count": len(no_version),
            "store_apps_included": include_store,
        }

        if no_version:
            result.warn(
                f"{len(no_version)} applications report no version string and cannot "
                "participate in CVE correlation."
            )
        if not applications:
            result.warn("No installed applications were found in the uninstall hives.")
