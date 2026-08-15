"""Installed hotfixes / KB inventory."""

from __future__ import annotations

import re

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, iso, text

SCRIPT = r"""
$hotfixes = @()
try {
  $hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      HotFixID=$_.HotFixID; Description=$_.Description; InstalledOn=$_.InstalledOn
      InstalledBy=$_.InstalledBy; Caption=$_.Caption; Source='Win32_QuickFixEngineering'
    }
  }
} catch {}

# The servicing stack records package state that QFE does not always expose.
$packages = @()
try {
  $packages = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages' -ErrorAction Stop |
    Where-Object { $_.PSChildName -match 'KB\d{6,}' } |
    ForEach-Object {
      $state = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).CurrentState
      [pscustomobject]@{ Package=$_.PSChildName; CurrentState=$state }
    } | Select-Object -First 4000
} catch {}

[pscustomobject]@{ HotFixes=$hotfixes; Packages=$packages }
"""

KB_PATTERN = re.compile(r"KB\d{6,}", re.IGNORECASE)

# CBS package states that mean "installed".
INSTALLED_STATES = {112, 80}


class HotfixesCollector(BaseCollector):
    name = "hotfixes"
    category = "windows"
    description = "Installed Windows hotfixes and servicing packages"
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Win32_QuickFixEngineering and Component Based Servicing package keys"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Hotfix query returned nothing")
            return

        hotfixes = []
        kb_ids: set[str] = set()
        for record in dicts(get(ps.data, "HotFixes")):
            kb = text(get(record, "HotFixID")).upper()
            if not kb:
                continue
            kb_ids.add(kb)
            hotfixes.append(
                {
                    "kb": kb,
                    "description": text(get(record, "Description")),
                    "installed_on": iso(get(record, "InstalledOn")),
                    "installed_by": text(get(record, "InstalledBy")),
                    "source": "Win32_QuickFixEngineering",
                }
            )

        package_kbs: set[str] = set()
        for record in dicts(get(ps.data, "Packages")):
            match = KB_PATTERN.search(text(get(record, "Package")))
            if match:
                package_kbs.add(match.group(0).upper())

        # KBs visible only through the servicing stack (common for cumulative
        # updates on Windows 10/11) are recorded with their weaker evidence.
        for kb in sorted(package_kbs - kb_ids):
            hotfixes.append(
                {
                    "kb": kb,
                    "description": "Servicing stack package",
                    "installed_on": None,
                    "installed_by": "",
                    "source": "component-based-servicing",
                }
            )
            kb_ids.add(kb)

        dated = [h for h in hotfixes if h["installed_on"]]
        latest = max((h["installed_on"] for h in dated), default=None)

        result.data = {
            "hotfixes": sorted(hotfixes, key=lambda h: h["installed_on"] or "", reverse=True),
            "kb_ids": sorted(kb_ids),
            "hotfix_count": len(hotfixes),
            "latest_install_date": latest,
            "security_update_count": sum(
                1 for h in hotfixes if "security" in h["description"].lower()
            ),
        }

        if not hotfixes:
            result.warn(
                "No hotfixes were reported. On Windows 10/11 this can happen when "
                "updates are delivered only as cumulative packages; patch level was "
                "therefore derived from the OS build instead."
            )
