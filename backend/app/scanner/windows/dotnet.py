""".NET Framework and .NET (Core) runtime inventory."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

# Release key -> .NET Framework version (Microsoft published mapping).
NDP_RELEASE_MAP: list[tuple[int, str]] = [
    (533320, "4.8.1"), (528040, "4.8"), (461808, "4.7.2"), (461308, "4.7.1"),
    (460798, "4.7"), (394802, "4.6.2"), (394254, "4.6.1"), (393295, "4.6"),
    (379893, "4.5.2"), (378675, "4.5.1"), (378389, "4.5"),
]

SCRIPT = r"""
$results = New-Object System.Collections.ArrayList

try {
  $ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
  [void]$results.Add([pscustomobject]@{
    Kind='framework'; Name='.NET Framework 4.x'; Release=$ndp.Release; Version=$ndp.Version
  })
} catch {}

foreach ($v in @('v2.0.50727','v3.0','v3.5')) {
  try {
    $k = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\$v" -ErrorAction Stop
    if ($k.Install -eq 1) {
      [void]$results.Add([pscustomobject]@{
        Kind='framework'; Name=".NET Framework $v"; Release=$null; Version=$k.Version
      })
    }
  } catch {}
}

# .NET (Core) runtimes are discovered from the shared framework directories so
# no external process needs to be launched.
foreach ($root in @("$env:ProgramFiles\dotnet\shared", "${env:ProgramFiles(x86)}\dotnet\shared")) {
  if (Test-Path $root) {
    Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $family = $_.Name
      Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        [void]$results.Add([pscustomobject]@{
          Kind='runtime'; Name=$family; Release=$null; Version=$_.Name; Path=$_.FullName
        })
      }
    }
  }
}
,$results
"""


class DotNetCollector(BaseCollector):
    name = "dotnet"
    category = "windows"
    description = ".NET Framework and .NET runtime inventory"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        records, ps = self.context.runner.run_list(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "NDP registry keys and dotnet shared framework directories"
        )
        if not ps.ok:
            result.fail(ps.friendly_error())
            return

        frameworks: list[dict] = []
        runtimes: list[dict] = []
        for record in dicts(records):
            kind = text(get(record, "Kind"))
            version = text(get(record, "Version"))
            entry = {
                "name": text(get(record, "Name")),
                "version": version,
                "path": text(get(record, "Path")),
            }
            if kind == "framework":
                release = integer(get(record, "Release"))
                if release:
                    entry["release"] = release
                    entry["version"] = next(
                        (label for key, label in NDP_RELEASE_MAP if release >= key),
                        version,
                    )
                frameworks.append(entry)
            else:
                runtimes.append(entry)

        result.data = {
            "frameworks": frameworks,
            "runtimes": runtimes,
            "framework_count": len(frameworks),
            "runtime_count": len(runtimes),
            "legacy_framework_present": any(
                f["version"].startswith(("2.", "3.")) for f in frameworks
            ),
        }
        if not frameworks and not runtimes:
            result.warn("No .NET installations were detected.")
