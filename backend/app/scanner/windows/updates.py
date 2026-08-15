"""Windows Update configuration, history and pending updates.

Missing updates are reported only when the Windows Update Agent itself says an
update is applicable and not installed. VulScanner never guesses.
"""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import boolean, dicts, get, integer, iso, text

SCRIPT = r"""
$config = $null
try {
  $au = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction Stop
  $config = [pscustomobject]@{
    AUOptions=$au.AUOptions; NoAutoUpdate=$au.NoAutoUpdate
    LastSuccessTime=$au.LastSuccessTime
  }
} catch {}

$policy = $null
try {
  $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue |
    Select-Object AUOptions, NoAutoUpdate, UseWUServer, ScheduledInstallDay
} catch {}

$service = $null
try {
  $svc = Get-Service wuauserv -ErrorAction Stop
  $service = [pscustomobject]@{ Status=[string]$svc.Status; StartType=[string]$svc.StartType }
} catch {}

$results = $null
$searchError = $null
$history = @()
if (__DEEP__) {
  try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    # Read-only search for applicable, not-yet-installed updates.
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $results = @($search.Updates | ForEach-Object {
      $kbs = @(); foreach ($k in $_.KBArticleIDs) { $kbs += "KB$k" }
      [pscustomobject]@{
        Title=$_.Title
        Severity=$_.MsrcSeverity
        KBs=$kbs
        IsMandatory=$_.IsMandatory
        RebootRequired=$_.RebootRequired
        Categories=@($_.Categories | ForEach-Object { $_.Name })
        SupportUrl=$_.SupportUrl
        Description=$_.Description
      }
    })

    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
      $take = [Math]::Min($count, 50)
      $history = @($searcher.QueryHistory(0, $take) | ForEach-Object {
        [pscustomobject]@{
          Title=$_.Title; Date=$_.Date; ResultCode=$_.ResultCode
          Operation=$_.Operation; HResult=$_.HResult
        }
      })
    }
  } catch { $searchError = $_.Exception.Message }
}

$pendingReboot = $false
foreach ($p in @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
  if (Test-Path $p) { $pendingReboot = $true }
}

[pscustomobject]@{
  Config=$config; Policy=$policy; Service=$service
  Pending=$results; SearchError=$searchError; History=$history
  PendingReboot=$pendingReboot
}
"""

AU_OPTIONS = {
    1: "Never check for updates (not recommended)",
    2: "Notify before download",
    3: "Download automatically, notify before install",
    4: "Install updates automatically",
    5: "Allow local administrator to choose",
}
RESULT_CODES = {
    0: "Not started", 1: "In progress", 2: "Succeeded",
    3: "Succeeded with errors", 4: "Failed", 5: "Aborted",
}
OPERATIONS = {1: "Installation", 2: "Uninstallation"}


class UpdatesCollector(BaseCollector):
    name = "updates"
    category = "windows"
    description = "Windows Update configuration, pending updates and history"
    requires_admin = False
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        # Querying the update agent reaches out to the configured update source
        # and is slow, so it only runs in the deeper profiles.
        deep = self.context.profile in {"full", "compliance"} and bool(
            self.context.option("query_windows_update", True)
        )
        script = SCRIPT.replace("__DEEP__", "$true" if deep else "$false")

        ps = self.context.runner.run(script, depth=5, timeout=max(180, self.context.runner.timeout))
        result.collection_method = self.context.runner.describe_method(
            "Windows Update registry configuration"
            + (" and Microsoft.Update.Session searcher" if deep else "")
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Windows Update query returned nothing")
            return

        raw = ps.data
        config = get(raw, "Config") or {}
        policy = get(raw, "Policy") or {}
        service = get(raw, "Service") or {}

        au_option = integer(get(config, "AUOptions")) or integer(
            get(policy, "AUOptions")
        )

        pending = []
        for record in dicts(get(raw, "Pending")):
            kbs = [text(k).upper() for k in (get(record, "KBs") or []) if text(k)]
            categories = [text(c) for c in (get(record, "Categories") or []) if text(c)]
            pending.append(
                {
                    "title": text(get(record, "Title")),
                    "kbs": kbs,
                    "msrc_severity": text(get(record, "Severity")) or "Unspecified",
                    "mandatory": bool(get(record, "IsMandatory")),
                    "reboot_required": bool(get(record, "RebootRequired")),
                    "categories": categories,
                    "is_security_update": any(
                        "security" in c.lower() for c in categories
                    )
                    or bool(text(get(record, "Severity"))),
                    "support_url": text(get(record, "SupportUrl")),
                }
            )

        history = []
        for record in dicts(get(raw, "History")):
            history.append(
                {
                    "title": text(get(record, "Title")),
                    "date": iso(get(record, "Date")),
                    "operation": OPERATIONS.get(
                        integer(get(record, "Operation"), -1) or -1, "Unknown"
                    ),
                    "result": RESULT_CODES.get(
                        integer(get(record, "ResultCode"), -1) or -1, "Unknown"
                    ),
                }
            )

        search_error = text(get(raw, "SearchError"))
        result.data = {
            "queried_update_agent": deep,
            "automatic_updates": {
                "au_option": au_option,
                "behaviour": AU_OPTIONS.get(au_option or -1, "Not configured"),
                "disabled": boolean(get(config, "NoAutoUpdate"), False)
                or boolean(get(policy, "NoAutoUpdate"), False),
                "uses_wsus": boolean(get(policy, "UseWUServer"), False),
                "last_success": iso(get(config, "LastSuccessTime")),
            },
            "service": {
                "status": text(get(service, "Status")),
                "start_type": text(get(service, "StartType")),
                "disabled": text(get(service, "StartType")).lower() == "disabled",
            },
            "pending_updates": pending,
            "pending_count": len(pending),
            "pending_security_count": sum(1 for u in pending if u["is_security_update"]),
            "pending_critical": [
                u for u in pending if u["msrc_severity"].lower() == "critical"
            ],
            "history": history,
            "failed_installs": [h for h in history if h["result"] == "Failed"],
            "pending_reboot": bool(get(raw, "PendingReboot")),
            "evidence_quality": "windows-update-agent" if deep and not search_error
            else "registry-only",
        }

        if search_error:
            result.degrade(
                "The Windows Update agent search failed, so missing updates could "
                f"not be enumerated: {search_error}"
            )
        elif not deep:
            result.warn(
                "Missing-update enumeration was skipped for this scan profile. Run "
                "the 'full' profile to query the Windows Update agent."
            )
