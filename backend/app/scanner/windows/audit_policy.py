"""Advanced audit policy and event log configuration."""

from __future__ import annotations

import csv
import io

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, text

# auditpol writes CSV to stdout; we capture it as text rather than JSON.
SCRIPT = r"""
$csv = $null
$err = $null
try {
  $csv = (& auditpol.exe /get /category:* /r 2>&1 | Out-String)
} catch { $err = $_.Exception.Message }

$logs = @()
foreach ($name in @('Security','System','Application','Windows PowerShell',
                    'Microsoft-Windows-PowerShell/Operational',
                    'Microsoft-Windows-Sysmon/Operational',
                    'Microsoft-Windows-Windows Defender/Operational')) {
  try {
    $log = Get-WinEvent -ListLog $name -ErrorAction Stop
    $logs += [pscustomobject]@{
      LogName=$log.LogName; IsEnabled=$log.IsEnabled; MaximumSizeInBytes=$log.MaximumSizeInBytes
      LogMode=[string]$log.LogMode; RecordCount=$log.RecordCount; FileSize=$log.FileSize
    }
  } catch {}
}

[pscustomobject]@{ AuditPolCsv=$csv; AuditPolError=$err; Logs=$logs }
"""

# Subcategories that materially affect blue-team detection capability.
CRITICAL_SUBCATEGORIES = {
    "logon": "Success and Failure",
    "logoff": "Success",
    "account lockout": "Failure",
    "special logon": "Success",
    "process creation": "Success",
    "security group management": "Success",
    "user account management": "Success",
    "audit policy change": "Success",
    "authentication policy change": "Success",
    "credential validation": "Success and Failure",
    "sensitive privilege use": "Success and Failure",
    "other logon/logoff events": "Success",
}


def parse_auditpol_csv(raw: str) -> list[dict]:
    """Parse ``auditpol /r`` CSV output into subcategory records."""
    if not raw or "," not in raw:
        return []
    lines = [line for line in raw.splitlines() if line.strip()]
    header_index = next(
        (i for i, line in enumerate(lines) if "Subcategory" in line and "," in line), None
    )
    if header_index is None:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:])))
    records = []
    for row in reader:
        normalized = { (k or "").strip(): (v or "").strip() for k, v in row.items() }
        subcategory = normalized.get("Subcategory", "")
        setting = normalized.get("Inclusion Setting", "")
        if not subcategory or subcategory.startswith("System audit"):
            continue
        records.append(
            {
                "category": normalized.get("Category/Subcategory", "")
                or normalized.get("Category", ""),
                "subcategory": subcategory,
                "setting": setting or "No Auditing",
                "guid": normalized.get("Subcategory GUID", ""),
                "machine": normalized.get("Machine Name", ""),
            }
        )
    return records


class AuditPolicyCollector(BaseCollector):
    name = "audit_policy"
    category = "windows"
    description = "Advanced audit policy subcategories and event log configuration"
    requires_admin = True
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "auditpol.exe /get /category:* /r and Get-WinEvent -ListLog"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Audit policy query returned nothing")
            return

        raw_csv = text(get(ps.data, "AuditPolCsv"))
        subcategories = parse_auditpol_csv(raw_csv)

        logs = []
        for record in dicts(get(ps.data, "Logs")):
            logs.append(
                {
                    "log_name": text(get(record, "LogName")),
                    "enabled": bool(get(record, "IsEnabled")),
                    "max_size_bytes": integer(get(record, "MaximumSizeInBytes")),
                    "current_size_bytes": integer(get(record, "FileSize")),
                    "mode": text(get(record, "LogMode")),
                    "record_count": integer(get(record, "RecordCount")),
                }
            )

        by_name = {r["subcategory"].lower(): r for r in subcategories}
        gaps = []
        for name, expected in CRITICAL_SUBCATEGORIES.items():
            record = by_name.get(name)
            if record is None:
                continue  # subcategory not present on this build; do not invent a gap
            setting = record["setting"]
            if setting.lower() in ("no auditing", ""):
                gaps.append(
                    {"subcategory": record["subcategory"], "expected": expected,
                     "actual": setting, "severity": "high"}
                )
            elif expected == "Success and Failure" and setting != "Success and Failure":
                gaps.append(
                    {"subcategory": record["subcategory"], "expected": expected,
                     "actual": setting, "severity": "medium"}
                )

        security_log = next((l for l in logs if l["log_name"] == "Security"), None)
        result.data = {
            "subcategories": subcategories,
            "subcategory_count": len(subcategories),
            "audited_count": sum(
                1 for r in subcategories if r["setting"].lower() != "no auditing"
            ),
            "coverage_gaps": gaps,
            "event_logs": logs,
            "security_log": security_log,
            "security_log_small": bool(
                security_log
                and security_log["max_size_bytes"]
                and security_log["max_size_bytes"] < 128 * 1024 * 1024
            ),
        }

        error = text(get(ps.data, "AuditPolError"))
        if error:
            result.degrade(f"auditpol failed: {error}")
        if not subcategories:
            result.warn(
                "Audit policy could not be read. auditpol requires an elevated "
                "session; run VulScanner as Administrator for this collector."
            )
