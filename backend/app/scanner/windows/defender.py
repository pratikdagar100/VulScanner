"""Microsoft Defender Antivirus status, preferences and exclusions."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult, CollectorStatus
from app.scanner.util import as_list, boolean, get, integer, iso, number, text

SCRIPT = r"""
$status = $null; $prefs = $null; $statusError = $null; $prefError = $null
try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $statusError = $_.Exception.Message }
try { $prefs  = Get-MpPreference -ErrorAction Stop }     catch { $prefError = $_.Exception.Message }

$tamper = $null
try {
  $tamper = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -ErrorAction Stop).TamperProtection
} catch {}

$policyDisable = $null
try {
  $policyDisable = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction Stop).DisableAntiSpyware
} catch {}

[pscustomobject]@{
  StatusError = $statusError
  PrefError   = $prefError
  AMServiceEnabled          = $status.AMServiceEnabled
  AntispywareEnabled        = $status.AntispywareEnabled
  AntivirusEnabled          = $status.AntivirusEnabled
  RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
  BehaviorMonitorEnabled    = $status.BehaviorMonitorEnabled
  IoavProtectionEnabled     = $status.IoavProtectionEnabled
  OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
  NISEnabled                = $status.NISEnabled
  IsTamperProtected         = $status.IsTamperProtected
  AntivirusSignatureVersion = $status.AntivirusSignatureVersion
  AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
  AntispywareSignatureVersion = $status.AntispywareSignatureVersion
  NISSignatureVersion       = $status.NISSignatureVersion
  AMEngineVersion           = $status.AMEngineVersion
  AMProductVersion          = $status.AMProductVersion
  QuickScanAge              = $status.QuickScanAge
  FullScanAge               = $status.FullScanAge
  QuickScanEndTime          = $status.QuickScanEndTime
  FullScanEndTime           = $status.FullScanEndTime
  ComputerState             = $status.ComputerState
  DefenderSignaturesOutOfDate = $status.DefenderSignaturesOutOfDate

  DisableRealtimeMonitoring = $prefs.DisableRealtimeMonitoring
  DisableBehaviorMonitoring = $prefs.DisableBehaviorMonitoring
  DisableIOAVProtection     = $prefs.DisableIOAVProtection
  DisableScriptScanning     = $prefs.DisableScriptScanning
  DisableArchiveScanning    = $prefs.DisableArchiveScanning
  DisableRemovableDriveScanning = $prefs.DisableRemovableDriveScanning
  MAPSReporting             = $prefs.MAPSReporting
  SubmitSamplesConsent      = $prefs.SubmitSamplesConsent
  CloudBlockLevel           = $prefs.CloudBlockLevel
  PUAProtection             = $prefs.PUAProtection
  EnableControlledFolderAccess = $prefs.EnableControlledFolderAccess
  EnableNetworkProtection   = $prefs.EnableNetworkProtection
  SignatureUpdateInterval   = $prefs.SignatureUpdateInterval
  ExclusionPath             = @($prefs.ExclusionPath)
  ExclusionExtension        = @($prefs.ExclusionExtension)
  ExclusionProcess          = @($prefs.ExclusionProcess)
  ExclusionIpAddress        = @($prefs.ExclusionIpAddress)
  ControlledFolderAccessAllowedApplications = @($prefs.ControlledFolderAccessAllowedApplications)
  AttackSurfaceReductionRules_Ids = @($prefs.AttackSurfaceReductionRules_Ids)
  AttackSurfaceReductionRules_Actions = @($prefs.AttackSurfaceReductionRules_Actions)

  TamperProtectionRegistry  = $tamper
  PolicyDisableAntiSpyware  = $policyDisable
}
"""

MAPS_LEVELS = {0: "Disabled", 1: "Basic", 2: "Advanced"}
SUBMIT_LEVELS = {
    0: "Always prompt",
    1: "Send safe samples automatically",
    2: "Never send",
    3: "Send all samples automatically",
}
CFA_STATES = {0: "Disabled", 1: "Enabled", 2: "Audit mode", 3: "Block disk modification", 4: "Audit disk modification"}
PUA_STATES = {0: "Disabled", 1: "Enabled (block)", 2: "Audit mode"}
CLOUD_BLOCK_LEVELS = {0: "Default", 1: "Moderate", 2: "High", 4: "High+", 6: "Zero tolerance"}

# Exclusion paths broad enough that they materially weaken protection.
BROAD_EXCLUSION_PREFIXES = (
    "c:\\", "c:\\users", "c:\\windows", "c:\\program files",
    "c:\\program files (x86)", "c:\\programdata", "c:\\temp", "%systemdrive%",
    "d:\\", "\\",
)


class DefenderCollector(BaseCollector):
    name = "defender"
    category = "windows"
    description = "Microsoft Defender Antivirus status, preferences and exclusions"
    requires_admin = True
    profiles = ("quick", "standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "Get-MpComputerStatus, Get-MpPreference and Windows Defender registry keys"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            if ps.is_not_found:
                result.status = CollectorStatus.SKIPPED
                result.data = {"installed": False}
                result.warnings.append(
                    "Microsoft Defender cmdlets are unavailable; Defender is likely "
                    "not installed or is replaced by a third-party product."
                )
                return
            result.fail(ps.friendly_error() or "Defender query returned nothing")
            return

        raw = ps.data
        status_error = text(get(raw, "StatusError"))
        pref_error = text(get(raw, "PrefError"))

        exclusions = {
            "paths": [text(p) for p in as_list(get(raw, "ExclusionPath")) if text(p)],
            "extensions": [
                text(p) for p in as_list(get(raw, "ExclusionExtension")) if text(p)
            ],
            "processes": [
                text(p) for p in as_list(get(raw, "ExclusionProcess")) if text(p)
            ],
            "ip_addresses": [
                text(p) for p in as_list(get(raw, "ExclusionIpAddress")) if text(p)
            ],
        }
        broad = [
            path
            for path in exclusions["paths"]
            if path.lower().rstrip("\\*").strip() in
            {p.rstrip("\\") for p in BROAD_EXCLUSION_PREFIXES}
            or path.lower().rstrip("\\* ") in ("c:", "d:")
        ]

        asr_ids = [text(i) for i in as_list(get(raw, "AttackSurfaceReductionRules_Ids"))]
        asr_actions = [
            integer(a) for a in as_list(get(raw, "AttackSurfaceReductionRules_Actions"))
        ]

        result.data = {
            "installed": True,
            "service_enabled": boolean(get(raw, "AMServiceEnabled")),
            "antivirus_enabled": boolean(get(raw, "AntivirusEnabled")),
            "antispyware_enabled": boolean(get(raw, "AntispywareEnabled")),
            "real_time_protection": boolean(get(raw, "RealTimeProtectionEnabled")),
            "behavior_monitoring": boolean(get(raw, "BehaviorMonitorEnabled")),
            "ioav_protection": boolean(get(raw, "IoavProtectionEnabled")),
            "on_access_protection": boolean(get(raw, "OnAccessProtectionEnabled")),
            "network_inspection": boolean(get(raw, "NISEnabled")),
            "tamper_protection": boolean(
                get(raw, "IsTamperProtected"),
                default=(integer(get(raw, "TamperProtectionRegistry")) == 5)
                if get(raw, "TamperProtectionRegistry") is not None
                else None,
            ),
            "signatures": {
                "antivirus_version": text(get(raw, "AntivirusSignatureVersion")),
                "antispyware_version": text(get(raw, "AntispywareSignatureVersion")),
                "nis_version": text(get(raw, "NISSignatureVersion")),
                "last_updated": iso(get(raw, "AntivirusSignatureLastUpdated")),
                "out_of_date": boolean(get(raw, "DefenderSignaturesOutOfDate"), False),
                "engine_version": text(get(raw, "AMEngineVersion")),
                "product_version": text(get(raw, "AMProductVersion")),
            },
            "scans": {
                "quick_scan_age_days": integer(get(raw, "QuickScanAge")),
                "full_scan_age_days": integer(get(raw, "FullScanAge")),
                "last_quick_scan": iso(get(raw, "QuickScanEndTime")),
                "last_full_scan": iso(get(raw, "FullScanEndTime")),
            },
            "cloud_protection": {
                "maps_reporting": MAPS_LEVELS.get(
                    integer(get(raw, "MAPSReporting"), -1) or -1, "Unknown"
                ),
                "maps_raw": integer(get(raw, "MAPSReporting")),
                "sample_submission": SUBMIT_LEVELS.get(
                    integer(get(raw, "SubmitSamplesConsent"), -1) or -1, "Unknown"
                ),
                "cloud_block_level": CLOUD_BLOCK_LEVELS.get(
                    integer(get(raw, "CloudBlockLevel"), -1) or -1, "Unknown"
                ),
            },
            "features": {
                "controlled_folder_access": CFA_STATES.get(
                    integer(get(raw, "EnableControlledFolderAccess"), -1) or -1,
                    "Unknown",
                ),
                "network_protection": CFA_STATES.get(
                    integer(get(raw, "EnableNetworkProtection"), -1) or -1, "Unknown"
                ),
                "pua_protection": PUA_STATES.get(
                    integer(get(raw, "PUAProtection"), -1) or -1, "Unknown"
                ),
                "script_scanning_disabled": boolean(
                    get(raw, "DisableScriptScanning"), False
                ),
                "archive_scanning_disabled": boolean(
                    get(raw, "DisableArchiveScanning"), False
                ),
                "removable_drive_scanning_disabled": boolean(
                    get(raw, "DisableRemovableDriveScanning"), False
                ),
            },
            "asr_rules": [
                {"id": rule_id, "action": action}
                for rule_id, action in zip(asr_ids, asr_actions)
            ],
            "asr_rule_count": len(asr_ids),
            "exclusions": exclusions,
            "exclusion_count": sum(len(v) for v in exclusions.values()),
            "broad_exclusions": broad,
            "policy_disable_antispyware": boolean(
                get(raw, "PolicyDisableAntiSpyware"), False
            ),
            "signature_update_interval_hours": number(
                get(raw, "SignatureUpdateInterval")
            ),
        }

        if status_error:
            result.degrade(f"Get-MpComputerStatus failed: {status_error}")
        if pref_error:
            result.degrade(f"Get-MpPreference failed: {pref_error}")
        if not self.context.runner.is_elevated():
            result.warn(
                "Not running elevated: Defender exclusions and preferences may be "
                "incomplete."
            )
