"""Secure Boot, TPM, BitLocker, virtualization-based security and Credential Guard."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import as_list, dicts, get, integer, text

SCRIPT = r"""
$secureBoot = $null; $secureBootError = $null
try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBootError = $_.Exception.Message }

$firmware = $null
try { $firmware = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop).PEFirmwareType } catch {}

$tpm = $null
try {
  $t = Get-Tpm -ErrorAction Stop
  $tpm = [pscustomobject]@{
    Present=$t.TpmPresent; Ready=$t.TpmReady; Enabled=$t.TpmEnabled
    Activated=$t.TpmActivated; Owned=$t.TpmOwned
    ManufacturerVersion=$t.ManufacturerVersion; ManufacturerIdTxt=$t.ManufacturerIdTxt
  }
} catch {
  try {
    $w = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
    $tpm = [pscustomobject]@{
      Present=$true; Enabled=$w.IsEnabled_InitialValue; Activated=$w.IsActivated_InitialValue
      Owned=$w.IsOwned_InitialValue; SpecVersion=$w.SpecVersion; ManufacturerVersion=$w.ManufacturerVersion
    }
  } catch {}
}

$dg = $null
try {
  $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured,
                  SecurityServicesRunning, CodeIntegrityPolicyEnforcementStatus,
                  RequiredSecurityProperties, AvailableSecurityProperties
} catch {}

$bitlocker = @()
try {
  $bitlocker = Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      MountPoint=$_.MountPoint; VolumeType=[string]$_.VolumeType
      ProtectionStatus=[string]$_.ProtectionStatus; EncryptionPercentage=$_.EncryptionPercentage
      EncryptionMethod=[string]$_.EncryptionMethod
      KeyProtector=@($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
    }
  }
} catch {}

[pscustomobject]@{
  SecureBoot=$secureBoot; SecureBootError=$secureBootError; FirmwareType=$firmware
  Tpm=$tpm; DeviceGuard=$dg; BitLocker=$bitlocker
}
"""

VBS_STATUS = {0: "Not enabled", 1: "Enabled but not running", 2: "Running"}
SECURITY_SERVICES = {
    1: "Credential Guard",
    2: "Hypervisor-Enforced Code Integrity",
    3: "System Guard Secure Launch",
    4: "SMM Firmware Measurement",
}
CI_ENFORCEMENT = {0: "Off", 1: "Audit mode", 2: "Enforced"}
FIRMWARE_TYPES = {1: "BIOS (legacy)", 2: "UEFI", 3: "Max"}


class SecureBootCollector(BaseCollector):
    name = "secure_boot"
    category = "windows"
    description = "Secure Boot, TPM, BitLocker and virtualization-based security"
    requires_admin = True
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=5)
        result.collection_method = self.context.runner.describe_method(
            "Confirm-SecureBootUEFI, Get-Tpm, Win32_DeviceGuard and Get-BitLockerVolume"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Boot integrity query returned nothing")
            return

        raw = ps.data
        secure_boot = get(raw, "SecureBoot")
        secure_boot_error = text(get(raw, "SecureBootError"))
        firmware = integer(get(raw, "FirmwareType"))

        tpm = get(raw, "Tpm") or {}
        device_guard = get(raw, "DeviceGuard") or {}
        services_running = [
            SECURITY_SERVICES.get(integer(s) or -1, f"Unknown ({s})")
            for s in as_list(get(device_guard, "SecurityServicesRunning"))
        ]
        services_configured = [
            SECURITY_SERVICES.get(integer(s) or -1, f"Unknown ({s})")
            for s in as_list(get(device_guard, "SecurityServicesConfigured"))
        ]

        volumes = []
        for record in dicts(get(raw, "BitLocker")):
            volumes.append(
                {
                    "mount_point": text(get(record, "MountPoint")),
                    "volume_type": text(get(record, "VolumeType")),
                    "protection_status": text(get(record, "ProtectionStatus")),
                    "encryption_percentage": integer(
                        get(record, "EncryptionPercentage")
                    ),
                    "encryption_method": text(get(record, "EncryptionMethod")),
                    "key_protectors": [
                        text(k) for k in as_list(get(record, "KeyProtector"))
                    ],
                }
            )
        os_volume = next(
            (v for v in volumes if v["volume_type"].lower() == "operatingsystem"), None
        )

        # Confirm-SecureBootUEFI only succeeds on UEFI firmware, so a readable
        # Secure Boot state is itself proof of UEFI when PEFirmwareType is absent.
        uefi = firmware == 2 or (firmware is None and secure_boot is not None)

        result.data = {
            "secure_boot_enabled": bool(secure_boot) if secure_boot is not None else None,
            "secure_boot_supported": not bool(secure_boot_error),
            "firmware_type": FIRMWARE_TYPES.get(
                firmware or -1, "UEFI (inferred)" if uefi else "Unknown"
            ),
            "uefi": uefi,
            "tpm": {
                "present": bool(get(tpm, "Present")),
                "enabled": bool(get(tpm, "Enabled")),
                "activated": bool(get(tpm, "Activated")),
                "ready": bool(get(tpm, "Ready")),
                "owned": bool(get(tpm, "Owned")),
                "spec_version": text(get(tpm, "SpecVersion")),
                "manufacturer": text(get(tpm, "ManufacturerIdTxt")),
            },
            "device_guard": {
                "vbs_status": VBS_STATUS.get(
                    integer(get(device_guard, "VirtualizationBasedSecurityStatus"), -1)
                    or -1,
                    "Unknown",
                ),
                "services_configured": services_configured,
                "services_running": services_running,
                "credential_guard_running": "Credential Guard" in services_running,
                "hvci_running": "Hypervisor-Enforced Code Integrity" in services_running,
                "code_integrity_policy": CI_ENFORCEMENT.get(
                    integer(
                        get(device_guard, "CodeIntegrityPolicyEnforcementStatus"), -1
                    )
                    or -1,
                    "Unknown",
                ),
            },
            "bitlocker": {
                "volumes": volumes,
                "os_volume_protected": bool(
                    os_volume and os_volume["protection_status"].lower() == "on"
                ),
                "unprotected_volumes": [
                    v["mount_point"]
                    for v in volumes
                    if v["protection_status"].lower() != "on"
                ],
            },
        }

        if secure_boot_error:
            if "not supported" in secure_boot_error.lower():
                result.warn(
                    "Secure Boot state is unavailable: the platform reports a legacy "
                    "BIOS rather than UEFI."
                )
            else:
                result.warn(f"Secure Boot state unavailable: {secure_boot_error}")
        if not tpm:
            result.warn("TPM information was not available on this host.")
