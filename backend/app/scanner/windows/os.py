"""Operating system, hardware, BIOS and boot information (CIM/WMI)."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import get, integer, iso, text

# Windows client build -> marketing version. Used for patch-level reasoning.
WINDOWS_BUILD_MAP: dict[int, str] = {
    19041: "2004", 19042: "20H2", 19043: "21H1", 19044: "21H2", 19045: "22H2",
    22000: "21H2", 22621: "22H2", 22631: "23H2", 26100: "24H2", 26200: "25H2",
}

# Builds that no longer receive security servicing (checked against the OS build).
END_OF_SERVICING_BUILDS: dict[int, str] = {
    19041: "2021-12-14", 19042: "2023-05-09", 19043: "2022-12-13",
    22000: "2023-10-10", 22621: "2024-06-11",
}

SCRIPT = r"""
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$tz  = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue
$cv  = $null
try {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
} catch {}

[pscustomobject]@{
  Caption            = $os.Caption
  Version            = $os.Version
  BuildNumber        = $os.BuildNumber
  UBR                = if ($cv) { $cv.UBR } else { $null }
  DisplayVersion     = if ($cv) { $cv.DisplayVersion } else { $null }
  ReleaseId          = if ($cv) { $cv.ReleaseId } else { $null }
  EditionID          = if ($cv) { $cv.EditionID } else { $null }
  InstallationType   = if ($cv) { $cv.InstallationType } else { $null }
  ProductName        = if ($cv) { $cv.ProductName } else { $null }
  OSArchitecture     = $os.OSArchitecture
  ServicePack        = $os.ServicePackMajorVersion
  InstallDate        = $os.InstallDate
  LastBootUpTime     = $os.LastBootUpTime
  LocalDateTime      = $os.LocalDateTime
  SystemDrive        = $os.SystemDrive
  WindowsDirectory   = $os.WindowsDirectory
  TotalVisibleMemoryKB = $os.TotalVisibleMemorySize
  FreePhysicalMemoryKB = $os.FreePhysicalMemory
  RegisteredUser     = $os.RegisteredUser
  Hostname           = $cs.Name
  Domain             = $cs.Domain
  PartOfDomain       = $cs.PartOfDomain
  Workgroup          = $cs.Workgroup
  DomainRole         = $cs.DomainRole
  Manufacturer       = $cs.Manufacturer
  Model              = $cs.Model
  SystemType         = $cs.SystemType
  TotalPhysicalMemory= $cs.TotalPhysicalMemory
  NumberOfProcessors = $cs.NumberOfProcessors
  BiosManufacturer   = $bios.Manufacturer
  BiosVersion        = ($bios.BIOSVersion -join ', ')
  BiosSerial         = $bios.SerialNumber
  BiosReleaseDate    = $bios.ReleaseDate
  SmbiosVersion      = "$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)"
  CpuName            = $cpu.Name
  CpuCores           = $cpu.NumberOfCores
  CpuLogical         = $cpu.NumberOfLogicalProcessors
  CpuArchitecture    = $cpu.AddressWidth
  TimeZone           = if ($tz) { $tz.Caption } else { $null }
  VirtualMachine     = ($cs.Model -match 'Virtual|VMware|KVM|Xen|Hyper-V')
}
"""

DOMAIN_ROLES = {
    0: "Standalone Workstation",
    1: "Member Workstation",
    2: "Standalone Server",
    3: "Member Server",
    4: "Backup Domain Controller",
    5: "Primary Domain Controller",
}


class OSCollector(BaseCollector):
    name = "os"
    category = "windows"
    description = "Operating system, hardware, BIOS and boot information"
    profiles = ("quick", "standard", "full", "compliance", "network")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=3)
        result.collection_method = self.context.runner.describe_method(
            "Win32_OperatingSystem, Win32_ComputerSystem, Win32_BIOS, CurrentVersion registry"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "No system information returned")
            return

        raw = ps.data
        build = integer(get(raw, "BuildNumber"), 0) or 0
        ubr = integer(get(raw, "UBR"))
        display_version = text(get(raw, "DisplayVersion")) or text(
            get(raw, "ReleaseId")
        ) or WINDOWS_BUILD_MAP.get(build, "")

        product = text(get(raw, "ProductName")) or text(get(raw, "Caption"))
        # Windows 11 keeps ProductName as "Windows 10" in the registry.
        if build >= 22000 and "Windows 10" in product:
            product = product.replace("Windows 10", "Windows 11")

        result.data = {
            "hostname": text(get(raw, "Hostname")),
            "os_name": text(get(raw, "Caption")),
            "product_name": product,
            "edition": text(get(raw, "EditionID")),
            "version": text(get(raw, "Version")),
            "display_version": display_version,
            "build": build,
            "ubr": ubr,
            "full_build": f"{build}.{ubr}" if ubr else str(build),
            "architecture": text(get(raw, "OSArchitecture")),
            "installation_type": text(get(raw, "InstallationType")),
            "service_pack": integer(get(raw, "ServicePack"), 0),
            "install_date": iso(get(raw, "InstallDate")),
            "last_boot": iso(get(raw, "LastBootUpTime")),
            "local_time": iso(get(raw, "LocalDateTime")),
            "uptime_days": None,
            "system_drive": text(get(raw, "SystemDrive")),
            "windows_directory": text(get(raw, "WindowsDirectory")),
            "registered_user": text(get(raw, "RegisteredUser")),
            "domain": text(get(raw, "Domain")),
            "workgroup": text(get(raw, "Workgroup")),
            "part_of_domain": bool(get(raw, "PartOfDomain")),
            "domain_role": DOMAIN_ROLES.get(
                integer(get(raw, "DomainRole"), -1) or -1, "Unknown"
            ),
            "manufacturer": text(get(raw, "Manufacturer")),
            "model": text(get(raw, "Model")),
            "system_type": text(get(raw, "SystemType")),
            "total_physical_memory": integer(get(raw, "TotalPhysicalMemory")),
            "processors": integer(get(raw, "NumberOfProcessors")),
            "cpu": {
                "name": text(get(raw, "CpuName")),
                "cores": integer(get(raw, "CpuCores")),
                "logical_processors": integer(get(raw, "CpuLogical")),
                "address_width": integer(get(raw, "CpuArchitecture")),
            },
            "bios": {
                "manufacturer": text(get(raw, "BiosManufacturer")),
                "version": text(get(raw, "BiosVersion")),
                "release_date": iso(get(raw, "BiosReleaseDate")),
                "smbios_version": text(get(raw, "SmbiosVersion")),
                "serial_present": bool(text(get(raw, "BiosSerial"))),
            },
            "timezone": text(get(raw, "TimeZone")),
            "virtual_machine": bool(get(raw, "VirtualMachine")),
            "supported_build": build in WINDOWS_BUILD_MAP,
            "end_of_servicing": END_OF_SERVICING_BUILDS.get(build),
        }

        boot = get(raw, "LastBootUpTime")
        local = get(raw, "LocalDateTime")
        from app.scanner.util import parse_datetime

        boot_dt, local_dt = parse_datetime(boot), parse_datetime(local)
        if boot_dt and local_dt:
            result.data["uptime_days"] = round(
                (local_dt - boot_dt).total_seconds() / 86400, 2
            )

        if not build:
            result.warn("Windows build number could not be determined.")
