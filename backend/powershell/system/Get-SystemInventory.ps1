<#
.SYNOPSIS
    VulScanner - operating system, hardware, patch and software inventory.

.DESCRIPTION
    Read-only collection. Emits a single JSON object describing the host's
    identity, build level, installed updates and installed applications.

    Nothing is modified. No credential material is read.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-SystemInventory.ps1
#>
[CmdletBinding()]
param(
    [int]$MaxApplications = 2000
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-OperatingSystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cv = $null
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    } catch { }

    $build = [int]$os.BuildNumber
    $product = if ($cv) { $cv.ProductName } else { $os.Caption }
    # Windows 11 still reports "Windows 10" in ProductName.
    if ($build -ge 22000 -and $product -match 'Windows 10') {
        $product = $product -replace 'Windows 10', 'Windows 11'
    }

    [pscustomobject]@{
        Hostname        = $cs.Name
        ProductName     = $product
        Caption         = $os.Caption
        Edition         = if ($cv) { $cv.EditionID } else { $null }
        Version         = $os.Version
        Build           = $build
        UBR             = if ($cv) { $cv.UBR } else { $null }
        DisplayVersion  = if ($cv) { $cv.DisplayVersion } else { $null }
        Architecture    = $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBootUpTime  = $os.LastBootUpTime
        Domain          = $cs.Domain
        PartOfDomain    = $cs.PartOfDomain
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        TotalMemoryBytes= $cs.TotalPhysicalMemory
        BiosVersion     = ($bios.BIOSVersion -join ', ')
        BiosReleaseDate = $bios.ReleaseDate
    }
}

function Get-InstalledUpdates {
    try {
        Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                KB          = $_.HotFixID
                Description = $_.Description
                InstalledOn = $_.InstalledOn
                InstalledBy = $_.InstalledBy
            }
        }
    } catch {
        @()
    }
}

function Get-InstalledApplications {
    param([int]$Limit)

    $paths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x64'; Scope = 'machine' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x86'; Scope = 'machine' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Arch = 'x64'; Scope = 'user' }
    )

    $applications = New-Object System.Collections.ArrayList
    foreach ($entry in $paths) {
        try {
            Get-ItemProperty $entry.Path -ErrorAction Stop | ForEach-Object {
                if ($_.DisplayName -and -not $_.SystemComponent -and $applications.Count -lt $Limit) {
                    [void]$applications.Add([pscustomobject]@{
                        Name         = $_.DisplayName
                        Version      = $_.DisplayVersion
                        Publisher    = $_.Publisher
                        InstallDate  = $_.InstallDate
                        Architecture = $entry.Arch
                        Scope        = $entry.Scope
                    })
                }
            }
        } catch { }
    }
    , $applications
}

$result = [pscustomobject]@{
    Collector        = 'system-inventory'
    CollectedAt      = (Get-Date).ToUniversalTime().ToString('o')
    ScannerHost      = $env:COMPUTERNAME
    OperatingSystem  = Get-OperatingSystemInfo
    InstalledUpdates = @(Get-InstalledUpdates)
    Applications     = @(Get-InstalledApplications -Limit $MaxApplications)
}

$result | ConvertTo-Json -Depth 6 -Compress
