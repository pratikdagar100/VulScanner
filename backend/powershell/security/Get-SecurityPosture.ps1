<#
.SYNOPSIS
    VulScanner - Windows security posture snapshot.

.DESCRIPTION
    Read-only collection of Microsoft Defender status, firewall profiles, UAC,
    Remote Desktop configuration, local accounts and boot integrity.

    Nothing is modified, no security product is disabled or reconfigured, and
    no password, hash or private key is read. Where a value requires elevation
    that the session does not have, the field is returned as $null rather than
    guessed.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-SecurityPosture.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefenderStatus {
    $status = $null; $preferences = $null; $errors = @()
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $errors += $_.Exception.Message }
    try { $preferences = Get-MpPreference -ErrorAction Stop } catch { $errors += $_.Exception.Message }
    if (-not $status -and -not $preferences) {
        return [pscustomobject]@{ Installed = $false; Errors = $errors }
    }

    [pscustomobject]@{
        Installed              = $true
        RealTimeProtection     = $status.RealTimeProtectionEnabled
        AntivirusEnabled       = $status.AntivirusEnabled
        BehaviorMonitoring     = $status.BehaviorMonitorEnabled
        TamperProtection       = $status.IsTamperProtected
        SignatureVersion       = $status.AntivirusSignatureVersion
        SignatureLastUpdated   = $status.AntivirusSignatureLastUpdated
        SignaturesOutOfDate    = $status.DefenderSignaturesOutOfDate
        CloudProtectionLevel   = $preferences.MAPSReporting
        ControlledFolderAccess = $preferences.EnableControlledFolderAccess
        ExclusionPaths         = @($preferences.ExclusionPath)
        ExclusionProcesses     = @($preferences.ExclusionProcess)
        AsrRuleCount           = @($preferences.AttackSurfaceReductionRules_Ids).Count
        Errors                 = $errors
    }
}

function Get-FirewallStatus {
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name                  = $_.Name
                Enabled               = [bool]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
                LogBlocked            = [bool]$_.LogBlocked
            }
        }
    } catch {
        @()
    }
}

function Get-UacStatus {
    $key = $null
    try {
        $key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    } catch { }
    [pscustomobject]@{
        EnableLUA                     = $key.EnableLUA
        ConsentPromptBehaviorAdmin    = $key.ConsentPromptBehaviorAdmin
        PromptOnSecureDesktop         = $key.PromptOnSecureDesktop
        LocalAccountTokenFilterPolicy = $key.LocalAccountTokenFilterPolicy
    }
}

function Get-RdpStatus {
    $ts = $null; $rdpTcp = $null
    try { $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop } catch { }
    try {
        $rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
    } catch { }

    [pscustomobject]@{
        Enabled            = ($ts.fDenyTSConnections -eq 0)
        Port               = if ($rdpTcp.PortNumber) { $rdpTcp.PortNumber } else { 3389 }
        NetworkLevelAuth   = ($rdpTcp.UserAuthentication -eq 1)
        SecurityLayer      = $rdpTcp.SecurityLayer
        MinEncryptionLevel = $rdpTcp.MinEncryptionLevel
    }
}

function Get-LocalAccountSummary {
    # Account metadata only. Passwords and hashes are never read.
    try {
        Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name             = $_.Name
                Enabled          = $_.Enabled
                SID              = $_.SID.Value
                PasswordRequired = $_.PasswordRequired
                PasswordLastSet  = $_.PasswordLastSet
                LastLogon        = $_.LastLogon
            }
        }
    } catch {
        @()
    }
}

function Get-BootIntegrity {
    $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }

    $tpm = $null
    try {
        $t = Get-Tpm -ErrorAction Stop
        $tpm = [pscustomobject]@{ Present = $t.TpmPresent; Enabled = $t.TpmEnabled; Ready = $t.TpmReady }
    } catch { }

    $bitlocker = @()
    try {
        $bitlocker = Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                MountPoint       = $_.MountPoint
                VolumeType       = [string]$_.VolumeType
                ProtectionStatus = [string]$_.ProtectionStatus
            }
        }
    } catch { }

    [pscustomobject]@{ SecureBoot = $secureBoot; Tpm = $tpm; BitLocker = @($bitlocker) }
}

$elevated = Test-Elevated
$result = [pscustomobject]@{
    Collector     = 'security-posture'
    CollectedAt   = (Get-Date).ToUniversalTime().ToString('o')
    ScannerHost   = $env:COMPUTERNAME
    Elevated      = $elevated
    Note          = if ($elevated) {
        'Collected with administrative rights.'
    } else {
        'Not elevated - Defender preferences and some policy values may be incomplete.'
    }
    Defender      = Get-DefenderStatus
    Firewall      = @(Get-FirewallStatus)
    Uac           = Get-UacStatus
    Rdp           = Get-RdpStatus
    LocalAccounts = @(Get-LocalAccountSummary)
    BootIntegrity = Get-BootIntegrity
}

$result | ConvertTo-Json -Depth 6 -Compress
