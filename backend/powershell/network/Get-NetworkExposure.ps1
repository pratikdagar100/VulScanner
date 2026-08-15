<#
.SYNOPSIS
    VulScanner - network exposure snapshot.

.DESCRIPTION
    Read-only collection of network adapters, listening TCP/UDP endpoints with
    their owning processes, SMB shares and the neighbour cache.

    Nothing is modified. No scanning of other hosts is performed by this script;
    it reports only what this machine exposes and what it has already talked to.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-NetworkExposure.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Adapters {
    try {
        Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $index = $_.ifIndex
            $addresses = @()
            try {
                $addresses = Get-NetIPAddress -InterfaceIndex $index -ErrorAction Stop |
                    ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }
            } catch { }
            [pscustomobject]@{
                Name        = $_.Name
                Description = $_.InterfaceDescription
                MacAddress  = $_.MacAddress
                LinkSpeed   = $_.LinkSpeed
                Addresses   = @($addresses)
            }
        }
    } catch {
        @()
    }
}

function Get-ListeningEndpoints {
    $processes = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $processes[[int]$_.ProcessId] = $_.Name
        }
    } catch { }

    $endpoints = New-Object System.Collections.ArrayList

    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [void]$endpoints.Add([pscustomobject]@{
                Protocol     = 'tcp'
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                ProcessId    = $_.OwningProcess
                ProcessName  = $processes[[int]$_.OwningProcess]
            })
        }
    } catch { }

    try {
        Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [void]$endpoints.Add([pscustomobject]@{
                Protocol     = 'udp'
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                ProcessId    = $_.OwningProcess
                ProcessName  = $processes[[int]$_.OwningProcess]
            })
        }
    } catch { }

    , $endpoints
}

function Get-Shares {
    try {
        Get-SmbShare -ErrorAction Stop | ForEach-Object {
            $access = @()
            try {
                $access = Get-SmbShareAccess -Name $_.Name -ErrorAction Stop | ForEach-Object {
                    "$($_.AccountName):$($_.AccessRight):$($_.AccessControlType)"
                }
            } catch { }
            [pscustomobject]@{
                Name        = $_.Name
                Path        = $_.Path
                Description = $_.Description
                Special     = $_.Special
                EncryptData = $_.EncryptData
                Access      = @($access)
            }
        }
    } catch {
        @()
    }
}

function Get-Neighbours {
    try {
        Get-NetNeighbor -ErrorAction Stop |
            Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' } |
            ForEach-Object {
                [pscustomobject]@{
                    IPAddress        = $_.IPAddress
                    LinkLayerAddress = $_.LinkLayerAddress
                    State            = [string]$_.State
                    InterfaceAlias   = $_.InterfaceAlias
                }
            }
    } catch {
        @()
    }
}

$result = [pscustomobject]@{
    Collector           = 'network-exposure'
    CollectedAt         = (Get-Date).ToUniversalTime().ToString('o')
    ScannerHost         = $env:COMPUTERNAME
    Adapters            = @(Get-Adapters)
    ListeningEndpoints  = @(Get-ListeningEndpoints)
    Shares              = @(Get-Shares)
    NeighbourCache      = @(Get-Neighbours)
}

$result | ConvertTo-Json -Depth 6 -Compress
