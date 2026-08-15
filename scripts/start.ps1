<#
.SYNOPSIS
    Starts the VulScanner API and web application.

.DESCRIPTION
    .\scripts\start.ps1                start both, open the browser
    .\scripts\start.ps1 -ApiOnly       API only (headless / server use)
    .\scripts\start.ps1 -Production    bind 0.0.0.0 and serve the built frontend

.PARAMETER ApiOnly
    Do not start the frontend dev server.

.PARAMETER NoBrowser
    Do not open a browser window.

.PARAMETER Production
    Production mode: requires a built frontend and a configured secret key.

.PARAMETER StopExisting
    Stop whatever already holds the API or web port, then start fresh. Use this
    after changing code or when re-launching elevated - a leftover process keeps
    serving the code it loaded at startup.
#>
[CmdletBinding()]
param(
    [switch]$ApiOnly,
    [switch]$NoBrowser,
    [switch]$Production,
    [switch]$StopExisting,
    [int]$ApiPort = 8000,
    [int]$WebPort = 5173
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'

if (-not (Test-Path $Python)) {
    Write-Host "[x] VulScanner is not installed. Run .\scripts\install.ps1 first." -ForegroundColor Red
    exit 1
}

$bindAddress = if ($Production) { '0.0.0.0' } else { '127.0.0.1' }

Write-Host "`n VulScanner" -ForegroundColor Cyan
Write-Host " ----------" -ForegroundColor Cyan
Write-Host "  API            http://localhost:$ApiPort"
Write-Host "  API docs       http://localhost:$ApiPort/api/docs"
if (-not $ApiOnly) { Write-Host "  Web app        http://localhost:$WebPort" }
Write-Host "  Stop           Ctrl+C`n"

if ($Production -and -not (Test-Path (Join-Path $RepoRoot 'frontend\dist\index.html'))) {
    Write-Host "[!] No production frontend build found. Run .\scripts\build.ps1 first." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Refuse to start alongside an existing instance.
#
# Without this check a leftover server keeps the port, the new one fails to
# bind and exits, and the readiness probe below still succeeds - because it is
# answered by the old process. The result is a VulScanner that appears to be
# running while silently serving stale code from a previous session.
# ---------------------------------------------------------------------------
function Get-PortOwner {
    param([int]$Port)
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $listener) { return $null }

    $info = [ordered]@{ Port = $Port; ProcessId = $listener.OwningProcess; Started = $null; Command = '' }
    $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    if ($process) { $info.Started = $process.StartTime }
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
    if ($cim) { $info.Command = $cim.CommandLine }
    [pscustomobject]$info
}

function Assert-PortFree {
    param([int]$Port, [string]$Label)

    $owner = Get-PortOwner -Port $Port
    if (-not $owner) { return }

    if ($StopExisting) {
        Write-Host "[*] Stopping the existing $Label on port $Port (PID $($owner.ProcessId))..." -ForegroundColor Cyan
        try {
            Stop-Process -Id $owner.ProcessId -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            if (Get-PortOwner -Port $Port) { throw 'port still held' }
            Write-Host "    [ok] Stopped." -ForegroundColor Green
            return
        } catch {
            Write-Host "    [x]  Could not stop PID $($owner.ProcessId). If it was started" -ForegroundColor Red
            Write-Host "         elevated, re-run this script as Administrator." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "[x] Port $Port is already in use - VulScanner will not start a second $Label." -ForegroundColor Red
    Write-Host ""
    Write-Host "    Held by PID $($owner.ProcessId)$(if ($owner.Started) { ", started $($owner.Started.ToString('HH:mm:ss'))" })" -ForegroundColor Yellow
    if ($owner.Command) {
        Write-Host "    $($owner.Command.Substring(0, [Math]::Min(100, $owner.Command.Length)))" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "    That process is most likely an earlier VulScanner session. It will keep" -ForegroundColor Yellow
    Write-Host "    answering requests with the code it loaded at startup, so recent changes" -ForegroundColor Yellow
    Write-Host "    and elevation will not apply until it is replaced." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Restart cleanly:   .\scripts\start.ps1 -StopExisting" -ForegroundColor Cyan
    Write-Host "    Or stop it:        Stop-Process -Id $($owner.ProcessId) -Force" -ForegroundColor Cyan
    Write-Host "    Or use new ports:  .\scripts\start.ps1 -ApiPort 8001 -WebPort 5174" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

Assert-PortFree -Port $ApiPort -Label 'API'
if (-not $ApiOnly) { Assert-PortFree -Port $WebPort -Label 'web application' }

$jobs = @()

# Start-Process joins its ArgumentList with spaces and adds no quoting, so any
# path containing a space (C:\Users\First Last\...) would be split into two
# arguments. Quote each one that needs it.
function Format-ProcessArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -match '\s' -and $Value -notmatch '^".*"$') { return '"' + $Value + '"' }
    return $Value
}

# --- API -------------------------------------------------------------------
# uvicorn runs with the backend directory as its working directory, so the
# application package resolves without passing a path at all.
$backendDir = Join-Path $RepoRoot 'backend'
$apiArgs = @(
    '-m', 'uvicorn', 'app.main:app',
    '--host', $bindAddress,
    '--port', $ApiPort
)
if (-not $Production) { $apiArgs += '--reload' }
$apiArgs = $apiArgs | ForEach-Object { Format-ProcessArgument $_ }

Write-Host "[*] Starting the VulScanner API..." -ForegroundColor Cyan
$api = Start-Process -FilePath $Python -ArgumentList $apiArgs `
    -WorkingDirectory $backendDir -PassThru -NoNewWindow
$jobs += $api

# Wait for the API to answer before starting anything that depends on it.
$ready = $false
foreach ($attempt in 1..30) {
    Start-Sleep -Milliseconds 700
    try {
        $response = Invoke-RestMethod "http://127.0.0.1:$ApiPort/api/health" -TimeoutSec 2
        if ($response.status -eq 'ok') { $ready = $true; break }
    } catch { }
}
if ($ready) {
    Write-Host "    [ok] API is responding." -ForegroundColor Green
} else {
    Write-Host "    [!]  API did not answer within 20s - check the console output above." -ForegroundColor Yellow
}

# --- Web application -------------------------------------------------------
if (-not $ApiOnly) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npm) {
        Write-Host "[!] npm was not found; starting the API only." -ForegroundColor Yellow
    } else {
        Write-Host "[*] Starting the web application..." -ForegroundColor Cyan
        $frontendDir = Join-Path $RepoRoot 'frontend'

        if (-not (Test-Path (Join-Path $frontendDir 'node_modules'))) {
            Write-Host "    [!]  frontend dependencies are missing - run .\scripts\install.ps1" -ForegroundColor Yellow
        }

        $script = if ($Production) { 'preview' } else { 'dev' }

        # Get-Command resolves npm to npm.ps1 (or the extensionless shell
        # script) depending on the Node install, and Start-Process cannot
        # execute either - it fails with "%1 is not a valid Win32 application".
        # Use the npm.cmd launcher that sits beside whichever one was found.
        $npmCmd = Join-Path (Split-Path $npm.Source) 'npm.cmd'
        if (-not (Test-Path $npmCmd)) { $npmCmd = $npm.Source }

        $web = Start-Process -FilePath $npmCmd `
            -ArgumentList @('run', $script, '--', '--port', $WebPort) `
            -WorkingDirectory $frontendDir -PassThru -NoNewWindow
        $jobs += $web

        # Wait for the dev server to bind rather than assuming a fixed delay.
        # Vite binds to localhost, which resolves to ::1 first on Windows, so
        # probing 127.0.0.1 would report a false failure.
        $webReady = $false
        foreach ($attempt in 1..30) {
            Start-Sleep -Milliseconds 700
            try {
                $null = Invoke-WebRequest "http://localhost:$WebPort" -TimeoutSec 2 -UseBasicParsing
                $webReady = $true
                break
            } catch { }
        }
        if ($webReady) {
            Write-Host "    [ok] Web application is responding." -ForegroundColor Green
        } else {
            Write-Host "    [!]  Web application did not answer within 20s." -ForegroundColor Yellow
        }
    }
}

if (-not $NoBrowser) {
    $url = if ($ApiOnly) { "http://localhost:$ApiPort/api/docs" } else { "http://localhost:$WebPort" }
    Start-Process $url
}

Write-Host "`n[*] VulScanner is running. Press Ctrl+C to stop.`n" -ForegroundColor Green

try {
    while ($true) {
        Start-Sleep -Seconds 1
        foreach ($job in $jobs) {
            if ($job.HasExited) {
                Write-Host "[!] A VulScanner process exited (code $($job.ExitCode)). Shutting down." -ForegroundColor Yellow
                throw 'process-exited'
            }
        }
    }
} finally {
    Write-Host "`n[*] Stopping VulScanner..." -ForegroundColor Cyan
    foreach ($job in $jobs) {
        if (-not $job.HasExited) {
            Stop-Process -Id $job.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "    [ok] Stopped." -ForegroundColor Green
}
