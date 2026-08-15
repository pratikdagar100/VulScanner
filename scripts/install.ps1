<#
.SYNOPSIS
    Installs VulScanner: verifies prerequisites, creates the Python virtual
    environment, installs dependencies, initialises the database and writes a
    starting configuration.

.DESCRIPTION
    Run from anywhere:  .\scripts\install.ps1
    The script is idempotent - re-running it repairs a partial install.

.PARAMETER SkipFrontend
    Skip the Node/npm frontend install (API and CLI only).

.PARAMETER Force
    Recreate the virtual environment even if one already exists.
#>
[CmdletBinding()]
param(
    [switch]$SkipFrontend,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $RepoRoot '.venv'
$Python = Join-Path $VenvPath 'Scripts\python.exe'

function Write-Step  { param($Message) Write-Host "`n[*] $Message" -ForegroundColor Cyan }
function Write-Ok    { param($Message) Write-Host "    [ok] $Message" -ForegroundColor Green }
function Write-Warn2 { param($Message) Write-Host "    [!]  $Message" -ForegroundColor Yellow }
function Write-Fail  { param($Message) Write-Host "    [x]  $Message" -ForegroundColor Red }

Write-Host @"

 __     __    _ ____
 \ \   / /   | / ___|  ___ __ _ _ __  _ __   ___ _ __
  \ \ / / | | | \___ \ / __/ _`` | '_ \| '_ \ / _ \ '__|
   \ V /| |_| |  ___) | (_| (_| | | | | | | |  __/ |
    \_/  \__,_| |____/ \___\__,_|_| |_|_| |_|\___|_|

  VulScanner installer - agent-less Windows security assessment
"@ -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
Write-Step 'Checking prerequisites'

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) { $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pythonCommand) {
    Write-Fail 'Python was not found on PATH.'
    Write-Host '        Install Python 3.11 or newer from https://www.python.org/downloads/'
    Write-Host '        During setup, tick "Add python.exe to PATH".'
    exit 1
}

$versionText = (& $pythonCommand.Source --version 2>&1) -replace 'Python\s*', ''
$version = [version]($versionText -split '\s')[0]
if ($version -lt [version]'3.11') {
    Write-Fail "Python $version found, but VulScanner needs 3.11 or newer."
    exit 1
}
Write-Ok "Python $version at $($pythonCommand.Source)"

$psVersion = $PSVersionTable.PSVersion
Write-Ok "PowerShell $psVersion"
if ($psVersion.Major -lt 5) {
    Write-Warn2 'Windows PowerShell 5.1 or PowerShell 7+ is required for collection.'
}

if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    Write-Ok 'Windows detected - the full collector set is available.'
} else {
    Write-Warn2 'Not running on Windows. Only network assessment will be available.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Ok 'Running elevated - all collectors can read their data.'
} else {
    Write-Warn2 'Not elevated. Defender preferences, audit policy and the local'
    Write-Warn2 'security policy will be reported as incomplete. Run VulScanner as'
    Write-Warn2 'Administrator for a full assessment.'
}

if (-not $SkipFrontend) {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    $npmCommand  = Get-Command npm  -ErrorAction SilentlyContinue
    if ($nodeCommand -and $npmCommand) {
        Write-Ok "Node $((& node --version)) / npm $((& npm --version))"
    } else {
        Write-Warn2 'Node.js and npm were not found. The web application will be skipped.'
        Write-Warn2 'Install Node 18+ from https://nodejs.org/ and re-run with the frontend.'
        $SkipFrontend = $true
    }
}

# ---------------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------------
Write-Step 'Creating the Python virtual environment'
if ($Force -and (Test-Path $VenvPath)) {
    Remove-Item $VenvPath -Recurse -Force
    Write-Ok 'Removed the existing environment (-Force).'
}
if (-not (Test-Path $Python)) {
    & $pythonCommand.Source -m venv $VenvPath
    Write-Ok "Created $VenvPath"
} else {
    Write-Ok 'Virtual environment already present.'
}

Write-Step 'Installing backend dependencies'
& $Python -m pip install --upgrade pip --quiet
& $Python -m pip install -r (Join-Path $RepoRoot 'backend\requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { Write-Fail 'Dependency installation failed.'; exit 1 }
Write-Ok 'Backend dependencies installed.'

# ---------------------------------------------------------------------------
# 3. Configuration
# ---------------------------------------------------------------------------
Write-Step 'Preparing configuration'
$envFile = Join-Path $RepoRoot '.env'
$envExample = Join-Path $RepoRoot '.env.example'
if (-not (Test-Path $envFile)) {
    Copy-Item $envExample $envFile
    # Generate a signing key so tokens survive a restart.
    $secret = & $Python -c "import secrets; print(secrets.token_urlsafe(64))"
    (Get-Content $envFile) -replace '^VULSCANNER_SECRET_KEY=.*', "VULSCANNER_SECRET_KEY=$secret" |
        Set-Content $envFile -Encoding utf8
    Write-Ok 'Created .env with a generated secret key.'
    Write-Warn2 'Review VULSCANNER_AUTHORIZED_SCOPES before scanning. VulScanner'
    Write-Warn2 'refuses any target outside those scopes.'
} else {
    Write-Ok '.env already exists - leaving it untouched.'
}

foreach ($directory in @('logs', 'cache\cve', 'reports\generated')) {
    $path = Join-Path $RepoRoot $directory
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}
Write-Ok 'Created the logs, cache and report directories.'

# ---------------------------------------------------------------------------
# 4. Database
# ---------------------------------------------------------------------------
Write-Step 'Initialising the database'
Push-Location (Join-Path $RepoRoot 'backend')
try {
    & $Python -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 'Alembic migration failed; falling back to direct table creation.'
        & $Python -c "import sys; sys.path.insert(0,'.'); from app.db.init_db import create_tables; create_tables()"
    }
    Write-Ok 'Schema applied.'
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# 5. Frontend
# ---------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Step 'Installing the web application'
    Push-Location (Join-Path $RepoRoot 'frontend')
    try {
        & npm install --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { Write-Warn2 'npm install failed - the API and CLI still work.' }
        else { Write-Ok 'Frontend dependencies installed.' }
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# 6. Verify
# ---------------------------------------------------------------------------
Write-Step 'Verifying the installation'
& $Python (Join-Path $RepoRoot 'cli\vulscanner.py') version
if ($LASTEXITCODE -ne 0) { Write-Fail 'The CLI did not start correctly.'; exit 1 }

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " VulScanner installed" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
Write-Host " Start everything:      .\scripts\start.ps1"
Write-Host " Scan this machine:     .\scripts\vulscanner.ps1 scan local --profile full"
Write-Host " Web application:       http://localhost:5173"
Write-Host " API documentation:     http://localhost:8000/api/docs"
Write-Host ""
Write-Host " The bootstrap administrator password is printed once, in the API"
Write-Host " console, the first time the backend starts. Store it immediately."
Write-Host ""
Write-Host " VulScanner assesses only systems you are authorized to assess." -ForegroundColor Yellow
Write-Host ""
