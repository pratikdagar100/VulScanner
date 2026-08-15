<#
.SYNOPSIS
    Packages a VulScanner release: builds everything, then produces a zip
    containing the executable, the web bundle, documentation and configuration.

.PARAMETER Version
    Version label for the archive name. Defaults to the application version.

.PARAMETER SkipBuild
    Package whatever has already been built.
#>
[CmdletBinding()]
param(
    [string]$Version,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$DistDir = Join-Path $RepoRoot 'dist'

function Write-Step { param($Message) Write-Host "`n[*] $Message" -ForegroundColor Cyan }
function Write-Ok   { param($Message) Write-Host "    [ok] $Message" -ForegroundColor Green }

if (-not $Version) {
    if (Test-Path $Python) {
        $Version = & $Python -c "import sys; sys.path.insert(0,'backend'); from app.core.config import APP_VERSION; print(APP_VERSION)"
    }
    if (-not $Version) { $Version = '1.0.0' }
}

if (-not $SkipBuild) {
    Write-Step 'Building release artefacts'
    & (Join-Path $PSScriptRoot 'build.ps1')
    if ($LASTEXITCODE -ne 0) { Write-Host '[x] Build failed.' -ForegroundColor Red; exit 1 }
}

$stamp = Get-Date -Format 'yyyyMMdd'
$packageName = "vulscanner-$Version-win64-$stamp"
$stagingDir = Join-Path $DistDir $packageName

Write-Step "Staging $packageName"
if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# --- executable ------------------------------------------------------------
$exe = Join-Path $DistDir 'vulscanner.exe'
if (Test-Path $exe) {
    Copy-Item $exe (Join-Path $stagingDir 'vulscanner.exe')
    Write-Ok 'vulscanner.exe'
} else {
    Write-Host '    [!]  vulscanner.exe not found - packaging without it.' -ForegroundColor Yellow
}

# --- web bundle ------------------------------------------------------------
$frontendDist = Join-Path $RepoRoot 'frontend\dist'
if (Test-Path $frontendDist) {
    Copy-Item $frontendDist (Join-Path $stagingDir 'web') -Recurse
    Write-Ok 'web application bundle'
}

# --- source needed to run the API -----------------------------------------
Copy-Item (Join-Path $RepoRoot 'backend') (Join-Path $stagingDir 'backend') -Recurse `
    -Exclude '__pycache__', '*.pyc', '*.db', 'migration_check.db'
Copy-Item (Join-Path $RepoRoot 'cli') (Join-Path $stagingDir 'cli') -Recurse -Exclude '__pycache__', '*.pyc'
Copy-Item (Join-Path $RepoRoot 'reports\templates') (Join-Path $stagingDir 'reports\templates') -Recurse -Force
Copy-Item (Join-Path $RepoRoot 'docs') (Join-Path $stagingDir 'docs') -Recurse
Copy-Item (Join-Path $RepoRoot 'scripts') (Join-Path $stagingDir 'scripts') -Recurse

foreach ($file in @('README.md', 'LICENSE', '.env.example', 'docker-compose.yml')) {
    $path = Join-Path $RepoRoot $file
    if (Test-Path $path) { Copy-Item $path (Join-Path $stagingDir $file) }
}
Write-Ok 'source, docs, scripts and configuration'

# Remove any stray Python caches that slipped through.
Get-ChildItem $stagingDir -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- release notes ---------------------------------------------------------
@"
VulScanner $Version
==================

Agent-less Windows vulnerability, security posture and network assessment
platform. For authorized defensive security assessment only.

Contents
--------
  vulscanner.exe    Command-line scanner (no Python installation required)
  backend/          REST API and scanning engine
  cli/              CLI source
  web/              Built web application (serve with any static host)
  docs/             Architecture, installation, CLI, API, security, methodology
  scripts/          install.ps1, start.ps1, build.ps1, package.ps1

Quick start
-----------
  1. Extract this archive.
  2. Review .env.example and copy it to .env. Set VULSCANNER_AUTHORIZED_SCOPES
     to the networks you are authorized to assess.
  3. Scan this machine:      .\vulscanner.exe scan local --profile full
  4. Full platform:          .\scripts\install.ps1  then  .\scripts\start.ps1

Authorization
-------------
VulScanner refuses any target outside the configured authorized scope. Use it
only against systems and networks you own or have written permission to assess.
It performs no exploitation, collects no passwords, hashes or private keys, and
never applies remediation automatically.

Packaged $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@ | Set-Content (Join-Path $stagingDir 'RELEASE.txt') -Encoding utf8

# --- archive ---------------------------------------------------------------
Write-Step 'Creating the archive'
$archive = Join-Path $DistDir "$packageName.zip"
if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $archive -CompressionLevel Optimal
Write-Ok "$archive"

$hash = (Get-FileHash $archive -Algorithm SHA256).Hash
"$hash  $packageName.zip" | Set-Content "$archive.sha256" -Encoding ascii
Write-Ok "SHA256 $hash"

$sizeMb = [math]::Round((Get-Item $archive).Length / 1MB, 2)
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " VulScanner $Version packaged" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
Write-Host " Archive:   $archive ($sizeMb MB)"
Write-Host " Checksum:  $archive.sha256"
Write-Host ''
