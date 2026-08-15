<#
.SYNOPSIS
    Builds VulScanner for distribution: the web application bundle and the
    vulscanner.exe command-line executable.

.PARAMETER SkipFrontend
    Do not build the web application.

.PARAMETER SkipExe
    Do not build vulscanner.exe.
#>
[CmdletBinding()]
param(
    [switch]$SkipFrontend,
    [switch]$SkipExe
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$DistDir = Join-Path $RepoRoot 'dist'

function Write-Step { param($Message) Write-Host "`n[*] $Message" -ForegroundColor Cyan }
function Write-Ok   { param($Message) Write-Host "    [ok] $Message" -ForegroundColor Green }

if (-not (Test-Path $Python)) {
    Write-Host '[x] Run .\scripts\install.ps1 first.' -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

# ---------------------------------------------------------------------------
# Web application
# ---------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Step 'Building the web application'
    Push-Location (Join-Path $RepoRoot 'frontend')
    try {
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        Write-Ok "Bundle written to frontend\dist"
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# vulscanner.exe
# ---------------------------------------------------------------------------
if (-not $SkipExe) {
    Write-Step 'Building vulscanner.exe'

    & $Python -m pip show pyinstaller *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '    Installing PyInstaller...'
        & $Python -m pip install pyinstaller --quiet
    }

    Push-Location $RepoRoot
    try {
        # The scanner discovers collectors through the registry, so PyInstaller
        # needs them named explicitly as hidden imports.
        $hiddenImports = @(
            'app.scanner.registry',
            'app.services.analyzers.windows_rules',
            'app.services.analyzers.windows_rules2',
            'app.services.analyzers.network_rules',
            'app.models',
            'reportlab.graphics.barcode.code128',
            'uvicorn.logging'
        ) | ForEach-Object { "--hidden-import=$_" }

        & $Python -m PyInstaller `
            --name vulscanner `
            --onefile `
            --console `
            --clean `
            --noconfirm `
            --distpath $DistDir `
            --workpath (Join-Path $RepoRoot 'build') `
            --specpath (Join-Path $RepoRoot 'build') `
            --paths (Join-Path $RepoRoot 'backend') `
            --paths $RepoRoot `
            --add-data "$(Join-Path $RepoRoot 'reports\templates');reports/templates" `
            --add-data "$(Join-Path $RepoRoot 'backend\powershell');backend/powershell" `
            @hiddenImports `
            (Join-Path $RepoRoot 'cli\vulscanner.py')

        if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
        Write-Ok "Executable written to $DistDir\vulscanner.exe"

        Write-Step 'Verifying the executable'
        & (Join-Path $DistDir 'vulscanner.exe') version
        if ($LASTEXITCODE -ne 0) { throw 'vulscanner.exe did not run correctly.' }
        Write-Ok 'Executable verified.'
    } finally {
        Pop-Location
    }
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' VulScanner build complete' -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
if (-not $SkipExe) {
    Write-Host " CLI executable:  $DistDir\vulscanner.exe"
    Write-Host " Add it to PATH, then run:  vulscanner scan local"
}
if (-not $SkipFrontend) {
    Write-Host " Web bundle:      $RepoRoot\frontend\dist"
}
Write-Host ''
