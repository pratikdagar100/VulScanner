<#
.SYNOPSIS
    Runs the VulScanner CLI from a source checkout without activating the
    virtual environment.

.EXAMPLE
    .\scripts\vulscanner.ps1 scan local --profile full
    .\scripts\vulscanner.ps1 network discover --scope 192.168.1.0/24
#>
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'

if (-not (Test-Path $Python)) {
    Write-Host '[x] VulScanner is not installed. Run .\scripts\install.ps1 first.' -ForegroundColor Red
    exit 1
}

& $Python (Join-Path $RepoRoot 'cli\vulscanner.py') @args
exit $LASTEXITCODE
