@echo off
REM VulScanner launcher - convenience wrapper around start.ps1.
setlocal
where powershell >nul 2>&1
if errorlevel 1 (
    echo [x] Windows PowerShell was not found. VulScanner requires PowerShell 5.1+.
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
