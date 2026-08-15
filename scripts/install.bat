@echo off
REM VulScanner installer - convenience wrapper around install.ps1.
setlocal
echo.
echo  VulScanner installer
echo  --------------------
echo.
where powershell >nul 2>&1
if errorlevel 1 (
    echo [x] Windows PowerShell was not found. VulScanner requires PowerShell 5.1+.
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
    echo.
    echo [x] Installation failed. See the output above.
    pause
    exit /b 1
)
echo.
echo Installation finished. Run start.bat to launch VulScanner.
pause
