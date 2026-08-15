@echo off
REM Runs the VulScanner CLI from a source checkout.
setlocal
if not exist "%~dp0..\.venv\Scripts\python.exe" (
    echo [x] VulScanner is not installed. Run install.bat first.
    exit /b 1
)
"%~dp0..\.venv\Scripts\python.exe" "%~dp0..\cli\vulscanner.py" %*
