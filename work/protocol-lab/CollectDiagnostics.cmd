@echo off
powershell.exe -NoLogo -NoProfile -File "%~dp0Collect-RF-Diagnostics.ps1" -OutputPath "%~dp0rf-windows-diagnostics.json"
if errorlevel 1 (
    echo.
    echo Diagnostics could not finish. Keep the error message for review.
    echo If Windows policy blocked the script, do not change that policy for this tool.
)
echo.
pause
