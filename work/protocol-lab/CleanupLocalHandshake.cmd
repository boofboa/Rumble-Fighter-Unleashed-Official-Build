@echo off
echo Close Rumble Fighter and its launcher first. Run this file as administrator.
echo This removes only the temporary address identified by this folder's test ownership journal.
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-RF-LocalHandshake.ps1" -CleanupOnly
echo.
pause
