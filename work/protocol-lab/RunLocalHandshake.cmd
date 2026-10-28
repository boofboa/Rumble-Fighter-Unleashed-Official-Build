@echo off
rem Usage: RunLocalHandshake.cmd [profile]   (default profile: baseline; see RFAdmin.cmd)
set RFPROFILE=%~1
if "%RFPROFILE%"=="" set RFPROFILE=baseline
echo Local server 1.28 (persistent: runs until you press Q or Ctrl+C; reconnects allowed). Account profile: %RFPROFILE%
echo Right-click this file and choose Run as administrator. Close Rumble Fighter and its launcher first.
echo Use only the invented login shown after GAME CONNECTED.
echo.
powershell.exe -STA -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-RF-LocalHandshake.ps1" -Profile %RFPROFILE%
echo.
pause
