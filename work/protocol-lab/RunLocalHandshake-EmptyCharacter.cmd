@echo off
echo Comparison run 1.28 (persistent; Q or Ctrl+C stops) with the v1.12 empty character (no class item). Right-click this file and choose Run as administrator.
echo Close Rumble Fighter and its launcher first. Use only the invented password shown after GAME CONNECTED.
echo.
powershell.exe -STA -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-RF-LocalHandshake.ps1" -EmptyCharacter
echo.
pause
