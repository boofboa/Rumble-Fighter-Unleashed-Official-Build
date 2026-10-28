@echo off
rem Local item generator. Double-click for the menu, or e.g.:
rem   RFItemGen.cmd list -Family 203      RFItemGen.cmd grant 2030834 -Profile admin
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0RFItemGen.ps1" %*
if errorlevel 1 echo. & echo The command failed; the message above says why. Nothing was changed.
if "%~1"=="" pause
