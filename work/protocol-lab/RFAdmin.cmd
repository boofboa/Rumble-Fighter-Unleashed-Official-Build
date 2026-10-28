@echo off
rem Local account administration, e.g.:  RFAdmin.cmd show -Profile loadout
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0RFAdmin.ps1" %*
