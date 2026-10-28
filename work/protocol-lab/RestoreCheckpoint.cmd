@echo off
rem Usage: RestoreCheckpoint.cmd v1.25-local-startup-training   (stop the server and close the game first)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Restore-Checkpoint.ps1" -Name %1 %2
