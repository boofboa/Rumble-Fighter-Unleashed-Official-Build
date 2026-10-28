@echo off
call "%~dp0_RunPython.cmd" -m unittest discover -v
if errorlevel 1 (
    echo.
    echo Tests could not complete. Send the error text for diagnosis.
) else (
    echo.
    echo Local tests passed. This does not test the Windows game client.
)
pause
