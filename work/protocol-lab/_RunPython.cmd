@echo off
setlocal
cd /d "%~dp0" 2>nul
if errorlevel 1 (
    echo Extract this package into a writable local Windows folder first.
    exit /b 1
)
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 goto use_python
echo Python 3.10 or newer is needed to run the local backend.
echo The separate CollectDiagnostics.cmd does not need Python.
exit /b 1

:use_py
py -3 %*
exit /b %errorlevel%

:use_python
python %*
exit /b %errorlevel%
