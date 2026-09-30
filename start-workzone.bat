@echo off
rem Double-click to start the Work Zone dashboard (this computer only).
rem Close this window to stop it.
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3.10+ is needed: https://www.python.org/downloads/ & pause & exit /b 1)
start "" http://127.0.0.1:8770/
python tools\workzone.py
pause
