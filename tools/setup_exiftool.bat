@echo off
echo Setting up Exiftool for Windows...
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0setup_exiftool.ps1"
echo.
pause
