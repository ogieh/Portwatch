@echo off
rem double-click friendly wrapper around run.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
pause
