@echo off
rem Runs this checkout's reviewed entry point with a process-only policy setting.
rem No persisted execution policy or administrator permission is changed.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-h100-server.ps1" %*
exit /b %ERRORLEVEL%
