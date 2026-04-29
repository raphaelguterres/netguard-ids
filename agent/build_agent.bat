@echo off
REM NetGuard Agent build (cmd wrapper).
REM Uso:
REM   build_agent.bat            (build padrao)
REM   build_agent.bat clean      (apaga build/dist antes)
REM   build_agent.bat service    (inclui hooks Windows service)

setlocal
cd /d "%~dp0"

set EXTRA_ARGS=
if /i "%1"=="clean" set EXTRA_ARGS=%EXTRA_ARGS% -Clean
if /i "%1"=="service" set EXTRA_ARGS=%EXTRA_ARGS% -WithService
if /i "%2"=="service" set EXTRA_ARGS=%EXTRA_ARGS% -WithService
if /i "%2"=="clean" set EXTRA_ARGS=%EXTRA_ARGS% -Clean

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_agent.ps1" %EXTRA_ARGS%
exit /b %ERRORLEVEL%
