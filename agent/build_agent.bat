@echo off
REM NetGuard Agent build (cmd wrapper).
REM Uso:
REM   build_agent.bat                 (build padrao via agent.spec)
REM   build_agent.bat clean           (apaga build/dist antes)
REM   build_agent.bat service         (legacy; spec ja inclui hooks)
REM   build_agent.bat nospec          (forca build inline antigo)
REM   build_agent.bat noselftest      (pula --selftest pos-build)
REM Combine livremente: build_agent.bat clean noselftest

setlocal
cd /d "%~dp0"

set EXTRA_ARGS=

:parse
if "%~1"=="" goto run
if /i "%~1"=="clean"      set EXTRA_ARGS=%EXTRA_ARGS% -Clean
if /i "%~1"=="service"    set EXTRA_ARGS=%EXTRA_ARGS% -WithService
if /i "%~1"=="nospec"     set EXTRA_ARGS=%EXTRA_ARGS% -NoSpec
if /i "%~1"=="noselftest" set EXTRA_ARGS=%EXTRA_ARGS% -NoSelftest
if /i "%~1"=="noupx"      set EXTRA_ARGS=%EXTRA_ARGS% -NoUpx
shift
goto parse

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_agent.ps1" %EXTRA_ARGS%
exit /b %ERRORLEVEL%
