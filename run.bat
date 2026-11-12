
---

### run.bat

```bat
@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions

echo ========================================
echo   Streaming Cookie Checker
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)

python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo Installing requests...
    python -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo [ERROR] install failed.
        pause
        exit /b 1
    )
)

echo.
set /p TARGET="Path: "
if "%TARGET%"=="" (
    echo [ERROR] empty path.
    pause
    exit /b 1
)

echo.
echo Service: 1=auto  2=netflix  3=disney  4=prime  5=dazn  6=hulu  7=paramount
set /p SVC="Service [1]: "
if "%SVC%"=="" set SVC=1
if "%SVC%"=="1" set SFLAG=auto
if "%SVC%"=="2" set SFLAG=netflix
if "%SVC%"=="3" set SFLAG=disney
if "%SVC%"=="4" set SFLAG=prime
if "%SVC%"=="5" set SFLAG=dazn
if "%SVC%"=="6" set SFLAG=hulu
if "%SVC%"=="7" set SFLAG=paramount
if not defined SFLAG set SFLAG=auto

echo.
set /p STATUS="Status a/d/b/e [a]: "
if "%STATUS%"=="" set STATUS=a

echo.
set /p WORKERS="Workers [6]: "
if "%WORKERS%"=="" set WORKERS=6

echo.
set /p DELAY="Delay sec [0]: "
if "%DELAY%"=="" set DELAY=0

echo.
echo Running...
python "%~dp0cookie.py" "%TARGET%" -s %SFLAG% -w %WORKERS% -r %STATUS% --delay %DELAY%

echo.
echo Done. Check result folder.
pause
