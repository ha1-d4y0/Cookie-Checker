@echo off
chcp 65001 >nul 2>&1
setlocal EnableExtensions

echo ========================================
echo   Netflix Cookie Checker
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Please install Python and add it to PATH.
    pause
    exit /b 1
)

python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo Installing requests...
    python -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo [ERROR] Failed to install requests.
        pause
        exit /b 1
    )
)

echo.
echo Enter the folder or file path to check.
echo Example: C:\Users\admin\Downloads\cookies
echo.
set /p TARGET="Path: "

if "%TARGET%"=="" (
    echo [ERROR] Path is empty.
    pause
    exit /b 1
)

echo.
echo Select output status:
echo   a = alive only  (recommended / default)
echo   d = dead
echo   b = blocked
echo   e = error
echo   Multiple OK  (example: a  or  ad  or  adbe)
echo.
set /p STATUS="Status [a]: "
if "%STATUS%"=="" set STATUS=a

echo.
echo Concurrent workers (recommended: 4-8)
set /p WORKERS="Workers [6]: "
if "%WORKERS%"=="" set WORKERS=6

echo.
echo Running...
echo.

python "%~dp0cookie.py" "%TARGET%" -w %WORKERS% -r %STATUS%

echo.
echo Done. Check the "result" folder.
pause