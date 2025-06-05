@echo off
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python is not installed. Please install Python first.
    pause
    exit /b
)
echo Installing Python packages...
python -m pip install requests colorama bs4 pycryptodomex
if %ERRORLEVEL% equ 0 (
    echo Packages installed successfully.
) else (
    echo Failed to install packages.
)
pause
