@echo off
REM ============================================================
REM  Cyber Hub - build CyberHub.exe (and the installer, if Inno Setup is installed)
REM  Developed by Syed Muhammad Tayyab
REM ============================================================
cd /d "%~dp0"
if not exist .venv (
    python -m venv .venv || (echo Python 3.10+ is required & pause & exit /b 1)
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
pip install -r requirements-desktop.txt || (echo Package install failed & pause & exit /b 1)
pip install -q "yara-python>=4.3" >nul 2>&1 || echo [Cyber Hub] yara-python not available - the .exe will use the built-in YARA-lite engine

echo [Cyber Hub] Running the tests first...
python -m pytest -q -x || (echo Tests failed - not building & pause & exit /b 1)

echo [Cyber Hub] Building CyberHub.exe ...
pyinstaller --noconfirm --clean packaging\CyberHub.spec || (echo Build failed & pause & exit /b 1)
echo [Cyber Hub] Built: dist\CyberHub\CyberHub.exe

set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist %ISCC% (
    %ISCC% packaging\CyberHub.iss && echo [Cyber Hub] Installer: dist\CyberHub-Setup-1.0.0.exe
) else (
    echo [Cyber Hub] Inno Setup 6 not found - skip the installer. Get it free from https://jrsoftware.org/isdl.php
)
pause
