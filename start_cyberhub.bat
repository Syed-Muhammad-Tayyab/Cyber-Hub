@echo off
REM ============================================================
REM  Cyber Hub - start the desktop app from the source folder
REM  Developed by Syed Muhammad Tayyab
REM
REM  start_cyberhub.bat              app window + tray icon
REM  start_cyberhub.bat --browser    open in your web browser instead
REM  start_cyberhub.bat --server-only engine only (API on http://127.0.0.1:8765/docs)
REM ============================================================
cd /d "%~dp0"
if not exist .venv (
    echo [Cyber Hub] First start: creating the Python environment...
    python -m venv .venv || (echo Python 3.10+ is required - https://www.python.org/downloads/ & pause & exit /b 1)
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip >nul
) else (
    call .venv\Scripts\activate.bat
)
REM quick no-op when everything is installed already
pip install -q -r requirements.txt
pip install -q pywebview pystray Pillow >nul 2>&1 || echo [Cyber Hub] Window / tray packages unavailable - opening in the browser instead
pip install -q "yara-python>=4.3" >nul 2>&1 || echo [Cyber Hub] yara-python not available - using the built-in YARA-lite engine
echo [Cyber Hub] Starting...
python CyberHub.pyw %*
if errorlevel 1 pause
