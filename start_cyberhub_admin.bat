@echo off
REM ============================================================
REM  Cyber Hub - start WITH administrator rights
REM  Developed by Syed Muhammad Tayyab
REM  Needed to change Windows Firewall (Part 9), apply machine-wide
REM  security fixes (Part 11) and end system processes / switch
REM  machine-wide startup items (Part 4).
REM ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [Cyber Hub] Asking Windows for administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)
call "%~dp0start_cyberhub.bat" %*
