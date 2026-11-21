"""
Cyber Hub - desktop launcher
Developed by Syed Muhammad Tayyab

Double-click this file (or CyberHub.exe after building) to start Cyber Hub in its own window with a tray icon.
    CyberHub.pyw --minimized     start hidden in the tray
    CyberHub.pyw --browser       open in the default web browser instead
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cyberhub.desktop_app import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
