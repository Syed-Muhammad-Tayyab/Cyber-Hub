"""
Cyber Hub Backend - Configuration
Developed by Syed Muhammad Tayyab

All paths and runtime settings live here. Values can be overridden with
environment variables (CYBERHUB_*), which is how the tests run in isolation.
"""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "Cyber Hub"
APP_VERSION = "1.0.0"           # 0.N.0 = Part N of 20; 1.0.0 = all 20 parts, the finished desktop app
BUILD_PART = 20
TOTAL_PARTS = 20


def _default_data_dir() -> Path:
    """Per-user data folder: %LOCALAPPDATA%\\CyberHub on Windows, ~/.cyberhub elsewhere."""
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "CyberHub"
    return Path.home() / ".cyberhub"


@dataclass
class Settings:
    host: str = field(default_factory=lambda: os.environ.get("CYBERHUB_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("CYBERHUB_PORT", "8765")))
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("CYBERHUB_DATA_DIR", str(_default_data_dir())))
    )
    # Extra dev origins allowed to call the API. The recommended setup is to put the
    # UI in ./ui so the backend serves it same-origin at http://127.0.0.1:8765/.
    # "null" (file:// pages, sandboxed iframes) is deliberately NOT allowed.
    allowed_origins: list[str] = field(
        default_factory=lambda: os.environ.get(
            "CYBERHUB_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,"
            "http://127.0.0.1:5500,http://localhost:5500,app://cyberhub",
        ).split(",")
    )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cyberhub.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def ui_dir(self) -> Path:
        if os.environ.get("CYBERHUB_UI_DIR"):
            return Path(os.environ["CYBERHUB_UI_DIR"])
        if getattr(sys, "frozen", False):                # Part 20: packaged app - the UI sits beside the bundle's code
            base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
            return base / "ui"
        return Path(__file__).resolve().parent.parent / "ui"

    @property
    def token_path(self) -> Path:
        return self.data_dir / "api_token"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.log_dir, self.data_dir / "quarantine", self.data_dir / "reports",
                  self.data_dir / "backups"):
            d.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
