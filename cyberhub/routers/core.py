"""
Cyber Hub Backend - Core routes: health, bootstrap, app info, modules map
Developed by Syed Muhammad Tayyab
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from ..config import APP_NAME, APP_VERSION, BUILD_PART, TOTAL_PARTS
from ..security import require_token

router = APIRouter(prefix="/api", tags=["core"])

# Sections of the UI and which build part delivers their backend.
MODULES = [
    {"id": "core",        "name": "Core & System Info",          "part": 1},
    {"id": "account",     "name": "Account & Login",             "part": 2},
    {"id": "monitor",     "name": "Live System Monitor",         "part": 3},
    {"id": "processes",   "name": "Processes & Startup",         "part": 4},
    {"id": "scanner",     "name": "Antivirus Scan Engine",       "part": 5},
    {"id": "quarantine",  "name": "Quarantine & Threat History", "part": 6},
    {"id": "realtime",    "name": "Real-time Protection",        "part": 7},
    {"id": "heuristics",  "name": "Rules Engine & Hash Lookup",  "part": 8},
    {"id": "firewall",    "name": "Firewall & Network Protection", "part": 9},
    {"id": "network",     "name": "Network Monitor & Wi-Fi",     "part": 10},
    {"id": "posture",     "name": "Windows Security Posture",    "part": 11},
    {"id": "passwords",   "name": "Password Vault & Auditor",    "part": 12},
    {"id": "data",        "name": "Data Protection & Shredder",  "part": 13},
    {"id": "web",         "name": "Website / Developer Scanner", "part": 14},
    {"id": "intel",       "name": "Threat Intelligence",         "part": 15},
    {"id": "platforms",   "name": "Social & Platform Accounts",  "part": 16},
    {"id": "scheduler",   "name": "Scheduler & Notifications",   "part": 17},
    {"id": "score",       "name": "Security Score & Dashboard",  "part": 18},
    {"id": "reports",     "name": "Reports, Export & Backup",    "part": 19},
    {"id": "desktop",     "name": "Desktop Packaging & Installer", "part": 20},
]


@router.get("/health")
def health(request: Request):
    """Public liveness check - the UI polls this to show 'Engine online'."""
    db = request.app.state.db
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "schema_version": db.schema_version(),
        "time": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int((datetime.now(timezone.utc) - request.app.state.started_at).total_seconds()),
    }


@router.get("/bootstrap")
def bootstrap(request: Request):
    """Hands the API token to the desktop UI. Only answers allowed origins
    (or no Origin at all, i.e. the local desktop shell) - a random website gets 403."""
    origin = request.headers.get("origin")
    own = f"http://{request.url.netloc}"
    if origin is not None and origin != own and origin not in request.app.state.settings.allowed_origins:
        raise HTTPException(403, "Origin not allowed")
    return {"token": request.app.state.api_token, "header": "X-CyberHub-Token"}


@router.get("/info", dependencies=[Depends(require_token)])
def app_info():
    built = [m for m in MODULES if m["part"] <= BUILD_PART]
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "build_part": BUILD_PART,
        "total_parts": TOTAL_PARTS,
        "progress_percent": BUILD_PART * 100 // TOTAL_PARTS,
        "modules": [dict(m, available=m["part"] <= BUILD_PART) for m in MODULES],
        "available_modules": [m["id"] for m in built],
    }
