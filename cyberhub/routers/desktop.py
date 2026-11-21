"""
Cyber Hub Backend - Desktop app routes (Part 20)
Developed by Syed Muhammad Tayyab

GET  /api/about                    product, version, developer, components (token only - shown on the sign-in page)
GET  /api/desktop/status           window / tray / packaged state, run-at-sign-in entry, data folder
PUT  /api/desktop/autostart        {enabled} - start Cyber Hub (minimised) when you sign in to Windows
POST /api/desktop/pick             {kind: file|folder|save, title?, multiple?} - native file dialog (desktop window)
POST /api/desktop/show             bring the window to the front
POST /api/desktop/activate         the same, token only - a second start of the app calls it instead of opening twice
POST /api/desktop/restart          restart the app (admin) - used after a backup restore; elevated=true restarts
                                   it "as administrator" (Windows asks for consent) for firewall / system fixes
POST /api/desktop/quit             close the app completely (admin; protection stops)
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.desktop import DesktopError, DesktopService

about_router = APIRouter(prefix="/api", tags=["desktop"], dependencies=[Depends(require_token)])
router = APIRouter(prefix="/api/desktop", tags=["desktop"],
                   dependencies=[Depends(require_token), Depends(require_session)])


class AutostartIn(BaseModel):
    enabled: bool


class PickIn(BaseModel):
    kind: Literal["file", "folder", "save"] = "folder"
    title: str | None = Field(None, max_length=120)
    multiple: bool = False


def _ds(request: Request) -> DesktopService:
    return request.app.state.desktop


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except DesktopError as e:
        raise HTTPException(e.status, e.message)


@about_router.get("/about")
def about(request: Request):
    st = request.app.state
    comp = {}
    try:
        comp = {"schema_version": st.db.schema_version(), "yara_engine": st.rules.backend,
                "yara_rules": st.rules.rule_count, "firewall": st.firewall.backend.label,
                "network": st.network.probe.label, "posture": st.posture.backend.label,
                "toasts": st.notifications.toaster.name, "signatures": st.malware_db.stats()["enabled"]
                if hasattr(st.malware_db, "stats") else None}
    except Exception:                                                # pragma: no cover - about must never fail
        pass
    return _ds(request).about(comp)


@router.get("/status")
def status(request: Request):
    return _ds(request).status()


@router.put("/autostart")
def set_autostart(request: Request, body: AutostartIn, cu: CurrentUser = Depends(require_session)):
    return _run(_ds(request).set_autostart, body.enabled, cu.user["username"])


@router.post("/pick")
def pick(request: Request, body: PickIn):
    return _run(_ds(request).pick, body.kind, body.title, body.multiple)


@router.post("/show")
def show(request: Request):
    return _run(_ds(request).show)


@about_router.post("/desktop/activate")
def activate(request: Request):
    """Only raises the window - needs no session so a second launch can call it."""
    try:
        return _ds(request).show()
    except DesktopError:
        return {"shown": False}


@router.post("/restart", status_code=202)
def restart(request: Request, cu: CurrentUser = Depends(require_admin), elevated: bool = False):
    return _run(_ds(request).restart, cu.user["username"], elevated)


@router.post("/quit", status_code=202)
def quit_app(request: Request, cu: CurrentUser = Depends(require_admin)):
    return _run(_ds(request).quit, cu.user["username"])
