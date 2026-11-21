"""
Cyber Hub Backend - Real-time Protection routes (Part 7)
Developed by Syed Muhammad Tayyab

Anyone signed in can see the status, turn protection ON, resume it and scan
a plugged-in USB drive. Turning it OFF, pausing it, changing the protected
folders, trusting / forgetting USB drives and clearing the log need a Cyber
Hub administrator - the same rule Windows Security uses.

Live feed:  ws://127.0.0.1:8765/api/realtime/stream?token=...&session=...
"""
from __future__ import annotations

import asyncio
import hmac

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.realtime import RealtimeError, default_folders

router = APIRouter(prefix="/api/realtime", tags=["realtime"],
                   dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/realtime", tags=["realtime"])


def _rt(request: Request):
    return request.app.state.realtime


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except RealtimeError as e:
        raise HTTPException(e.status, e.message)


# ================================================================== status & control
@router.get("/status")
def status(request: Request):
    """On / off / paused, every protected folder with its watch status, USB drives plugged in,
    queue depth, counters since start and the last threat - the Real-time protection card."""
    return _rt(request).status()


@router.post("/enable")
def enable(request: Request, cu: CurrentUser = Depends(require_session)):
    return _rt(request).set_enabled(True, cu.user["username"])


@router.post("/disable")
def disable(request: Request, cu: CurrentUser = Depends(require_admin)):
    return _rt(request).set_enabled(False, cu.user["username"])


class PauseIn(BaseModel):
    minutes: int = Field(..., ge=1, le=480)


@router.post("/pause")
def pause(request: Request, body: PauseIn, cu: CurrentUser = Depends(require_admin)):
    """Turn protection off for a while (e.g. while installing trusted software) - it comes back on by itself."""
    return _rt(request).pause(body.minutes, cu.user["username"])


@router.post("/resume")
def resume(request: Request, cu: CurrentUser = Depends(require_session)):
    return _rt(request).resume(cu.user["username"])


@router.post("/self-test")
def self_test(request: Request):
    """Checks that Windows delivers file notifications (and how fast) plus the scan engine self-test."""
    return _rt(request).self_test()


# ================================================================== folders
@router.get("/folders")
def folders(request: Request):
    return {"folders": _rt(request).folders(), "defaults": default_folders(),
            "custom": request.app.state.settings_store.get("rtp_watched_paths")}


class FolderIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)


@router.post("/folders", status_code=201)
def add_folder(request: Request, body: FolderIn, cu: CurrentUser = Depends(require_admin)):
    out = _run(_rt(request).add_folder, body.path)
    request.app.state.activity.record("realtime", "Protected folder added", body.path, source="realtime")
    return {"custom": out, "folders": _rt(request).folders()}


@router.delete("/folders")
def remove_folder(request: Request, path: str = Query(..., min_length=1, max_length=1024),
                  cu: CurrentUser = Depends(require_admin)):
    out = _run(_rt(request).remove_folder, path)
    request.app.state.activity.record("realtime", "Protected folder removed", path, severity="low", source="realtime")
    return {"custom": out, "folders": _rt(request).folders()}


# ================================================================== activity
@router.get("/events")
def events(request: Request, status: str | None = Query(None, pattern="^(clean|infected|skipped|error)$"),
           origin: str | None = Query(None, pattern="^(folder|usb)$"),
           limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Files checked on arrival, newest first (path, result, threat, action taken, downloaded-from, time taken)."""
    return _rt(request).events(status, origin, limit, offset)


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_admin)):
    n = _rt(request).clear_events()
    request.app.state.activity.record("realtime", "Real-time activity list cleared", f"{n} rows by "
                                      f"{cu.user['username']}", severity="low", source="realtime")
    return {"deleted": n}


@router.get("/summary")
def summary(request: Request, days: int = Query(14, ge=1, le=365)):
    """Per-day files checked / threats / USB plug-ins / bursts, top threats, actions, busiest folders."""
    return _rt(request).summary(days)


# ================================================================== USB devices
@router.get("/usb")
def usb_devices(request: Request, connected: bool = False):
    """Every USB / removable drive seen on this PC (plugged in first), with the warnings
    from its last insertion check (autorun.inf, shortcut virus, programs in the root)."""
    return {"devices": _rt(request).devices(connected_only=connected)}


class TrustIn(BaseModel):
    trusted: bool


@router.patch("/usb/{dev_id}")
def trust_device(request: Request, dev_id: int, body: TrustIn, cu: CurrentUser = Depends(require_admin)):
    """Trusted drives are not scanned automatically when plugged in (new files on them still are)."""
    return _run(_rt(request).set_trusted, dev_id, body.trusted, cu.user["username"])


@router.post("/usb/{dev_id}/scan", status_code=202)
def scan_device(request: Request, dev_id: int, cu: CurrentUser = Depends(require_session)):
    """Starts a Custom scan of the whole drive (watch it on /api/scan/stream)."""
    return _run(_rt(request).scan_device, dev_id, cu.user["username"])


@router.delete("/usb/{dev_id}")
def forget_device(request: Request, dev_id: int, cu: CurrentUser = Depends(require_admin)):
    return {"deleted": _run(_rt(request).forget, dev_id)}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"realtime", status:{state, queue, counters, watching}, events:[file_scanned |
    threat_found | threat_blocked | usb_inserted | usb_removed | burst | protection ...]}
    as things happen, and a status heartbeat every 5 s."""
    app = ws.app
    from ..services.accounts import AuthError

    def check_session() -> int | None:
        try:
            app.state.accounts.authenticate(session, allow_locked=False, touch=False)
            return None
        except AuthError as e:
            return 4423 if e.status == 423 else 4401

    if not hmac.compare_digest(token, app.state.api_token):
        await ws.close(code=4401)
        return
    code = check_session()
    if code:
        await ws.close(code=code)
        return
    await ws.accept()
    rt = app.state.realtime

    def brief() -> dict:
        s = rt.status()
        return {k: s[k] for k in ("state", "protected", "snoozed_until", "queue", "counters", "watching")} | {
            "usb_connected": len(s["usb_connected"])}

    seq, _ = rt.events_since(10 ** 12)
    ticks = 0
    try:
        await ws.send_json({"type": "realtime", "status": brief(), "events": [], "hello": True})
        while True:
            await asyncio.sleep(0.5)
            ticks += 1
            if ticks % 20 == 0:
                code = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
            seq, events = rt.events_since(seq)
            if events or ticks % 10 == 0:
                await ws.send_json({"type": "realtime", "status": brief(), "events": events})
    except (WebSocketDisconnect, RuntimeError):
        pass
