"""
Cyber Hub Backend - Data Protection routes (Part 13)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked Cyber Hub session.
Encrypt / decrypt / shred / clean / find run as background jobs: the POST
answers at once with {id, kind, status: running, progress}; poll
GET /api/data/jobs/{id} or listen on the /api/data/stream WebSocket.

Errors: 403 protected path (own / OS / program folders, whole drive, home
folder), 404 not found, 409 another job is working on the same path,
422 bad input / weak password, 423 password vault locked (save_to_vault),
428 confirm needed (shredding, emptying the Recycle Bin, cookies), 429 too
many jobs, 503 device key unavailable. Passwords are never logged or stored.
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_session, require_token
from ..services.data_protection import DataProtectionService, DPError

router = APIRouter(prefix="/api/data", tags=["data"], dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/data", tags=["data"])

Paths = list[str]


def _dp(request: Request) -> DataProtectionService:
    return request.app.state.data_protection


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except DPError as e:
        raise HTTPException(e.status, e.message)


# ================================================================== overview
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    """Data Protection card: features, encryption / shredder / cleaner / finder settings, data-exposure score,
    running jobs, unread alerts."""
    return _dp(request).status(cu)


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365), cu: CurrentUser = Depends(require_session)):
    """Graphs: per_day (encrypted / decrypted / shredded / cleaned / new findings), findings by type / severity /
    status, score history, junk by category, health."""
    return _dp(request).summary(cu, days)


@router.get("/health")
def health(request: Request, cu: CurrentUser = Depends(require_session)):
    return _dp(request).health(cu.user["id"])


# ================================================================== encryption
class EncryptIn(BaseModel):
    paths: Paths = Field(..., min_length=1, max_length=100)
    mode: Literal["password", "device"] = "password"
    password: str | None = Field(None, max_length=1024)
    delete_original: Literal["shred", "delete", "keep"] | None = None
    hide_names: bool | None = None
    save_to_vault: bool = False
    allow_weak: bool = False


@router.post("/encrypt")
def encrypt(request: Request, body: EncryptIn, cu: CurrentUser = Depends(require_session)):
    """Encrypt files / folders to .chx. password mode works on any PC; device mode needs no password but only opens
    on this PC + Windows account. Each file is verified before its original is shredded / deleted / kept."""
    return _run(_dp(request).start_encrypt, cu, body.paths, body.mode, body.password, body.delete_original,
                body.hide_names, body.save_to_vault, body.allow_weak)


class DecryptIn(BaseModel):
    paths: Paths = Field(..., min_length=1, max_length=100)
    password: str | None = Field(None, max_length=1024)
    destination: str | None = Field(None, max_length=4096)
    conflict: Literal["rename", "overwrite", "skip"] = "rename"
    delete_encrypted: bool = True


@router.post("/decrypt")
def decrypt(request: Request, body: DecryptIn, cu: CurrentUser = Depends(require_session)):
    """Decrypt .chx files (or every .chx in folders) back to their original names. Wrong password = that file is
    reported as wrong_password, the rest continue. Decrypted files are scanned (dp_decrypt_scan)."""
    return _run(_dp(request).start_decrypt, cu, body.paths, body.password, body.destination, body.conflict,
                body.delete_encrypted)


class InspectIn(BaseModel):
    path: str = Field(..., max_length=4096)
    password: str | None = Field(None, max_length=1024)


@router.post("/inspect")
def inspect(request: Request, body: InspectIn):
    """What is this .chx? mode, cipher, key settings; with the password (or device mode) also its real name / size."""
    return _run(_dp(request).inspect, body.path, body.password)


@router.post("/verify")
def verify(request: Request, body: InspectIn):
    """Check every block of a .chx decrypts, without writing anything. 401 wrong password."""
    return _run(_dp(request).verify, body.path, body.password)


@router.get("/encrypted")
def encrypted(request: Request, status: Literal["encrypted", "decrypted"] | None = "encrypted",
              limit: int = Query(200, ge=1, le=2000), cu: CurrentUser = Depends(require_session)):
    """Files Cyber Hub encrypted (exists = still on disk)."""
    return _dp(request).encrypted_files(cu, status, limit)


# ================================================================== shredder
class ShredPreviewIn(BaseModel):
    paths: Paths = Field(..., min_length=1, max_length=100)


@router.post("/shred/preview")
def shred_preview(request: Request, body: ShredPreviewIn):
    """Files / folders / bytes that would be destroyed, drive type (SSD warning), hard links, running programs."""
    return _run(_dp(request).shred_preview, body.paths)


class ShredIn(BaseModel):
    paths: Paths = Field(..., min_length=1, max_length=100)
    method: Literal["zero", "random", "dod3", "random3"] | None = None
    verify: bool | None = None
    confirm: bool = False
    allow_hardlinks: bool = False


@router.post("/shred")
def shred(request: Request, body: ShredIn, cu: CurrentUser = Depends(require_session)):
    """Overwrite then delete. 428 until confirm=true - this can't be undone."""
    return _run(_dp(request).start_shred, cu, body.paths, body.method, body.verify, body.confirm, body.allow_hardlinks)


# ================================================================== privacy cleaner
@router.post("/cleaner/analyze")
def cleaner_analyze(request: Request, cu: CurrentUser = Depends(require_session)):
    """Measure every category (job). Result: GET /cleaner/report."""
    return _run(_dp(request).start_cleaner_analysis, cu)


@router.get("/cleaner/report")
def cleaner_report(request: Request):
    """Last analysis: categories[{id, group, label, description, files, bytes, warning, needs_confirm,
    browser_running, note}], totals."""
    return _dp(request).cleaner_report()


class CleanIn(BaseModel):
    categories: list[str] = Field(..., min_length=1, max_length=100)
    secure: bool | None = None
    confirm: bool = False


@router.post("/cleaner/clean")
def cleaner_clean(request: Request, body: CleanIn, cu: CurrentUser = Depends(require_session)):
    """Clean the chosen categories. Recycle Bin / cookies need confirm=true (428). Running browsers are skipped."""
    return _run(_dp(request).start_clean, cu, body.categories, body.secure, body.confirm)


# ================================================================== sensitive-file finder
class FinderIn(BaseModel):
    paths: Paths | None = Field(None, max_length=100)
    types: list[str] | None = Field(None, max_length=20)


@router.post("/finder/scan")
def finder_scan(request: Request, body: FinderIn, cu: CurrentUser = Depends(require_session)):
    """Search folders (default: Documents, Desktop, Downloads + dp_finder_paths) for sensitive data."""
    return _run(_dp(request).start_finder, cu, body.paths, body.types)


@router.get("/finder/roots")
def finder_roots(request: Request):
    return {"roots": _dp(request).finder_roots()}


@router.get("/finder/findings")
def findings(request: Request, status: Literal["open", "ignored", "encrypted", "shredded", "resolved", "all"] = "open",
             severity: Literal["low", "medium", "high", "critical"] | None = None,
             type: str | None = Query(None, max_length=40), q: str | None = Query(None, max_length=200),
             limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
             cu: CurrentUser = Depends(require_session)):
    """Files with sensitive data (masked samples, advice, actions)."""
    return _dp(request).findings(cu, None if status == "all" else status, severity, type, q, limit, offset)


@router.get("/finder/findings/{fid}")
def finding(request: Request, fid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).finding, cu, fid)


class IgnoreIn(BaseModel):
    note: str | None = Field(None, max_length=300)


@router.post("/finder/findings/{fid}/ignore")
def ignore(request: Request, fid: int, body: IgnoreIn | None = None, cu: CurrentUser = Depends(require_session)):
    """'This file is fine' - stays ignored until it changes."""
    return _run(_dp(request).set_ignored, cu, fid, True, body.note if body else None)


@router.post("/finder/findings/{fid}/unignore")
def unignore(request: Request, fid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).set_ignored, cu, fid, False)


class FindingEncryptIn(BaseModel):
    mode: Literal["password", "device"] = "password"
    password: str | None = Field(None, max_length=1024)
    delete_original: Literal["shred", "delete", "keep"] | None = None
    save_to_vault: bool = False
    allow_weak: bool = False


@router.post("/finder/findings/{fid}/encrypt")
def finding_encrypt(request: Request, fid: int, body: FindingEncryptIn, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).encrypt_finding, cu, fid, mode=body.mode, password=body.password,
                delete_original=body.delete_original, save_to_vault=body.save_to_vault, allow_weak=body.allow_weak)


class FindingShredIn(BaseModel):
    confirm: bool = False
    method: Literal["zero", "random", "dod3", "random3"] | None = None


@router.post("/finder/findings/{fid}/shred")
def finding_shred(request: Request, fid: int, body: FindingShredIn, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).shred_finding, cu, fid, body.confirm, body.method)


# ================================================================== jobs
@router.get("/jobs")
def jobs(request: Request, limit: int = Query(30, ge=1, le=500),
         kind: Literal["encrypt", "decrypt", "shred", "clean", "cleaner_analyze", "finder"] | None = None,
         cu: CurrentUser = Depends(require_session)):
    return _dp(request).jobs_for(cu, limit, kind)


@router.get("/jobs/{job_id}")
def job(request: Request, job_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).job, cu, job_id)


@router.post("/jobs/{job_id}/cancel")
def cancel(request: Request, job_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_dp(request).cancel, cu, job_id)


# ================================================================== events
@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0),
           severity: Literal["info", "low", "medium", "high", "critical"] | None = None,
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), cu: CurrentUser = Depends(require_session)):
    return _dp(request).events(cu, after_id, severity, kind, unacknowledged, limit)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn, cu: CurrentUser = Depends(require_session)):
    return {"acknowledged": _dp(request).acknowledge(cu, body.ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _dp(request).clear_events(cu)}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"data", jobs:[running jobs with progress], events:[new dp_events], unacknowledged} every second."""
    app = ws.app
    from ..services.accounts import AuthError

    def check_session():
        try:
            s, u = app.state.accounts.authenticate(session, allow_locked=False, touch=False)
            return None, u
        except AuthError as e:
            return (4423 if e.status == 423 else 4401), None

    if not hmac.compare_digest(token, app.state.api_token):
        await ws.close(code=4401)
        return
    code, user = check_session()
    if code:
        await ws.close(code=code)
        return
    await ws.accept()
    dp: DataProtectionService = app.state.data_protection

    class _CU:                                                         # what the service reads from a session
        def __init__(self, u):
            self.user = u
    cu = _CU(user)
    last_id = dp.events(cu, limit=1)["last_id"]
    ticks = 0
    try:
        while True:
            if ticks % 2 == 0:
                ev = dp.events(cu, after_id=last_id, limit=50)
                if ev["items"]:
                    last_id = max(e["id"] for e in ev["items"])
                await ws.send_json({"type": "data", "jobs": dp.jobs_for(cu, limit=1)["running"],
                                    "events": list(reversed(ev["items"])), "unacknowledged": ev["unacknowledged"]})
            await asyncio.sleep(0.5)
            ticks += 1
            if ticks % 20 == 0:
                code, _ = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
