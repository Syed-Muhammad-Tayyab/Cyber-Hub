"""
Cyber Hub Backend - Antivirus Scan Engine routes (Part 5)
Developed by Syed Muhammad Tayyab

Any signed-in user can run, pause, resume and cancel scans (like Windows
Security). Changing the signature database, exclusions or dismissing a
threat needs a Cyber Hub administrator.

Live progress:  ws://127.0.0.1:8765/api/scan/stream?token=...&session=...
"""
from __future__ import annotations

import asyncio
import hmac
import io
import os
import zipfile
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.malware_db import SEVERITIES, normalize_hash, parse_hash_list
from ..services.scanner import ScanError, quick_locations, full_roots

router = APIRouter(prefix="/api/scan", tags=["scanner"],
                   dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/scan", tags=["scanner"])

MAX_IMPORT_TEXT = 10 * 1024 * 1024          # pasted / uploaded text
MAX_IMPORT_FILE = 512 * 1024 * 1024         # file on disk (MalwareBazaar full export is ~70 MB)


def _sc(request: Request):
    return request.app.state.scanner


def _mdb(request: Request):
    return request.app.state.malware_db


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ScanError as e:
        raise HTTPException(e.status, e.message)


# ================================================================== overview
@router.get("/summary")
def scan_summary(request: Request, days: int = Query(14, ge=1, le=365)):
    """Protection status, active threats by severity, last scan per type, scans/threats per day,
    signature DB stats and any running job - everything the Virus & threat protection page needs."""
    return _sc(request).summary(days)


@router.get("/locations")
def scan_locations(request: Request):
    """What a Quick scan covers and which drives a Full scan walks."""
    return {"quick": quick_locations(), "full": full_roots(),
            "quick_also_scans": "every running program file and every startup item's program file"}


@router.post("/self-test")
def self_test(request: Request):
    """Checks hash lookup, pattern matching and archive scanning with the EICAR test string in memory."""
    return _sc(request).self_test()


# ================================================================== jobs
class CustomIn(BaseModel):
    paths: list[str] = Field(..., min_length=1, max_length=50)


@router.post("/quick", status_code=202)
def start_quick(request: Request, cu: CurrentUser = Depends(require_session)):
    """Temp, Downloads, Desktop, AppData programs & scripts, Startup folders, running programs, startup items."""
    return _run(_sc(request).start, "quick", cu.user["username"])


@router.post("/full", status_code=202)
def start_full(request: Request, cu: CurrentUser = Depends(require_session)):
    """Every file on every fixed drive. Can take a long time - pause / cancel any time."""
    return _run(_sc(request).start, "full", cu.user["username"])


@router.post("/custom", status_code=202)
def start_custom(request: Request, body: CustomIn, cu: CurrentUser = Depends(require_session)):
    """Files and / or folders you choose."""
    return _run(_sc(request).start, "custom", cu.user["username"], body.paths)


@router.get("/jobs")
def list_jobs(request: Request, limit: int = Query(20, ge=1, le=500),
              kind: Literal["quick", "full", "custom"] | None = None):
    """Scan history, newest first (running jobs show live progress)."""
    return {"items": _sc(request).history(limit, kind)}


@router.get("/jobs/active")
def active_jobs(request: Request):
    return {"items": _sc(request).active()}


@router.get("/jobs/{job_id}")
def get_job(request: Request, job_id: int):
    return _run(_sc(request).get, job_id)


@router.get("/jobs/{job_id}/detections")
def job_detections(request: Request, job_id: int, limit: int = Query(200, ge=1, le=2000)):
    _run(_sc(request).get, job_id)
    return _sc(request).detections("all", job_id, limit)


@router.post("/jobs/{job_id}/pause")
def pause_job(request: Request, job_id: int):
    return _run(_sc(request).pause, job_id)


@router.post("/jobs/{job_id}/resume")
def resume_job(request: Request, job_id: int):
    return _run(_sc(request).resume, job_id)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(request: Request, job_id: int):
    return _run(_sc(request).cancel, job_id)


@router.delete("/jobs/{job_id}")
def delete_job(request: Request, job_id: int, cu: CurrentUser = Depends(require_admin)):
    if not _run(_sc(request).delete_job, job_id):
        raise HTTPException(404, "Scan job not found")
    return {"deleted": 1}


# ================================================================== on-demand
class FileIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)


class HashIn(BaseModel):
    hash: str = Field(..., min_length=32, max_length=64)


@router.post("/file")
def scan_one_file(request: Request, body: FileIn):
    """Scan a single file right now ('Scan with Cyber Hub'). Threats are recorded like any scan."""
    p = os.path.abspath(os.path.expandvars(os.path.expanduser(body.path)))
    if not os.path.exists(p):
        raise HTTPException(404, "File not found")
    if os.path.isdir(p):
        raise HTTPException(422, "That is a folder - use a Custom scan")
    sc = _sc(request)
    res = sc.scan_file(p)
    if res["status"] == "infected":
        res["detections"] = sc._record_detections(None, res)
    request.app.state.activity.record("scan", "File scanned", f"{p}: {res['status']}", source="scanner")
    return res


@router.post("/lookup")
def lookup_hash(request: Request, body: HashIn):
    """Is this hash in the signature database?"""
    try:
        h, t = normalize_hash(body.hash)
    except ValueError as e:
        raise HTTPException(422, str(e))
    sig = _mdb(request).lookup(**{t: h})
    return {"hash": h, "hash_type": t, "known_malware": bool(sig), "signature": sig}


# ================================================================== detections
@router.get("/detections")
def list_detections(request: Request,
                    status: Literal["active", "quarantined", "restored", "removed", "allowed", "dismissed", "resolved",
                                    "superseded", "all"] = "active",
                    limit: int = Query(100, ge=1, le=2000), offset: int = Query(0, ge=0)):
    return _sc(request).detections(status, None, limit, offset)


@router.post("/detections/{det_id}/dismiss")
def dismiss_detection(request: Request, det_id: int, cu: CurrentUser = Depends(require_admin)):
    """Mark a detection as a false alarm / handled. To act on the file use /api/threats/{id}/quarantine (Part 6)."""
    return _run(_sc(request).dismiss, det_id, cu.user["username"])


# ================================================================== signature database
class SignatureIn(BaseModel):
    hash: str = Field(..., min_length=32, max_length=64)
    name: str = Field(..., min_length=1, max_length=120)
    severity: Literal["low", "medium", "high", "critical"] = "high"
    family: str | None = Field(None, max_length=80)


class ImportIn(BaseModel):
    text: str | None = Field(None, description="Pasted hash list (one per line, CSV or MalwareBazaar export)")
    path: str | None = Field(None, max_length=4096, description="Or: a .txt / .csv / .zip file on this PC")
    severity: Literal["low", "medium", "high", "critical"] = "high"
    default_name: str = Field("Malware.Generic (imported)", max_length=120)
    label: str | None = Field(None, max_length=60, description="Source label, defaults to the file name")


class SigPatch(BaseModel):
    enabled: bool


@router.get("/signatures")
def list_signatures(request: Request, search: str | None = Query(None, max_length=120),
                    source: str | None = Query(None, max_length=80),
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    return _mdb(request).list(search, source, limit, offset)


@router.get("/signatures/stats")
def signature_stats(request: Request):
    return _mdb(request).stats()


@router.post("/signatures", status_code=201)
def add_signature(request: Request, body: SignatureIn, cu: CurrentUser = Depends(require_admin)):
    try:
        row = _mdb(request).add(body.hash, body.name, body.severity, body.family)
    except ValueError as e:
        raise HTTPException(422, str(e))
    request.app.state.activity.record("scan", "Signature added", f"{body.name} ({row['hash'][:16]}…)",
                                      source="scanner")
    return row


def _read_import_file(path: str) -> tuple[str, str]:
    p = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
    if not os.path.isfile(p):
        raise HTTPException(404, "Import file not found")
    if os.path.getsize(p) > MAX_IMPORT_FILE:
        raise HTTPException(413, "Import file is too large (max 512 MB)")
    name = os.path.basename(p)
    with open(p, "rb") as f:
        raw = f.read()
    if raw[:4] == b"PK\x03\x04":                        # MalwareBazaar ships full_sha256.zip
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members = [i for i in z.infolist() if not i.is_dir() and i.file_size <= MAX_IMPORT_FILE
                       and i.filename.lower().endswith((".txt", ".csv"))]
            if not members:
                raise HTTPException(422, "The zip has no .txt or .csv hash list inside")
            raw = z.read(members[0])
            name = f"{name}/{members[0].filename}"
    return raw.decode("utf-8", errors="replace"), name


@router.post("/signatures/import")
def import_signatures(request: Request, body: ImportIn, cu: CurrentUser = Depends(require_admin)):
    """Bulk-load a hash list. Accepts plain hashes, 'hash,name' CSV, sha256sum output and the
    MalwareBazaar CSV / txt exports. Re-importing the same list just updates names."""
    if bool(body.text) == bool(body.path):
        raise HTTPException(422, "Send either 'text' or 'path'")
    if body.text is not None:
        if len(body.text) > MAX_IMPORT_TEXT:
            raise HTTPException(413, "Pasted list is too large - import it from a file instead")
        text, label = body.text, body.label or "pasted list"
    else:
        text, fname = _read_import_file(body.path)
        label = body.label or fname
    entries, bad = parse_hash_list(text, body.default_name)
    if not entries:
        raise HTTPException(422, "No MD5 / SHA-1 / SHA-256 hashes found")
    source = f"import:{label}"[:80]
    res = _mdb(request).import_entries(entries, source, body.severity)
    res |= {"invalid_lines": bad, "source": source, "stats": _mdb(request).stats()}
    request.app.state.activity.record("scan", "Signature database updated",
                                      f"{res['added']:,} new, {res['received']:,} in list from {label}",
                                      source="scanner")
    return res


@router.patch("/signatures/{h}")
def toggle_signature(request: Request, h: str, body: SigPatch, cu: CurrentUser = Depends(require_admin)):
    row = _mdb(request).set_enabled(h, body.enabled)
    if not row:
        raise HTTPException(404, "Signature not found")
    return row


@router.delete("/signatures/{h}")
def delete_signature(request: Request, h: str, cu: CurrentUser = Depends(require_admin)):
    sig = _mdb(request).get(h)
    if not sig:
        raise HTTPException(404, "Signature not found")
    if sig["source"] == "builtin":
        raise HTTPException(403, "Built-in signatures can be disabled but not deleted")
    return {"deleted": _mdb(request).delete(h)}


@router.delete("/signatures")
def delete_signature_source(request: Request, source: str = Query(..., min_length=1, max_length=80),
                            cu: CurrentUser = Depends(require_admin)):
    """Remove everything that came from one import (source as shown in the list, e.g. import:full_sha256.txt)."""
    n = _mdb(request).delete_source(source)
    request.app.state.activity.record("scan", "Signatures removed", f"{n:,} from {source}", source="scanner")
    return {"deleted": n}


# ================================================================== exclusions / cache
class ExclusionsIn(BaseModel):
    paths: list[str] = Field(default_factory=list, max_length=500)
    extensions: list[str] = Field(default_factory=list, max_length=200)


@router.get("/exclusions")
def get_exclusions(request: Request):
    g = request.app.state.settings_store.get
    return {"paths": g("scan_excluded_paths"), "extensions": g("scan_excluded_extensions")}


@router.put("/exclusions")
def put_exclusions(request: Request, body: ExclusionsIn, cu: CurrentUser = Depends(require_admin)):
    paths = []
    for p in body.paths:
        p = os.path.expandvars(os.path.expanduser(p.strip()))
        if not p:
            continue
        if not os.path.isabs(p):
            raise HTTPException(422, f"Exclusions must be full paths: {p}")
        if len(os.path.abspath(p)) <= 3:                 # "C:\" or "/"
            raise HTTPException(422, "Excluding a whole drive would switch scanning off")
        paths.append(os.path.abspath(p))
    exts = []
    for e in body.extensions:
        e = e.strip().lower()
        if not e:
            continue
        e = e if e.startswith(".") else "." + e
        if len(e) > 16 or not e[1:].replace("_", "").replace("-", "").isalnum():
            raise HTTPException(422, f"Not a file extension: {e}")
        exts.append(e)
    request.app.state.settings_store.update({"scan_excluded_paths": list(dict.fromkeys(paths)),
                                             "scan_excluded_extensions": list(dict.fromkeys(exts))})
    request.app.state.activity.record("settings", "Scan exclusions updated",
                                      f"{len(paths)} path(s), {len(exts)} type(s)", severity="low", source="scanner")
    return get_exclusions(request)


@router.delete("/cache")
def clear_cache(request: Request, cu: CurrentUser = Depends(require_admin)):
    """Forget cached file hashes - the next scan re-reads every file."""
    return {"deleted": _sc(request).clear_cache()}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"scan", jobs:[live progress...], events:[threat / job_started / job_paused /
    job_finished ...]} twice a second while something changes, and a heartbeat every 5 s."""
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
    sc = app.state.scanner
    seq, _ = sc.events_since(10 ** 12)                 # start from "now"
    last_sent, ticks = None, 0
    try:
        await ws.send_json({"type": "scan", "jobs": sc.active(), "events": [], "hello": True})
        while True:
            await asyncio.sleep(0.5)
            ticks += 1
            if ticks % 20 == 0:
                code = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
            seq, events = sc.events_since(seq)
            jobs = sc.active()
            sig = [(j["id"], j["status"], j["files_scanned"], j["files_skipped"], j["files_found"]) for j in jobs]
            if events or sig != last_sent or ticks % 10 == 0:
                await ws.send_json({"type": "scan", "jobs": jobs, "events": events})
                last_sent = sig
    except (WebSocketDisconnect, RuntimeError):
        pass


__all__ = ["router", "stream_router", "SEVERITIES"]
