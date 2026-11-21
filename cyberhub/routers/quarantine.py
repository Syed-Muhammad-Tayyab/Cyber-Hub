"""
Cyber Hub Backend - Quarantine & Threat History routes (Part 6)
Developed by Syed Muhammad Tayyab

Who can do what (same idea as Windows Security):
  * any signed-in user  - quarantine / remove threats, delete quarantine items, verify, re-scan, view history
  * administrator       - restore from quarantine, allow threats, dismiss, force-quarantine OS files,
                          empty the vault, clear history

Quarantine / restore / delete events are also pushed on the scan WebSocket
(/api/scan/stream) as type "quarantined" | "restored" | "quarantine_deleted".
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.quarantine import QuarantineError
from ..services.vault import VaultError

router = APIRouter(prefix="/api/quarantine", tags=["quarantine"],
                   dependencies=[Depends(require_token), Depends(require_session)])
threats_router = APIRouter(prefix="/api/threats", tags=["threat history"],
                           dependencies=[Depends(require_token), Depends(require_session)])

DetStatus = Literal["history", "all", "active", "quarantined", "restored", "removed", "allowed", "dismissed",
                    "resolved", "superseded"]
Severity = Literal["low", "medium", "high", "critical"]


def _q(request: Request):
    return request.app.state.quarantine


def _h(request: Request):
    return request.app.state.threat_history


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except QuarantineError as e:
        raise HTTPException(e.status, e.message)
    except VaultError as e:
        raise HTTPException(500, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))


def _admin_if(force: bool, cu: CurrentUser) -> None:
    if force and cu.user["role"] != "admin":
        raise HTTPException(403, "Administrator rights required for force=true")


# ================================================================== quarantine vault
class QuarantineIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)
    threat_name: str | None = Field(None, max_length=120)
    note: str | None = Field(None, max_length=300)
    kill_processes: bool | None = Field(None, description="Stop programs running from the file (default: setting)")
    force: bool = Field(False, description="Admin only: allow operating-system files")


class RestoreIn(BaseModel):
    destination: str | None = Field(None, max_length=4096, description="Folder to restore into (default: original place)")
    conflict: Literal["rename", "overwrite", "fail"] = "rename"
    allow: bool = Field(False, description="Also add the file to allowed threats so scans stop reporting it")


class PurgeIn(BaseModel):
    older_than_days: int | None = Field(None, ge=0, le=3650, description="Omit to empty the whole vault")


@router.get("")
def list_quarantine(request: Request, status: Literal["quarantined", "restored", "deleted", "missing", "all"] = "quarantined",
                    search: str | None = Query(None, max_length=200),
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Quarantined items (newest first) with expiry date."""
    return _q(request).list(status, search, limit, offset)


@router.get("/stats")
def quarantine_stats(request: Request):
    """Item count, original / encrypted size, % of the size limit, by severity, retention, vault info."""
    return _q(request).stats()


@router.post("/vault/check")
def vault_check(request: Request, cu: CurrentUser = Depends(require_session)):
    """Finds missing vault files, removes orphan / temp files, rolls back unfinished quarantines."""
    return _q(request).check_vault(cu.user["username"])


@router.post("", status_code=201)
def quarantine_file(request: Request, body: QuarantineIn, cu: CurrentUser = Depends(require_session)):
    """Quarantine any file by path. If it's a known threat its name / severity are used."""
    _admin_if(body.force, cu)
    return _run(_q(request).quarantine_path, body.path, cu.user["username"], body.threat_name,
                body.kill_processes, body.force, body.note)


@router.post("/purge")
def purge(request: Request, body: PurgeIn, cu: CurrentUser = Depends(require_admin)):
    """Permanently delete every quarantined item (or only those older than N days)."""
    return {"deleted": _run(_q(request).purge, cu.user["username"], body.older_than_days)}


@router.get("/{qid}")
def get_item(request: Request, qid: str):
    return _run(_q(request).get, qid)


@router.post("/{qid}/restore")
def restore_item(request: Request, qid: str, body: RestoreIn, cu: CurrentUser = Depends(require_admin)):
    """Decrypt back to the original place (or a folder you choose). SHA-256 verified; modified time,
    permissions and Mark of the Web come back too."""
    return _run(_q(request).restore, qid, cu.user["username"], body.destination, body.conflict, body.allow)


@router.delete("/{qid}")
def delete_item(request: Request, qid: str, cu: CurrentUser = Depends(require_session)):
    """Permanently delete: the vault file and its key are destroyed."""
    return _run(_q(request).delete, qid, cu.user["username"])


@router.post("/{qid}/verify")
def verify_item(request: Request, qid: str):
    """Decrypts in memory and checks every block + the original SHA-256."""
    return _run(_q(request).verify, qid)


@router.post("/{qid}/rescan")
def rescan_item(request: Request, qid: str):
    """Is it still detected with today's signatures? (handy after a false alarm)"""
    return _run(_q(request).rescan, qid)


# ================================================================== threat history
class ThreatActionIn(BaseModel):
    kill_processes: bool | None = None
    force: bool = False


class AllowIn(BaseModel):
    note: str | None = Field(None, max_length=300)


class BulkIn(BaseModel):
    action: Literal["quarantine", "remove", "allow", "dismiss"]
    ids: list[int] | None = Field(None, max_length=1000, description="Omit = every active threat ('Start actions')")


class AllowedIn(BaseModel):
    sha256: str | None = Field(None, min_length=64, max_length=64)
    threat_name: str | None = Field(None, min_length=1, max_length=200)
    note: str | None = Field(None, max_length=300)


@threats_router.get("/summary")
def threats_summary(request: Request, days: int = Query(30, ge=1, le=365)):
    """Protection-history dashboard: status counts, active by severity, per-day detected / quarantined /
    restored / removed / allowed, top threats, top folders, detection methods, quarantine stats."""
    return _h(request).summary(days)


@threats_router.get("")
def threat_list(request: Request, status: DetStatus = "history", severity: Severity | None = None,
                search: str | None = Query(None, max_length=200), days: int | None = Query(None, ge=1, le=3650),
                limit: int = Query(100, ge=1, le=2000), offset: int = Query(0, ge=0)):
    """Protection history. status=history = everything except superseded duplicates."""
    return _h(request).list(status, severity, search, days, limit, offset)


@threats_router.get("/export.csv")
def threat_export(request: Request, status: DetStatus = "history", severity: Severity | None = None,
                  search: str | None = Query(None, max_length=200), days: int | None = Query(None, ge=1, le=3650)):
    csv_text = _h(request).export_csv(status, severity, search, days)
    return Response(csv_text, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="cyberhub-threat-history.csv"'})


@threats_router.delete("/history")
def clear_history(request: Request, older_than_days: int = Query(0, ge=0, le=3650),
                  cu: CurrentUser = Depends(require_admin)):
    """Forget finished entries. Active / quarantined threats and allowed entries are kept."""
    return _h(request).clear(cu.user["username"], older_than_days)


@threats_router.get("/allowed")
def allowed_list(request: Request):
    return {"items": request.app.state.allowlist.list()}


@threats_router.post("/allowed", status_code=201)
def allowed_add(request: Request, body: AllowedIn, cu: CurrentUser = Depends(require_admin)):
    """Allow a file by SHA-256, or every file matching a threat name."""
    if bool(body.sha256) == bool(body.threat_name):
        raise HTTPException(422, "Send either sha256 or threat_name")
    kind, value = ("sha256", body.sha256) if body.sha256 else ("threat_name", body.threat_name)
    entry, created = _run(request.app.state.allowlist.add, kind, value, cu.user["username"], note=body.note)
    if created:
        request.app.state.activity.record("threat", "Threat allowed", f"{kind}: {value}", severity="medium",
                                          source="quarantine")
    return entry


@threats_router.delete("/allowed/{entry_id}")
def allowed_remove(request: Request, entry_id: int, cu: CurrentUser = Depends(require_admin)):
    return _run(_h(request).unallow, entry_id, cu.user["username"])


@threats_router.post("/actions")
def bulk_actions(request: Request, body: BulkIn, cu: CurrentUser = Depends(require_session)):
    """Apply one action to many threats ('Start actions' in Windows Security). Never stops on the
    first failure - every id gets its own result."""
    if body.action in ("allow", "dismiss") and cu.user["role"] != "admin":
        raise HTTPException(403, "Administrator rights required")
    db = request.app.state.db
    ids = body.ids if body.ids is not None else [r["id"] for r in db.fetchall(
        "SELECT id FROM scan_detections WHERE status='active' ORDER BY id")]
    user, results = cu.user["username"], []
    for i in ids:
        try:
            if body.action == "quarantine":
                r = _q(request).quarantine_detection(i, user)
            elif body.action == "remove":
                r = _q(request).remove_detection(i, user)
            elif body.action == "allow":
                r = _h(request).allow_detection(i, user)
            else:
                from ..services.scanner import ScanError
                try:
                    r = request.app.state.scanner.dismiss(i, user)
                except ScanError as e:
                    raise QuarantineError(e.status, e.message)
            results.append({"id": i, "ok": True, "result": r})
        except QuarantineError as e:
            results.append({"id": i, "ok": False, "status": e.status, "error": e.message})
        except Exception as e:                                       # keep going with the rest
            results.append({"id": i, "ok": False, "status": 500, "error": f"{type(e).__name__}: {e}"[:300]})
    ok = sum(r["ok"] for r in results)
    return {"action": body.action, "requested": len(ids), "succeeded": ok, "failed": len(ids) - ok,
            "results": results}


@threats_router.get("/{det_id}")
def threat_details(request: Request, det_id: int):
    """One threat with its full timeline, quarantine item, allowed status and available actions."""
    return _run(_h(request).get, det_id)


@threats_router.post("/{det_id}/quarantine")
def threat_quarantine(request: Request, det_id: int, body: ThreatActionIn | None = None,
                      cu: CurrentUser = Depends(require_session)):
    body = body or ThreatActionIn()
    _admin_if(body.force, cu)
    return _run(_q(request).quarantine_detection, det_id, cu.user["username"], body.kill_processes, body.force)


@threats_router.post("/{det_id}/remove")
def threat_remove(request: Request, det_id: int, body: ThreatActionIn | None = None,
                  cu: CurrentUser = Depends(require_session)):
    """Quarantine and immediately destroy the copy (no restore possible)."""
    body = body or ThreatActionIn()
    _admin_if(body.force, cu)
    return _run(_q(request).remove_detection, det_id, cu.user["username"], body.kill_processes, body.force)


@threats_router.post("/{det_id}/allow")
def threat_allow(request: Request, det_id: int, body: AllowIn | None = None, cu: CurrentUser = Depends(require_admin)):
    """'Allow on device': this file's SHA-256 won't be reported again."""
    return _run(_h(request).allow_detection, det_id, cu.user["username"], (body or AllowIn()).note)


@threats_router.post("/{det_id}/dismiss")
def threat_dismiss(request: Request, det_id: int, cu: CurrentUser = Depends(require_admin)):
    from ..services.scanner import ScanError
    try:
        return request.app.state.scanner.dismiss(det_id, cu.user["username"])
    except ScanError as e:
        raise HTTPException(e.status, e.message)
