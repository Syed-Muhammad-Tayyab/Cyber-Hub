"""
Cyber Hub Backend - Reports, export & backup routes (Part 19)
Developed by Syed Muhammad Tayyab

Reports (signed-in user; you see your own reports, administrators see everyone's)
    GET    /api/reports/status | /types
    GET    /api/reports                     list
    POST   /api/reports                     {type, format, days} -> creates the file
    GET    /api/reports/preview             the report as data (what the PDF would contain)
    GET    /api/reports/{id}                details
    GET    /api/reports/{id}/download       the file itself
    DELETE /api/reports/{id}
    GET    /api/reports/logs/export         diagnostics .zip (admin): log files + activity + versions + settings

Backups (administrator)
    GET    /api/backup/status | /api/backup
    POST   /api/backup                      {mode: password|device, password?, include_quarantine?, destination?, note?}
    POST   /api/backup/verify               {id? | path?, password?}  - opens + checks a backup, changes nothing
    POST   /api/backup/restore              {id? | path?, password?, confirm}  - stages it; applied at next start
    DELETE /api/backup/restore              cancel a staged restore
    GET    /api/backup/{id}/download        the .chbackup file
    DELETE /api/backup/{id}
    GET    /api/backup/settings/export      settings as JSON
    POST   /api/backup/settings/import      {payload, only_changed?}
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.backup import BackupError, BackupService
from ..services.reports import ReportError, ReportService

router = APIRouter(prefix="/api/reports", tags=["reports"],
                   dependencies=[Depends(require_token), Depends(require_session)])
backup_router = APIRouter(prefix="/api/backup", tags=["backup"],
                          dependencies=[Depends(require_token), Depends(require_admin)])

Type = Literal["summary", "threats", "device", "network", "accounts", "activity", "full"]
Fmt = Literal["pdf", "html", "csv", "json"]


class ReportIn(BaseModel):
    type: Type = "summary"
    format: Fmt | None = None
    days: int | None = Field(None, ge=1, le=365)


class BackupIn(BaseModel):
    mode: Literal["password", "device"] = "device"
    password: str | None = Field(None, max_length=256)
    include_quarantine: bool | None = None
    destination: str | None = Field(None, max_length=1024)
    note: str | None = Field(None, max_length=200)


class BackupRef(BaseModel):
    id: int | None = None
    path: str | None = Field(None, max_length=1024)
    password: str | None = Field(None, max_length=256)
    confirm: bool = False


class SettingsIn(BaseModel):
    payload: dict[str, Any]
    only_changed: bool = False


def _rs(request: Request) -> ReportService:
    return request.app.state.reports


def _bs(request: Request) -> BackupService:
    return request.app.state.backup


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except (ReportError, BackupError) as e:
        raise HTTPException(e.status, e.message)


def _download(path, name: str, media: str) -> FileResponse:
    return FileResponse(str(path), media_type=media, filename=name,
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


# ================================================================== reports
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    return _rs(request).status(cu)


@router.get("/types")
def types(request: Request):
    return {"items": _rs(request).types(), "formats": ["pdf", "html", "csv", "json"]}


@router.get("")
def list_reports(request: Request, cu: CurrentUser = Depends(require_session), type: Type | None = None,
                 limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    return _rs(request).list(cu, limit, offset, type)


@router.post("", status_code=201)
def create_report(request: Request, body: ReportIn, cu: CurrentUser = Depends(require_session)):
    return _run(_rs(request).generate, cu, body.type, body.format, body.days)


@router.get("/preview")
def preview(request: Request, cu: CurrentUser = Depends(require_session), type: Type = "summary",
            days: int | None = Query(None, ge=1, le=365)):
    return _run(_rs(request).preview, cu, type, days)


@router.get("/logs/export")
def export_logs(request: Request, cu: CurrentUser = Depends(require_admin), days: int = Query(7, ge=1, le=90)):
    data, name = _rs(request).export_logs(cu, days)
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.get("/{rid}")
def get_report(request: Request, rid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_rs(request).get, cu, rid)


@router.get("/{rid}/download")
def download_report(request: Request, rid: int, cu: CurrentUser = Depends(require_session)):
    path, name, media = _run(_rs(request).file, cu, rid)
    return _download(path, name, media)


@router.delete("/{rid}")
def delete_report(request: Request, rid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_rs(request).delete, cu, rid)


# ================================================================== backups
@backup_router.get("/status")
def backup_status(request: Request):
    return _bs(request).status()


@backup_router.get("")
def list_backups(request: Request):
    return _bs(request).list()


@backup_router.post("", status_code=201)
def create_backup(request: Request, body: BackupIn, cu: CurrentUser = Depends(require_admin)):
    return _run(_bs(request).create, cu, body.mode, body.password, body.include_quarantine, body.destination,
                body.note)


@backup_router.post("/verify")
def verify_backup(request: Request, body: BackupRef):
    return _run(_bs(request).verify, body.id, body.path, body.password)


@backup_router.post("/restore")
def restore_backup(request: Request, body: BackupRef, cu: CurrentUser = Depends(require_admin)):
    return _run(_bs(request).restore, cu, body.id, body.path, body.password, body.confirm)


@backup_router.delete("/restore")
def cancel_restore(request: Request):
    return _bs(request).cancel_restore()


@backup_router.get("/settings/export")
def export_settings(request: Request):
    return _bs(request).export_settings()


@backup_router.post("/settings/import")
def import_settings(request: Request, body: SettingsIn, cu: CurrentUser = Depends(require_admin)):
    return _run(_bs(request).import_settings, cu, body.payload, body.only_changed)


@backup_router.get("/{bid}/download")
def download_backup(request: Request, bid: int):
    r = _run(_bs(request)._row, bid)
    import os
    if not os.path.isfile(r["file_path"]):
        raise HTTPException(410, "The backup file no longer exists")
    return _download(r["file_path"], r["file_name"], "application/octet-stream")


@backup_router.delete("/{bid}")
def delete_backup(request: Request, bid: int, cu: CurrentUser = Depends(require_admin)):
    return _run(_bs(request).delete, cu, bid)
