"""
Cyber Hub Backend - Website / Developer Scanner routes (Part 14)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked Cyber Hub session.
Scans run as background jobs: the POST answers at once with {id, kind, status: running, progress};
poll GET /api/web/jobs/{id} (or listen on /api/web/stream), then read the full report with
GET /api/web/scans/{id}.

Errors: 403 address / folder not allowed, 404 not found, 409 already scanning that target,
422 bad input / host not found, 428 confirm_owner needed for active checks (exposed files, ports)
on a public site, 429 too many scans running, 501/503 module or service unavailable.
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.web_scanner import SITE_CHECKS, WebError, WebScannerService

router = APIRouter(prefix="/api/web", tags=["web"], dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/web", tags=["web"])

Check = Literal["https", "headers", "content", "tech", "exposure", "ports"]
Eco = Literal["npm", "PyPI", "Packagist"]


def _ws(request: Request) -> WebScannerService:
    return request.app.state.web


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except WebError as e:
        raise HTTPException(e.status, e.message)


# ================================================================== overview
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    """Web scanner card: features, settings, health (score, grade, open issues, certificates, vulnerable packages,
    exposed dev servers), running scans, vulnerability-database status, unread alerts."""
    return _ws(request).status(cu)


@router.get("/health")
def health(request: Request, cu: CurrentUser = Depends(require_session)):
    return _ws(request).health(cu.user["id"])


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365), cu: CurrentUser = Depends(require_session)):
    """Graphs: scans per day + average score, findings by category / severity, grades, score history per target,
    certificate expiry timeline, top vulnerable packages, technologies seen."""
    return _ws(request).summary(cu, days)


# ================================================================== website scan
class SiteScanIn(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048, description="example.com, https://site.pk/shop, "
                                                                        "localhost:5173 ...")
    checks: list[Check] | None = Field(None, description=f"Default: all of {', '.join(SITE_CHECKS)}")
    confirm_owner: bool = Field(False, description="I own / manage this site -> exposed-file and port checks allowed")
    save: bool = False
    monitor: bool | None = None
    label: str | None = Field(None, max_length=80)


@router.post("/scan")
def scan_site(request: Request, body: SiteScanIn, cu: CurrentUser = Depends(require_session)):
    """Scan a website: HTTPS + certificate, security headers, cookies, page content, software versions; plus exposed
    files and open ports on your own sites (confirm_owner) / this PC / your network."""
    return _run(_ws(request).start_site_scan, cu, body.target, body.checks, body.confirm_owner, body.save,
                body.monitor, body.label)


# ================================================================== project scan
class ProjectScanIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096, description="Project folder on this PC")
    online: bool | None = Field(None, description="Ask osv.dev (package names + versions only). Default: "
                                                  "web_dep_online")
    secrets: bool | None = Field(None, description="Also look for keys / passwords in the code (default: "
                                                   "web_secret_scan)")
    save: bool = False
    monitor: bool | None = None
    label: str | None = Field(None, max_length=80)


@router.post("/project/scan")
def scan_project(request: Request, body: ProjectScanIn, cu: CurrentUser = Depends(require_session)):
    """Check a code project: vulnerable npm / PyPI / Composer packages (lockfiles), secrets in the code, risky
    settings (.env not git-ignored, debug on in production, tokens in .npmrc)."""
    return _run(_ws(request).start_project_scan, cu, body.path, body.online, body.secrets, body.save, body.monitor,
                body.label)


class PackageIn(BaseModel):
    ecosystem: Eco
    name: str = Field(..., min_length=1, max_length=214)
    version: str = Field(..., min_length=1, max_length=64)
    online: bool | None = None


@router.post("/packages/check")
def check_package(request: Request, body: PackageIn):
    """Is this one package version safe? (offline database + osv.dev)"""
    return _run(_ws(request).check_package, body.ecosystem, body.name, body.version, body.online)


# ================================================================== jobs & stored scans
@router.get("/jobs")
def jobs(request: Request, limit: int = Query(30, ge=1, le=500),
         kind: Literal["site", "project", "vulndb"] | None = None, cu: CurrentUser = Depends(require_session)):
    return _ws(request).jobs_for(cu, limit, kind)


@router.get("/jobs/{job_id}")
def job(request: Request, job_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).job, cu, job_id)


@router.post("/jobs/{job_id}/cancel")
def cancel(request: Request, job_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).cancel, cu, job_id)


@router.get("/scans")
def scans(request: Request, kind: Literal["site", "project"] | None = None, target_id: int | None = None,
          limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
          cu: CurrentUser = Depends(require_session)):
    return _ws(request).scans(cu, kind, target_id, limit, offset)


@router.get("/scans/{scan_id}")
def scan(request: Request, scan_id: str, cu: CurrentUser = Depends(require_session)):
    """Full report: findings (with advice), passed checks, score + grade per category, TLS / certificate,
    technologies, cookies (names + flags only), open ports, packages, changes since the previous scan."""
    return _run(_ws(request).scan, cu, scan_id)


@router.delete("/scans/{scan_id}")
def delete_scan(request: Request, scan_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).delete_scan, cu, scan_id)


# ================================================================== saved targets
class TargetIn(BaseModel):
    kind: Literal["site", "project"]
    target: str = Field(..., min_length=1, max_length=4096)
    label: str | None = Field(None, max_length=80)
    monitor: bool | None = None
    owner_confirmed: bool | None = None


class TargetPatch(BaseModel):
    label: str | None = Field(None, max_length=80)
    monitor: bool | None = None
    owner_confirmed: bool | None = None


@router.get("/targets")
def targets(request: Request, kind: Literal["site", "project"] | None = None,
            cu: CurrentUser = Depends(require_session)):
    return {"items": _ws(request).targets(cu, kind)}


@router.post("/targets")
def add_target(request: Request, body: TargetIn, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).save_target, cu, body.kind, body.target, body.label, body.monitor, body.owner_confirmed)


@router.patch("/targets/{tid}")
def patch_target(request: Request, tid: int, body: TargetPatch, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).update_target, cu, tid, body.label, body.monitor, body.owner_confirmed)


@router.delete("/targets/{tid}")
def delete_target(request: Request, tid: int, delete_scans: bool = False, cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).delete_target, cu, tid, delete_scans)


@router.get("/targets/{tid}/history")
def target_history(request: Request, tid: int, limit: int = Query(50, ge=1, le=500),
                   cu: CurrentUser = Depends(require_session)):
    return _run(_ws(request).target_history, cu, tid, limit)


@router.post("/targets/{tid}/scan")
def scan_target(request: Request, tid: int, cu: CurrentUser = Depends(require_session)):
    """Scan a saved site / project again (sites you confirmed get the full scan)."""
    w = _ws(request)
    t = _run(w.get_target, cu, tid)
    if t["kind"] == "site":
        return _run(w.start_site_scan, cu, t["target"])
    return _run(w.start_project_scan, cu, t["target"])


# ================================================================== dev servers on this PC
@router.get("/dev-servers")
def dev_servers(request: Request, refresh: bool = False):
    """Dev servers listening on this PC (Vite, React, Django, Flask, Jupyter, the Node debugger ...) with whether
    other devices can reach them - Part 10 listening ports + the Part 9 firewall's real verdict."""
    return _ws(request).dev_servers(refresh)


@router.post("/dev-servers/{port}/block")
def block_dev_server(request: Request, port: int, cu: CurrentUser = Depends(require_session)):
    """One-click fix: block incoming connections to that port in the firewall (Part 9 block, can be removed there)."""
    if not 1 <= port <= 65535:
        raise HTTPException(422, "Port must be 1-65535")
    return _run(_ws(request).block_dev_server, cu, port)


@router.post("/dev-servers/{port}/scan")
def scan_dev_server(request: Request, port: int, cu: CurrentUser = Depends(require_session)):
    """Run the website scan against http://127.0.0.1:<port>/ (all checks - it is your own PC)."""
    if not 1 <= port <= 65535:
        raise HTTPException(422, "Port must be 1-65535")
    return _run(_ws(request).start_site_scan, cu, f"http://127.0.0.1:{port}/")


# ================================================================== vulnerability database
@router.get("/vulndb")
def vulndb(request: Request):
    """Offline OSV copy + online cache: records per ecosystem, last import."""
    return _ws(request).vulndb_status()


class VulnImportIn(BaseModel):
    path: str | None = Field(None, max_length=4096, description="OSV all.zip / .json file or folder on this PC")
    download: bool = Field(False, description="Download the latest all.zip for each ecosystem from OSV instead")
    ecosystems: list[Eco] | None = None


@router.post("/vulndb/import")
def vulndb_import(request: Request, body: VulnImportIn, cu: CurrentUser = Depends(require_admin)):
    """Admin: import (or download) the OSV database for offline checks - a job."""
    if bool(body.path) == bool(body.download):
        raise HTTPException(422, "Send either path or download=true")
    return _run(_ws(request).start_vulndb_import, cu, body.path, body.ecosystems, body.download)


@router.delete("/vulndb")
def vulndb_clear(request: Request, source: Literal["import", "online"] | None = None,
                 cu: CurrentUser = Depends(require_admin)):
    return _ws(request).clear_vulndb(source)


# ================================================================== events
@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0),
           severity: Literal["info", "low", "medium", "high", "critical"] | None = None,
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), cu: CurrentUser = Depends(require_session)):
    """Alerts: critical problems found, new problems on monitored targets, grade drops, certificates expiring,
    unreachable sites, new vulnerable packages, dev servers reachable from the network."""
    return _ws(request).events(cu, after_id, severity, kind, unacknowledged, limit)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn, cu: CurrentUser = Depends(require_session)):
    return {"acknowledged": _ws(request).acknowledge(cu, body.ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _ws(request).clear_events(cu)}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"web", jobs:[running scans with progress], events:[new web_events], unacknowledged} every second."""
    app = ws.app
    from ..services.accounts import AuthError

    def check_session():
        try:
            _s, u = app.state.accounts.authenticate(session, allow_locked=False, touch=False)
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
    svc: WebScannerService = app.state.web

    class _CU:
        def __init__(self, u):
            self.user = u
    cu = _CU(user)
    last_id = svc.events(cu, limit=1)["last_id"]
    ticks = 0
    try:
        while True:
            if ticks % 2 == 0:
                ev = svc.events(cu, after_id=last_id, limit=50)
                if ev["items"]:
                    last_id = max(e["id"] for e in ev["items"])
                await ws.send_json({"type": "web", "jobs": svc.jobs_for(cu, limit=1)["running"],
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
