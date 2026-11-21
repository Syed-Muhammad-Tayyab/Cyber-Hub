"""
Cyber Hub Backend - Threat Intelligence routes (Part 15)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked Cyber Hub session.

Check:  POST /api/intel/check {value, online?, deep?, full_url?}  -> verdict malicious | suspicious | low_risk |
        clean | unknown, 0-100 score, reasons, feed matches, phishing findings, online answers, one-click actions.
Feeds:  GET /feeds, POST /feeds/refresh (job), POST /feeds (custom, admin), PATCH / DELETE /feeds/{id}.
Lists:  /blocklist (anyone adds, admin removes), /allowlist (admin adds), /import, /export.
Search: GET /iocs?q=..., GET /hunt?value=... (where this indicator was seen on this PC).
Alerts: GET /events (connection matches, retro-hunt finds, feed problems), POST /events/{id}/block, /events/ack.

Errors: 403 admin needed / address not allowed, 404 not found, 409 conflict (already updating, allow-listed,
key missing), 413 too large, 422 bad input, 429 rate limit (Retry-After), 501/503 module unavailable.
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.threat_intel import IntelError, ThreatIntelService

router = APIRouter(prefix="/api/intel", tags=["intel"], dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/intel", tags=["intel"])

IocType = Literal["ip", "cidr", "domain", "url", "email", "md5", "sha1", "sha256"]
Sev = Literal["info", "low", "medium", "high", "critical"]
Fmt = Literal["auto", "lines", "csv", "hosts", "stix"]


def _ti(request: Request) -> ThreatIntelService:
    return request.app.state.intel


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except IntelError as e:
        headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
        raise HTTPException(e.status, e.message, headers=headers)


# ================================================================== overview
@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    """Threat-intel card: features, settings, health (indicators loaded, feeds OK / stale / needing a key, open
    alerts), online providers, running feed update, unread alerts."""
    return _ti(request).status(cu)


@router.get("/health")
def health(request: Request, cu: CurrentUser = Depends(require_session)):
    return _ti(request).health(cu.user["id"])


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365), cu: CurrentUser = Depends(require_session)):
    """Graphs: indicators by type / category / feed, top malware families, alerts per day, your checks per day by
    verdict, most-matched addresses."""
    return _ti(request).summary(cu, days)


# ================================================================== check
class CheckIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048,
                       description="IP, CIDR, domain, URL, e-mail, MD5 / SHA-1 / SHA-256 (defanged forms accepted)")
    online: bool | None = Field(None, description="Ask VirusTotal / abuse.ch / AbuseIPDB (default: "
                                                  "intel_online_lookup). Only the indicator is sent.")
    deep: bool = Field(False, description="URLs / domains: open the page read-only (redirects, fake login forms, "
                                          "certificate and domain age)")
    full_url: bool = Field(False, description="Send the full URL incl. ?query online (may contain personal tokens)")


@router.post("/check")
def check(request: Request, body: CheckIn, cu: CurrentUser = Depends(require_session)):
    """Is this IP / domain / link / e-mail / file hash dangerous?"""
    return _run(_ti(request).check, cu, body.value, body.online, body.deep, body.full_url)


class BulkIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=1_000_000, description="Any text - e-mail, report, chat")
    online: bool = Field(False, description="Online lookups too (only when 20 indicators or fewer)")


@router.post("/check/bulk")
def check_bulk(request: Request, body: BulkIn, cu: CurrentUser = Depends(require_session)):
    """Pull every indicator out of a pasted text and check them all (offline, up to 500)."""
    return _run(_ti(request).check_bulk, cu, body.text, body.online)


@router.get("/checks")
def checks(request: Request, limit: int = Query(50, ge=1, le=500),
           verdict: Literal["malicious", "suspicious", "low_risk", "clean", "unknown"] | None = None,
           cu: CurrentUser = Depends(require_session)):
    """Your recent checks (query strings are never stored)."""
    return _ti(request).checks(cu, limit, verdict)


@router.delete("/checks")
def clear_checks(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _ti(request).clear_checks(cu)}


# ================================================================== IOC search / hunt
@router.get("/iocs")
def iocs(request: Request, q: str | None = Query(None, max_length=2048), type: IocType | None = None,
         feed: str | None = Query(None, max_length=60), threat: str | None = Query(None, max_length=120),
         category: str | None = Query(None, max_length=40), limit: int = Query(100, ge=1, le=1000),
         offset: int = Query(0, ge=0)):
    """Search the local threat-intel database (exact match when q is an indicator, else text search on value,
    malware family and tags)."""
    return _ti(request).search(q, type, feed, threat, category, limit, offset)


@router.get("/hunt")
def hunt(request: Request, value: str = Query(..., min_length=1, max_length=2048),
         limit: int = Query(50, ge=1, le=500)):
    """Has this indicator ever shown up on THIS PC? Antivirus cache + detections, quarantine, real-time downloads
    (Mark of the Web), network / firewall / web events, saved websites, activity log, live connections."""
    return _run(_ti(request).hunt, value, limit)


# ================================================================== feeds
@router.get("/feeds")
def feeds(request: Request):
    return _ti(request).feeds()


@router.get("/feeds/{fid}")
def feed(request: Request, fid: int):
    return _run(_ti(request).feed, fid)


class FeedIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    url: str = Field(..., min_length=10, max_length=2048, description="https:// on a public address")
    format: Fmt = "auto"
    column: str | None = Field(None, max_length=60, description="CSV: column name or number")
    category: str = Field("custom", max_length=40)
    severity: Sev = "high"
    refresh_hours: int | None = Field(None, ge=1, le=720)
    enabled: bool = True
    refresh_now: bool = True


@router.post("/feeds", status_code=201)
def add_feed(request: Request, body: FeedIn, cu: CurrentUser = Depends(require_admin)):
    """Admin: add your own feed (plain list, CSV, hosts file or STIX bundle over https)."""
    ti = _ti(request)
    f = _run(ti.add_feed, cu, body.name, body.url, body.format, body.column, body.category, body.severity,
             body.refresh_hours, body.enabled)
    if body.refresh_now and body.enabled:
        try:
            f["job"] = ti.refresh(cu, [f["id"]])
        except IntelError:
            f["job"] = None
    return f


class FeedPatch(BaseModel):
    enabled: bool | None = None
    refresh_hours: int | None = Field(None, ge=1, le=720)
    reset_refresh_hours: bool = False
    severity: Sev | None = None
    name: str | None = Field(None, max_length=80)


@router.patch("/feeds/{fid}")
def patch_feed(request: Request, fid: int, body: FeedPatch, cu: CurrentUser = Depends(require_session)):
    """Switch a feed on (anyone) or off / change it (admin)."""
    rh = None if body.reset_refresh_hours else (body.refresh_hours if body.refresh_hours is not None else ...)
    return _run(_ti(request).update_feed, cu, fid, body.enabled, rh, body.severity, body.name)


@router.delete("/feeds/{fid}")
def delete_feed(request: Request, fid: int, cu: CurrentUser = Depends(require_admin)):
    return _run(_ti(request).delete_feed, cu, fid)


class RefreshIn(BaseModel):
    feed_ids: list[int] | None = Field(None, max_length=100)
    force: bool = Field(False, description="Download even if not due / unchanged")


@router.post("/feeds/refresh")
def refresh(request: Request, body: RefreshIn, cu: CurrentUser = Depends(require_session)):
    """Update feeds now (background job - poll /jobs/{id})."""
    return _run(_ti(request).refresh, cu, body.feed_ids, body.force)


@router.get("/jobs")
def jobs(request: Request):
    return _ti(request).jobs()


@router.get("/jobs/{job_id}")
def job(request: Request, job_id: str):
    return _run(_ti(request).job, job_id)


# ================================================================== block list / allow list
@router.get("/blocklist")
def blocklist(request: Request, q: str | None = Query(None, max_length=200), limit: int = Query(100, ge=1, le=1000),
              offset: int = Query(0, ge=0)):
    return _ti(request).blocklist(q, limit, offset)


class BlockIn(BaseModel):
    values: list[str] | None = Field(None, max_length=5000)
    text: str | None = Field(None, max_length=2_000_000, description="Free text - indicators are extracted")
    severity: Sev = "high"
    note: str | None = Field(None, max_length=200)


@router.post("/blocklist")
def block_add(request: Request, body: BlockIn, cu: CurrentUser = Depends(require_session)):
    """Add IPs / ranges / domains / URLs / e-mails / hashes to your own block list (hashes also become antivirus
    signatures; addresses are matched against live connections)."""
    if not body.values and not body.text:
        raise HTTPException(422, "Send values or text")
    return _run(_ti(request).block_add, cu, body.values, body.text, body.severity, body.note)


class BlockRemove(BaseModel):
    ids: list[int] | None = Field(None, max_length=5000)
    value: str | None = Field(None, max_length=2048)


@router.post("/blocklist/remove")
def block_remove(request: Request, body: BlockRemove, cu: CurrentUser = Depends(require_admin)):
    return _run(_ti(request).block_remove, cu, body.ids, body.value)


class ImportIn(BaseModel):
    text: str | None = Field(None, max_length=20_000_000)
    path: str | None = Field(None, max_length=4096, description="File on this PC (.txt / .csv / .json / .zip)")
    format: Fmt = "auto"
    column: str | None = Field(None, max_length=60)
    severity: Sev = "high"
    note: str | None = Field(None, max_length=200)


@router.post("/import")
def import_iocs(request: Request, body: ImportIn, cu: CurrentUser = Depends(require_session)):
    """Import a list / CSV / hosts file / STIX 2.x bundle into your block list."""
    return _run(_ti(request).import_iocs, cu, body.text, body.path, body.format, body.column, body.severity, body.note)


@router.get("/export")
def export(request: Request, format: Literal["csv", "txt", "stix", "json"] = "csv",
           what: Literal["blocklist", "matches"] = "blocklist"):
    """Download your block list (or everything Cyber Hub matched) as CSV, plain text, STIX 2.1 or JSON."""
    body, media, name = _run(_ti(request).export, format, what)
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/allowlist")
def allowlist(request: Request):
    return _ti(request).allow_list()


class AllowIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    note: str | None = Field(None, max_length=200)


@router.post("/allowlist", status_code=201)
def allow_add(request: Request, body: AllowIn, cu: CurrentUser = Depends(require_admin)):
    """Admin: never flag this address / domain / hash again (false positive)."""
    return _run(_ti(request).allow_add, cu, body.value, body.note)


@router.delete("/allowlist/{aid}")
def allow_remove(request: Request, aid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_ti(request).allow_remove, cu, aid)


# ================================================================== firewall
class BlockIpIn(BaseModel):
    ip: str = Field(..., min_length=2, max_length=64)
    minutes: int | None = Field(None, ge=1, le=60 * 24 * 365)
    reason: str | None = Field(None, max_length=200)


@router.post("/block-ip")
def block_ip(request: Request, body: BlockIpIn, cu: CurrentUser = Depends(require_session)):
    """One click: block an internet address in the firewall (Part 9 block, both directions, removable there)."""
    return _run(_ti(request).block_ip, cu, body.ip, body.minutes, body.reason)


# ================================================================== providers (online keys)
@router.get("/providers")
def providers(request: Request):
    return _ti(request).providers()


class KeyIn(BaseModel):
    key: str | None = Field(None, max_length=256, description="Empty / null = remove")


@router.put("/providers/{provider}/key")
def set_key(request: Request, provider: str, body: KeyIn, cu: CurrentUser = Depends(require_admin)):
    """Admin: AbuseIPDB key (VirusTotal + abuse.ch keys are shared with the antivirus under /api/lookup/keys)."""
    return _run(_ti(request).set_key, cu, provider, body.key)


# ================================================================== watch + events
@router.post("/watch/run")
def watch_run(request: Request):
    """Match this PC's internet connections against the feeds right now."""
    return _ti(request).watch_once()


@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0), severity: Sev | None = None,
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), cu: CurrentUser = Depends(require_session)):
    """Alerts: programs talking to known bad addresses, files / downloads that newer intel now flags, automatic
    blocks, feed problems."""
    return _ti(request).events(cu, after_id, severity, kind, unacknowledged, limit)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn, cu: CurrentUser = Depends(require_session)):
    return {"acknowledged": _ti(request).acknowledge(cu, body.ids)}


@router.post("/events/{eid}/block")
def block_event(request: Request, eid: int, minutes: int | None = Query(None, ge=1, le=60 * 24 * 365),
                cu: CurrentUser = Depends(require_session)):
    """One-click fix for a connection alert: block that address in the firewall."""
    return _run(_ti(request).block_event, cu, eid, minutes)


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"deleted": _ti(request).clear_events(cu)}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"intel", jobs:[running feed update], events:[new intel_events], unacknowledged} every second."""
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
    svc: ThreatIntelService = app.state.intel

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
                await ws.send_json({"type": "intel", "jobs": svc.jobs()["running"],
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
