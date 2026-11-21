"""
Cyber Hub Backend - Notification center routes (Part 17)
Developed by Syed Muhammad Tayyab

Every route needs the API token + a signed-in, unlocked session.

GET    /api/notifications                 list (status unread|open|dismissed|all, source, severity, min_severity,
                                          search, after_id, limit, offset) + unread count
GET    /api/notifications/summary         unread by severity, per source, per day, toast counts
GET    /api/notifications/status          toast backend, quiet hours right now, sources, settings
GET    /api/notifications/{id}
POST   /api/notifications/read            {ids?}  (no ids = everything)
POST   /api/notifications/unread          {ids}
POST   /api/notifications/dismiss         {ids?}  (no ids = everything)
POST   /api/notifications/collect         pull new events from all modules now (the worker does it every 3 s)
POST   /api/notifications/test            show a test toast
DELETE /api/notifications                 delete (dismissed_only=true keeps open ones); shared ones need admin
WS     /api/notifications/stream?token=&session=   pushes new notifications + the unread count
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_session, require_token
from ..services.notifications import NotificationCenter, NotifyError

router = APIRouter(prefix="/api/notifications", tags=["notifications"],
                   dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/notifications", tags=["notifications"])

Sev = Literal["info", "low", "medium", "high", "critical"]


class Ids(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


class IdsRequired(BaseModel):
    ids: list[int] = Field(..., min_length=1, max_length=1000)


def _nc(request: Request) -> NotificationCenter:
    return request.app.state.notifications


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except NotifyError as e:
        raise HTTPException(e.status, e.message)


@router.get("")
def list_notifications(request: Request, cu: CurrentUser = Depends(require_session),
                       status: Literal["unread", "open", "dismissed", "all"] = "open", source: str | None = None,
                       severity: Sev | None = None, min_severity: Sev | None = None,
                       search: str | None = Query(None, max_length=100), after_id: int = Query(0, ge=0),
                       limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    return _run(_nc(request).list, cu, status, source, severity, min_severity, after_id, search, limit, offset)


@router.get("/summary")
def summary(request: Request, cu: CurrentUser = Depends(require_session), days: int = Query(14, ge=1, le=365)):
    return _nc(request).summary(cu, days)


@router.get("/status")
def status(request: Request, cu: CurrentUser = Depends(require_session)):
    return _nc(request).status(cu)


@router.post("/read")
def mark_read(request: Request, body: Ids, cu: CurrentUser = Depends(require_session)):
    return {"updated": _nc(request).mark_read(cu, body.ids), "unread": _nc(request).unread(cu)}


@router.post("/unread")
def mark_unread(request: Request, body: IdsRequired, cu: CurrentUser = Depends(require_session)):
    return {"updated": _nc(request).mark_unread(cu, body.ids), "unread": _nc(request).unread(cu)}


@router.post("/dismiss")
def dismiss(request: Request, body: Ids, cu: CurrentUser = Depends(require_session)):
    return {"updated": _nc(request).dismiss(cu, body.ids), "unread": _nc(request).unread(cu)}


@router.post("/collect")
def collect(request: Request, cu: CurrentUser = Depends(require_session)):
    return {"created": _nc(request).collect(), "unread": _nc(request).unread(cu)}


@router.post("/test")
def test_toast(request: Request, cu: CurrentUser = Depends(require_session)):
    return _nc(request).test(cu)


@router.delete("")
def clear(request: Request, cu: CurrentUser = Depends(require_session), dismissed_only: bool = False):
    return {"deleted": _nc(request).clear(cu, dismissed_only), "unread": _nc(request).unread(cu)}


@router.get("/{nid}")
def get_one(request: Request, nid: int, cu: CurrentUser = Depends(require_session)):
    return _run(_nc(request).get, cu, nid)


async def authed_socket(ws: WebSocket, token: str, session: str):
    """Shared by the Part 17 / 18 streams: check token + session, accept, return (user, recheck) or None."""
    app = ws.app
    from ..services.accounts import AuthError

    def check():
        try:
            _s, u = app.state.accounts.authenticate(session, allow_locked=False, touch=False)
            return None, u
        except AuthError as e:
            return (4423 if e.status == 423 else 4401), None

    if not hmac.compare_digest(token, app.state.api_token):
        await ws.close(code=4401)
        return None
    code, user = check()
    if code:
        await ws.close(code=code)
        return None
    await ws.accept()
    return user, check


class StreamUser:
    def __init__(self, u: dict[str, Any]):
        self.user = u
        self.session = {"id": None}


@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"notifications", items:[new, oldest first], unread, worst_unread} whenever something changes."""
    got = await authed_socket(ws, token, session)
    if not got:
        return
    user, check = got
    nc: NotificationCenter = ws.app.state.notifications
    cu = StreamUser(user)
    last_id = nc.list(cu, "all", limit=1)["last_id"]
    last_unread = -1
    ticks = 0
    try:
        while True:
            res = await asyncio.to_thread(nc.list, cu, "all", None, None, None, last_id, None, 50, 0)
            if res["items"] or res["unread"] != last_unread:
                if res["items"]:
                    last_id = max(i["id"] for i in res["items"])
                last_unread = res["unread"]
                sm = nc.summary(cu, 1)
                await ws.send_json({"type": "notifications", "items": list(reversed(res["items"])),
                                    "unread": res["unread"], "worst_unread": sm["worst_unread"]})
            await asyncio.sleep(1.0)
            ticks += 1
            if ticks % 10 == 0:
                code, _ = check()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
