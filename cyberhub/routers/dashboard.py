"""
Cyber Hub Backend - Security score & dashboard routes (Part 18)
Developed by Syed Muhammad Tayyab

GET /api/dashboard                 everything the front page shows, in one request: overall score + categories +
                                   recommendations, score history, threat / scan / real-time numbers, live system
                                   stats + history, firewall + network state, activity, notifications, next jobs
GET /api/score                     the overall score with every category and the reasons (refresh=true re-reads
                                   every module now instead of using their short caches)
GET /api/score/history             score points for the graph (days)
GET /api/score/recommendations     "what to fix first" (severity / category filters)
WS  /api/dashboard/stream          pushes {score, grade, status, unread, live stats} every few seconds
"""
from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect

from ..security import CurrentUser, require_session, require_token
from ..services.security_score import CATEGORIES, ScoreService
from .notifications import StreamUser, authed_socket

router = APIRouter(prefix="/api", tags=["dashboard"], dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api", tags=["dashboard"])

Sev = Literal["info", "low", "medium", "high", "critical"]


def _ss(request: Request) -> ScoreService:
    return request.app.state.score


@router.get("/dashboard")
def dashboard(request: Request, cu: CurrentUser = Depends(require_session), days: int = Query(14, ge=1, le=90),
              refresh: bool = False):
    return _ss(request).dashboard(cu, days, refresh)


@router.get("/score")
def score(request: Request, cu: CurrentUser = Depends(require_session), refresh: bool = False):
    return _ss(request).compute(cu.user["id"], refresh)


@router.get("/score/history")
def score_history(request: Request, cu: CurrentUser = Depends(require_session), days: int = Query(30, ge=1, le=365)):
    return _ss(request).history(cu.user["id"], days)


@router.get("/score/recommendations")
def recommendations(request: Request, cu: CurrentUser = Depends(require_session), severity: Sev | None = None,
                    category: str | None = None, limit: int = Query(60, ge=1, le=200)):
    s = _ss(request).compute(cu.user["id"])
    items = [r for r in s["recommendations"] if (not severity or r["severity"] == severity)
             and (not category or r["category"] == category)]
    return {"items": items[:limit], "total": len(items), "counts": s["counts"],
            "categories": [{"id": c[0], "name": c[1]} for c in CATEGORIES]}


@stream_router.websocket("/dashboard/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query(""),
                 interval: float = Query(3.0, ge=1.0, le=30.0)):
    got = await authed_socket(ws, token, session)
    if not got:
        return
    user, check = got
    app = ws.app
    cu = StreamUser(user)
    from ..services import system_info
    ticks = 0
    try:
        while True:
            s = await asyncio.to_thread(app.state.score.compute, user["id"])
            stats = await asyncio.to_thread(system_info.live_stats)
            await ws.send_json({"type": "dashboard", "score": s["score"], "grade": s["grade"], "status": s["status"],
                                "status_text": s["status_text"], "headline": s["headline"], "counts": s["counts"],
                                "tiles": [{"id": c["id"], "score": c["score"], "status": c["status"],
                                           "issues": c["issues"]} for c in s["categories"]],
                                "unread": app.state.notifications.unread(cu), "stats": stats})
            await asyncio.sleep(interval)
            ticks += 1
            if ticks % 5 == 0:
                code, _ = check()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
