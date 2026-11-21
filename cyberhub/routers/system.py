"""
Cyber Hub Backend - System routes: device info, live stats, history, WebSocket stream
Developed by Syed Muhammad Tayyab
"""
from __future__ import annotations

import asyncio
import hmac

from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect

from ..security import require_token
from ..services import metrics_recorder, system_info

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/info", dependencies=[Depends(require_token)])
def get_device_info():
    """Device card: hostname, OS, CPU, RAM, disks, adapters."""
    return system_info.device_info()


@router.get("/stats", dependencies=[Depends(require_token)])
def get_live_stats():
    """One live snapshot for rings/gauges."""
    return system_info.live_stats()


@router.get("/history", dependencies=[Depends(require_token)])
def get_history(request: Request, hours: int = Query(24, ge=1, le=24 * 30)):
    """Stored snapshots for line charts."""
    return {"hours": hours, "points": metrics_recorder.history(request.app.state.db, hours)}


@router.post("/snapshot", dependencies=[Depends(require_token)])
def snapshot_now(request: Request):
    """Force a history point immediately (useful on first launch)."""
    return metrics_recorder.take_snapshot(request.app.state.db)


@router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(...)):
    """Live push of stats: ws://127.0.0.1:8765/api/system/stream?token=..."""
    if not hmac.compare_digest(token, ws.app.state.api_token):
        await ws.close(code=4401)
        return
    await ws.accept()
    store = ws.app.state.settings_store
    try:
        while True:
            await ws.send_json(await asyncio.to_thread(system_info.live_stats))
            await asyncio.sleep(store.get("metrics_interval_seconds"))
    except (WebSocketDisconnect, RuntimeError):
        pass
