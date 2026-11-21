"""
Cyber Hub Backend - Live System Monitor routes (Part 3)
Developed by Syed Muhammad Tayyab

Every route needs the API token AND a signed-in, unlocked session.
The WebSocket takes both as query parameters (browsers cannot set
headers on WebSockets):
    ws://127.0.0.1:8765/api/monitor/stream?token=...&session=...&top=5
"""
from __future__ import annotations

import asyncio
import hmac
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import require_session, require_token
from ..services import alerts as alert_svc
from ..services import hardware, metrics_recorder, monitor

router = APIRouter(prefix="/api/monitor", tags=["monitor"],
                   dependencies=[Depends(require_token), Depends(require_session)])


def _engine(request: Request) -> alert_svc.AlertEngine:
    return request.app.state.alerts


# ------------------------------------------------------------------ live data
@router.get("/overview")
def get_overview(request: Request, top: int = Query(5, ge=0, le=25)):
    """Everything for the Live Monitor page: CPU, RAM, disk I/O, network, GPU, temps,
    health lights and the top CPU / memory users."""
    data = monitor.overview(_engine(request).thresholds(), top=top)
    data["alerts"] = _engine(request).summary(days=1)
    return data


@router.get("/cpu")
def get_cpu():
    """Total + per-core usage, frequency, user/system/idle split, interrupts, context switches."""
    return monitor.SAMPLER.sample()["cpu"]


@router.get("/memory")
def get_memory():
    """RAM (used/available/cached) and swap / page file."""
    return monitor.SAMPLER.sample()["memory"]


@router.get("/disks")
def get_disks():
    """Read/write MB/s, IOPS and active % per physical disk, plus space per drive."""
    return monitor.SAMPLER.sample()["disk_io"]


@router.get("/network")
def get_network():
    """Upload / download KB/s per network adapter."""
    return monitor.SAMPLER.sample()["network"]


@router.get("/gpu")
def get_gpu():
    return hardware.gpu_info()


@router.get("/temperatures")
def get_temperatures():
    """CPU / GPU / drive temperatures and fan speeds where the hardware exposes them."""
    return hardware.temperatures()


@router.get("/top")
def get_top(by: Literal["cpu", "memory", "disk"] = "cpu", limit: int = Query(10, ge=1, le=50)):
    """Top resource users (read-only; kill/suspend arrives with Part 4)."""
    return monitor.SAMPLER.top_processes(by, limit)


@router.get("/history")
def get_history(request: Request, hours: int = Query(24, ge=1, le=24 * 365),
                bucket_minutes: int | None = Query(None, ge=1, le=24 * 60)):
    """Averaged history for line charts (CPU, RAM, swap, disk I/O, GPU, temperature, network)."""
    return metrics_recorder.history_buckets(request.app.state.db, hours, bucket_minutes)


# ------------------------------------------------------------------ thresholds
class ThresholdsIn(BaseModel):
    monitor_alerts_enabled: bool | None = None
    alert_cpu_percent: int | None = Field(None, ge=50, le=100)
    alert_memory_percent: int | None = Field(None, ge=50, le=100)
    alert_disk_percent: int | None = Field(None, ge=50, le=99)
    alert_gpu_percent: int | None = Field(None, ge=50, le=100)
    alert_temperature_c: int | None = Field(None, ge=50, le=110)
    alert_sustain_seconds: int | None = Field(None, ge=0, le=3600)


@router.get("/thresholds")
def get_thresholds(request: Request):
    return _engine(request).thresholds()


@router.put("/thresholds")
def put_thresholds(request: Request, body: ThresholdsIn):
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(422, "Nothing to change")
    request.app.state.settings_store.update(changes)
    request.app.state.activity.record("settings", "Monitor alert thresholds updated", ", ".join(sorted(changes)))
    return _engine(request).thresholds()


# ------------------------------------------------------------------ alerts
@router.get("/alerts")
def list_alerts(request: Request,
                status: Literal["all", "active", "resolved", "unacknowledged"] = "all",
                limit: int = Query(50, ge=1, le=500)):
    return {"items": _engine(request).list(status, limit)}


@router.get("/alerts/summary")
def alerts_summary(request: Request, days: int = Query(7, ge=1, le=365)):
    """Badge count + charts for the alerts card."""
    return _engine(request).summary(days)


@router.post("/alerts/check")
def check_alerts(request: Request):
    """Run the threshold check right now (the engine also runs it in the background)."""
    return {"events": alert_svc.check_now(_engine(request))}


@router.post("/alerts/{alert_id}/ack")
def ack_alert(request: Request, alert_id: int):
    if not _engine(request).get(alert_id):
        raise HTTPException(404, "Alert not found")
    _engine(request).acknowledge(alert_id)
    return _engine(request).get(alert_id)


@router.post("/alerts/ack-all")
def ack_all(request: Request):
    return {"acknowledged": _engine(request).acknowledge()}


@router.delete("/alerts")
def clear_resolved(request: Request):
    n = _engine(request).clear_resolved()
    request.app.state.activity.record("system", "Resolved monitor alerts cleared", f"{n} removed",
                                      source="monitor")
    return {"deleted": n}


# ------------------------------------------------------------------ WebSocket
stream_router = APIRouter(prefix="/api/monitor", tags=["monitor"])


@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query(""),
                 top: int = Query(0, ge=0, le=15)):
    """Live push: per-core CPU, memory, disk I/O, network, GPU, temps, health and
    active alert count every `metrics_interval_seconds`. top=N adds the top-N CPU users."""
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
    store, engine = app.state.settings_store, app.state.alerts
    ticks = 0
    try:
        while True:
            if ticks and ticks % 10 == 0:            # re-check: honours lock / sign-out / expiry
                code = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
            data = await asyncio.to_thread(_stream_payload, engine, top)
            await ws.send_json(data)
            ticks += 1
            await asyncio.sleep(store.get("metrics_interval_seconds"))
    except (WebSocketDisconnect, RuntimeError):
        pass


def _stream_payload(engine: alert_svc.AlertEngine, top: int) -> dict:
    s = monitor.SAMPLER.sample()
    gpu, temps = hardware.gpu_info(), hardware.temperatures()
    return {
        "type": "monitor",
        "timestamp": s["timestamp"],
        "cpu": {k: s["cpu"][k] for k in ("percent", "per_core", "frequency_mhz", "busiest_core")},
        "memory": {k: s["memory"][k] for k in ("percent", "used_gb", "available_gb", "total_gb")}
        | {"swap_percent": s["memory"]["swap"]["percent"]},
        "disk_io": {k: s["disk_io"][k] for k in ("read_mb_s", "write_mb_s", "read_iops", "write_iops")},
        "network": {k: s["network"][k] for k in ("upload_kbps", "download_kbps")},
        "gpu_percent": gpu.get("max_usage_percent"),
        "cpu_temp_c": temps.get("cpu_celsius"),
        "health": monitor.health(s, gpu, temps, engine.thresholds()),
        "active_alerts": engine.summary(days=1)["active"],
        "top_cpu": monitor.SAMPLER.top_processes("cpu", top)["items"] if top else [],
    }
