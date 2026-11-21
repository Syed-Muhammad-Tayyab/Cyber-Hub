"""
Cyber Hub Backend - Network Monitor & Wi-Fi routes (Part 10)
Developed by Syed Muhammad Tayyab

Permission model (same rule as Parts 7 and 9 - raising protection is open to
anyone signed in, lowering it needs a Cyber Hub administrator):

  anyone signed in : view everything, run the watch, scan the LAN, apply
                     blocking fixes (they go through Part 9's guards), label a
                     device, mark a network as Home, acknowledge alerts
  administrator    : trust a device / un-mark Home (fewer alerts), accept a
                     changed router address, forget devices, clear events,
                     import / download the MAC vendor list, findings whose fix
                     is marked fix_requires_admin

Blocking a connection / port / program from the UI can also call the existing
/api/firewall/block/* routes directly - same guards, same permissions.
"""
from __future__ import annotations

import asyncio
import hmac
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.network import OUI_URL, NetworkError, NetworkService

router = APIRouter(prefix="/api/network", tags=["network"],
                   dependencies=[Depends(require_token), Depends(require_session)])
stream_router = APIRouter(prefix="/api/network", tags=["network"])

MAX_OUI_TEXT = 16 * 1024 * 1024


def _net(request: Request) -> NetworkService:
    return request.app.state.network


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except NetworkError as e:
        raise HTTPException(e.status, e.message)


def _is_admin(cu: CurrentUser) -> bool:
    return cu.user["role"] == "admin"


# ================================================================== overview
@router.get("/status")
def status(request: Request):
    """Network card: connection counts, Wi-Fi (SSID, security rating, signal), LAN (devices, new today,
    router alert), 0-100 network score + finding counts, unread alerts, last watch, LAN scan state."""
    return _run(_net(request).status)


@router.get("/findings")
def findings(request: Request, refresh: bool = False):
    """Everything worth fixing across connections, listening ports, Wi-Fi and the LAN, with one-click fixes."""
    return _run(_net(request).analyze, refresh)


@router.post("/findings/{finding_id}/fix")
def fix(request: Request, finding_id: str, cu: CurrentUser = Depends(require_session)):
    """Block remote address / incoming port / program (via the Part 9 firewall), or accept a new router (admin)."""
    return _run(_net(request).fix, finding_id, cu.user["username"], _is_admin(cu))


@router.get("/summary")
def summary(request: Request, hours: int = Query(24, ge=1, le=24 * 30), days: int = Query(14, ge=1, le=90)):
    """Graphs: connection counts over time, alerts per day / kind, top programs, top remote ports, scope + TCP
    state donuts."""
    return _run(_net(request).summary, hours, days)


# ================================================================== connections & ports
@router.get("/connections")
def connections(request: Request, search: str | None = Query(None, max_length=200),
                state: str | None = Query(None, max_length=20), proto: str | None = Query(None, pattern="^(tcp|udp)$"),
                scope: str | None = Query(None, pattern="^(internet|lan|local)$"),
                direction: str | None = Query(None, pattern="^(incoming|outgoing)$"), pid: int | None = None,
                flagged: bool = False, include_listening: bool = False, resolve: bool | None = None,
                sort: str = Query("risk", pattern="^(risk|process|remote|port)$"),
                limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)):
    """Active connections with the owning program (pid + create_time for the Part 4 / Part 9 buttons),
    scope, direction, service, risk flags. resolve=true adds reverse-DNS names (max 40 per call)."""
    return _run(_net(request).connections, search, state, proto, scope, direction, pid, flagged,
                include_listening, resolve, sort, limit, offset)


@router.get("/connections/by-process")
def by_process(request: Request):
    """One row per program: connections, internet hosts, listening ports, behaviour warnings."""
    return _run(_net(request).by_process)


@router.get("/listening")
def listening(request: Request, exposed_only: bool = False, include_ephemeral: bool = False):
    """Open ports: who listens, who can reach it (this PC / network) and the firewall's verdict for it."""
    return _run(_net(request).listening, exposed_only, include_ephemeral)


# ================================================================== Wi-Fi
@router.get("/wifi")
def wifi(request: Request, refresh: bool = False):
    """Current Wi-Fi + security rating, nearby networks, saved networks, Wi-Fi findings (evil twin,
    auto-join open networks). Saved passwords are never read."""
    return _run(_net(request).wifi, refresh)


@router.get("/wifi/history")
def wifi_history(request: Request, limit: int = Query(100, ge=1, le=1000)):
    return _run(_net(request).wifi_history, limit)


# ================================================================== LAN
@router.get("/lan")
def lan(request: Request, network_id: int | None = None):
    """Devices on the current network (or a past one): IP, MAC, vendor, name, type guess, open ports,
    online now, flags. Includes this PC. Reading the ARP table sends nothing on the network."""
    return _run(_net(request).lan, network_id)


@router.get("/lan/networks")
def lan_networks(request: Request):
    return _run(_net(request).networks)


class ScanIn(BaseModel):
    ports: bool = True          # also check a fixed list of common ports on each device


@router.post("/lan/scan", status_code=202)
def lan_scan(request: Request, body: ScanIn | None = None, cu: CurrentUser = Depends(require_session)):
    """Find every device on the current private network (ARP + fixed common ports + NetBIOS names).
    Refused for non-private networks. Poll GET /lan/scan for progress."""
    return _run(_net(request).start_scan, cu.user["username"], (body or ScanIn()).ports)


@router.get("/lan/scan")
def lan_scan_status(request: Request):
    return _net(request).scan_status()


@router.post("/lan/scan/cancel")
def lan_scan_cancel(request: Request):
    return _run(_net(request).cancel_scan)


@router.get("/lan/devices/{device_id}")
def device(request: Request, device_id: int):
    return _run(_net(request).get_device, device_id)


class DeviceIn(BaseModel):
    label: str | None = Field(None, max_length=80)
    trusted: bool | None = None
    notes: str | None = Field(None, max_length=500)


@router.patch("/lan/devices/{device_id}")
def update_device(request: Request, device_id: int, body: DeviceIn, cu: CurrentUser = Depends(require_session)):
    """Rename / add notes = anyone. Trust a device (no more warnings for it) = administrator."""
    if body.trusted is not None and not _is_admin(cu):
        raise HTTPException(403, "Administrator rights required to change whether a device is trusted")
    return _run(_net(request).update_device, device_id, body.label, body.trusted, body.notes)


@router.delete("/lan/devices/{device_id}")
def forget_device(request: Request, device_id: int, cu: CurrentUser = Depends(require_admin)):
    return {"deleted": _run(_net(request).forget_device, device_id)}


class HomeIn(BaseModel):
    home: bool
    name: str | None = Field(None, max_length=80)


@router.post("/lan/networks/{network_id}/home")
def set_home(request: Request, network_id: int, body: HomeIn, cu: CurrentUser = Depends(require_session)):
    """Mark as Home (new devices raise medium alerts, automatic scans allowed). Un-marking = administrator."""
    if not body.home and not _is_admin(cu):
        raise HTTPException(403, "Administrator rights required to un-mark a Home network")
    return _run(_net(request).set_home, network_id, body.home, body.name)


@router.post("/lan/networks/{network_id}/accept-gateway")
def accept_gateway(request: Request, network_id: int, cu: CurrentUser = Depends(require_admin)):
    """'It's my new router' - accept a changed router hardware address."""
    return _run(_net(request).accept_gateway, network_id, cu.user["username"])


# ================================================================== MAC vendors
@router.get("/oui")
def oui_status(request: Request):
    return _net(request).oui_status()


class OuiImportIn(BaseModel):
    text: str | None = None
    path: str | None = Field(None, max_length=1024)


@router.post("/oui/import")
def oui_import(request: Request, body: OuiImportIn, cu: CurrentUser = Depends(require_admin)):
    """Load the IEEE oui.csv / oui.txt or Wireshark manuf file (text or a local path)."""
    if bool(body.text) == bool(body.path):
        raise HTTPException(422, "Send either 'text' or 'path'")
    if body.text is not None:
        if len(body.text) > MAX_OUI_TEXT:
            raise HTTPException(413, "Vendor list too large (max 16 MB)")
        return _run(_net(request).import_oui, body.text, "pasted text", cu.user["username"])
    p = os.path.abspath(os.path.expandvars(os.path.expanduser(body.path)))
    if not os.path.isfile(p):
        raise HTTPException(404, "File not found")
    if os.path.getsize(p) > MAX_OUI_TEXT:
        raise HTTPException(413, "Vendor list too large (max 16 MB)")
    with open(p, "rb") as f:
        text = f.read().decode("utf-8", errors="replace")
    return _run(_net(request).import_oui, text, os.path.basename(p), cu.user["username"])


class OuiUpdateIn(BaseModel):
    url: str = Field(OUI_URL, max_length=500)


@router.post("/oui/update")
def oui_update(request: Request, body: OuiUpdateIn | None = None, cu: CurrentUser = Depends(require_admin)):
    """Download the official IEEE list (about 3-4 MB, https only)."""
    return _run(_net(request).update_oui, cu.user["username"], (body or OuiUpdateIn()).url)


# ================================================================== watch & events
@router.post("/watch")
def watch_now(request: Request):
    return _run(_net(request).watch_once)


@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0),
           severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000)):
    return _net(request).events(after_id, severity, kind, unacknowledged, limit)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn | None = None):
    return {"acknowledged": _net(request).acknowledge((body or AckIn()).ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_admin)):
    n = _net(request).clear_events()
    request.app.state.activity.record("network", "Network alert list cleared", f"{n} events (by {cu.user['username']})",
                                      source="network")
    return {"deleted": n}


# ================================================================== WebSocket
@stream_router.websocket("/stream")
async def stream(ws: WebSocket, token: str = Query(""), session: str = Query("")):
    """Pushes {type:"network", live:{total, established, listening, incoming, outgoing, internet, lan, syn_sent,
    processes, remote_hosts, flagged}, events:[new network_events], scan:{state, percent...}} every 3 s."""
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
    net: NetworkService = app.state.network
    last_id = net.events(limit=1)["last_id"]
    ticks = 0
    try:
        while True:
            if ticks % 6 == 0:
                live = await asyncio.to_thread(net.live_brief)
                ev = net.events(after_id=last_id, limit=50)
                if ev["items"]:
                    last_id = ev["last_id"]
                await ws.send_json({"type": "network", "live": live, "events": list(reversed(ev["items"])),
                                    "scan": net.scan_status(), "unacknowledged": ev["unacknowledged"]})
            await asyncio.sleep(0.5)
            ticks += 1
            if ticks % 20 == 0:
                code = check_session()
                if code:
                    await ws.send_json({"type": "closed", "reason": "locked" if code == 4423 else "signed_out"})
                    await ws.close(code=code)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
