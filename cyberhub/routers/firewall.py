"""
Cyber Hub Backend - Firewall & Network Protection routes (Part 9)
Developed by Syed Muhammad Tayyab

Permission model (same rule as Real-time protection - raising protection is
open to anyone signed in, lowering it needs a Cyber Hub administrator):

  anyone signed in : view everything, turn the firewall ON, block all incoming ON,
                     block a program / process / IP / port, switch an ALLOW rule off,
                     repair a block, run the watch, apply protective fixes,
                     save a policy snapshot, acknowledge alerts
  administrator    : turn the firewall OFF / allow inbound by default, block all
                     incoming OFF, switch a BLOCK rule off or an ALLOW rule on,
                     delete rules, remove a block, allow an app through,
                     force=true on any guard, restore / delete snapshots, reset
                     to defaults, clear the event list

On top of that Windows itself only lets an elevated engine change the firewall
(start_cyberhub_admin.bat) - otherwise those calls answer 403 with that hint.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.firewall import FirewallError, FirewallService

router = APIRouter(prefix="/api/firewall", tags=["firewall"],
                   dependencies=[Depends(require_token), Depends(require_session)])


def _fw(request: Request) -> FirewallService:
    return request.app.state.firewall


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except FirewallError as e:
        raise HTTPException(e.status, e.message)


def _admin_if(cu: CurrentUser, needed: bool, what: str) -> None:
    if needed and cu.user["role"] != "admin":
        raise HTTPException(403, f"Administrator rights required to {what}")


# ================================================================== status & profiles
@router.get("/status")
def status(request: Request):
    """The Firewall & network protection card: backend (Windows Firewall / ufw / simulated), can_modify,
    on / partial / off, block-all-incoming, each profile with the network connected to it, rule counts
    (inbound / outbound x allow / block), Cyber Hub blocks, health score + finding counts, unread alerts."""
    return _fw(request).status()


@router.get("/profiles")
def profiles(request: Request, refresh: bool = False):
    return _run(_fw(request).profiles, refresh)


class ProfileIn(BaseModel):
    enabled: bool | None = None
    default_inbound: str | None = Field(None, pattern="^(allow|block)$")
    default_outbound: str | None = Field(None, pattern="^(allow|block)$")
    block_all_inbound: bool | None = None      # "Block all incoming connections, including allowed apps"
    notify_on_listen: bool | None = None
    log_blocked: bool | None = None
    log_allowed: bool | None = None


@router.patch("/profiles/{name}")
def set_profile(request: Request, name: str, body: ProfileIn, cu: CurrentUser = Depends(require_session)):
    """name = domain | private | public | all (ufw: all). Turning protection down needs an administrator."""
    changes = body.model_dump(exclude_none=True)
    if "block_all_inbound" in changes:
        changes["allow_inbound_rules"] = not changes.pop("block_all_inbound")
    _admin_if(cu, FirewallService.lowers_protection(changes), "lower firewall protection")
    return _run(_fw(request).set_profile, name.lower(), changes, cu.user["username"])


class ShieldsIn(BaseModel):
    on: bool
    profile: str = Field("all", max_length=20)


@router.post("/shields-up")
def shields_up(request: Request, body: ShieldsIn, cu: CurrentUser = Depends(require_session)):
    """Block ALL incoming connections, even for allowed apps (e.g. on airport Wi-Fi). Off = admin."""
    _admin_if(cu, not body.on, "switch off 'block all incoming connections'")
    return _run(_fw(request).set_profile, body.profile.lower(), {"allow_inbound_rules": not body.on},
                cu.user["username"])


# ================================================================== rules
@router.get("/rules")
def rules(request: Request, search: str | None = Query(None, max_length=200),
          direction: str | None = Query(None, pattern="^(in|out)$"),
          action: str | None = Query(None, pattern="^(allow|block)$"), enabled: bool | None = None,
          profile: str | None = Query(None, pattern="^(domain|private|public|all)$"),
          origin: str = Query("all", pattern="^(all|cyberhub|system|policy)$"), flagged: bool = False,
          sort: str = Query("name", pattern="^(name|risk|program)$"),
          limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0), refresh: bool = False):
    """Every firewall rule with risk flags (allow_all, exposed_service, suspicious_location, orphaned)."""
    return _run(_fw(request).list_rules, search, direction, action, enabled, profile, origin, flagged, sort,
                limit, offset, refresh)


@router.get("/rules/{rule_id:path}")
def rule(request: Request, rule_id: str):
    return _run(_fw(request).get_rule, rule_id)


class RuleToggleIn(BaseModel):
    enabled: bool


@router.patch("/rules/{rule_id:path}")
def toggle_rule(request: Request, rule_id: str, body: RuleToggleIn, cu: CurrentUser = Depends(require_session)):
    """Switching an ALLOW rule off (safer) is open to everyone; a BLOCK rule off / ALLOW rule on needs admin."""
    svc = _fw(request)
    r = _run(svc.get_rule, rule_id)
    _admin_if(cu, svc.toggle_lowers(r, body.enabled), "switch this rule " + ("on" if body.enabled else "off"))
    return _run(svc.set_rule_enabled, rule_id, body.enabled, cu.user["username"])


@router.delete("/rules/{rule_id:path}")
def delete_rule(request: Request, rule_id: str, force: bool = False, cu: CurrentUser = Depends(require_admin)):
    """Cyber Hub rules only, unless force=true (Windows / app rules - prefer switching them off)."""
    return _run(_fw(request).delete_rule, rule_id, cu.user["username"], force)


# ================================================================== blocks
class BlockAppIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)
    direction: str = Field("both", pattern="^(in|out|both)$")
    minutes: int | None = Field(None, ge=1, le=525600)     # None = until removed
    reason: str | None = Field(None, max_length=300)
    force: bool = False


@router.post("/block/app", status_code=201)
def block_app(request: Request, body: BlockAppIn, cu: CurrentUser = Depends(require_session)):
    """Cut a program off the network (in, out or both), permanently or for N minutes."""
    _admin_if(cu, body.force, "use force")
    return _run(_fw(request).block_app, body.path, cu.user["username"], body.direction, body.minutes, body.reason,
                body.force)


class BlockProcessIn(BaseModel):
    pid: int = Field(..., ge=0)
    create_time: float | None = None                       # from the process list - guards against PID reuse
    direction: str = Field("both", pattern="^(in|out|both)$")
    minutes: int | None = Field(None, ge=1, le=525600)
    reason: str | None = Field(None, max_length=300)
    force: bool = False


@router.post("/block/process", status_code=201)
def block_process(request: Request, body: BlockProcessIn, cu: CurrentUser = Depends(require_session)):
    """'Block network' button in the Processes list - blocks the program file the process runs from."""
    _admin_if(cu, body.force, "use force")
    return _run(_fw(request).block_process, body.pid, cu.user["username"], body.create_time, body.direction,
                body.minutes, body.reason, body.force)


class BlockIpIn(BaseModel):
    addresses: list[str] = Field(..., min_length=1, max_length=64)   # 1.2.3.4 | 10.0.0.0/24 | 10.0.0.5-10.0.0.20
    direction: str = Field("both", pattern="^(in|out|both)$")
    minutes: int | None = Field(None, ge=1, le=525600)
    reason: str | None = Field(None, max_length=300)
    force: bool = False


@router.post("/block/ip", status_code=201)
def block_ip(request: Request, body: BlockIpIn, cu: CurrentUser = Depends(require_session)):
    """Block addresses. Loopback / this PC's own address are refused; LAN addresses come back with a warning."""
    _admin_if(cu, body.force, "use force")
    return _run(_fw(request).block_ip, body.addresses, cu.user["username"], body.direction, body.minutes,
                body.reason, body.force)


class BlockPortIn(BaseModel):
    ports: str = Field(..., min_length=1, max_length=200)            # 445 | 6000-6010 | 80,443
    protocol: str = Field("tcp", pattern="^(tcp|udp|both)$")
    direction: str = Field("in", pattern="^(in|out|both)$")
    minutes: int | None = Field(None, ge=1, le=525600)
    reason: str | None = Field(None, max_length=300)
    force: bool = False


@router.post("/block/port", status_code=201)
def block_port(request: Request, body: BlockPortIn, cu: CurrentUser = Depends(require_session)):
    """Close ports. Outgoing DNS / DHCP / HTTP / HTTPS need force (they would take the PC offline)."""
    _admin_if(cu, body.force, "use force")
    return _run(_fw(request).block_port, body.ports, cu.user["username"], body.protocol, body.direction,
                body.minutes, body.reason, body.force)


class AllowAppIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)
    profiles: list[str] = Field(default_factory=lambda: ["private"], max_length=3)
    reason: str | None = Field(None, max_length=300)
    force: bool = False


@router.post("/allow/app", status_code=201)
def allow_app(request: Request, body: AllowAppIn, cu: CurrentUser = Depends(require_admin)):
    """'Allow an app through firewall' - incoming connections for one program (Private networks by default)."""
    return _run(_fw(request).allow_app, body.path, cu.user["username"], [p.lower() for p in body.profiles],
                body.reason, body.force)


@router.get("/blocks")
def blocks(request: Request, status: str | None = Query(None, pattern="^(current|active|missing|expired|removed)$"),
           kind: str | None = Query(None, pattern="^(app|ip|port|allow_app)$"),
           limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Cyber Hub blocks / allows. status=current = active + missing. remaining_seconds for temporary ones."""
    return _fw(request).blocks(status, kind, limit, offset)


@router.get("/blocks/{block_id}")
def block(request: Request, block_id: int):
    return _run(_fw(request).get_block, block_id)


@router.delete("/blocks/{block_id}")
def unblock(request: Request, block_id: int, cu: CurrentUser = Depends(require_admin)):
    return _run(_fw(request).unblock, block_id, cu.user["username"])


@router.post("/blocks/{block_id}/repair")
def repair(request: Request, block_id: int, cu: CurrentUser = Depends(require_session)):
    """Re-create the firewall rules of a block that something removed behind Cyber Hub's back."""
    return _run(_fw(request).repair_block, block_id, cu.user["username"])


@router.post("/blocks/verify")
def verify(request: Request):
    return _run(_fw(request).verify_blocks)


# ================================================================== analysis
@router.get("/analysis")
def analysis(request: Request, refresh: bool = False):
    """0-100 firewall health score (Protected / Good / Needs attention / At risk) with findings + fixes."""
    return _run(_fw(request).analyze, refresh)


@router.post("/findings/{finding_id:path}/fix")
def fix(request: Request, finding_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_fw(request).fix, finding_id, cu.user["username"], cu.user["role"] == "admin")


# ================================================================== watch & events
@router.post("/watch")
def watch(request: Request):
    """Check now for rules / profile changes made outside Cyber Hub (also runs in the background)."""
    return _run(_fw(request).watch_once)


@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0),
           severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Firewall timeline, newest first. Poll with after_id=<last_id> for new alerts."""
    return _fw(request).events(after_id, severity, kind, unacknowledged, limit, offset)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)    # None = all


@router.post("/events/ack")
def ack(request: Request, body: AckIn):
    return {"acknowledged": _fw(request).acknowledge(body.ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_admin)):
    n = request.app.state.db.execute("DELETE FROM firewall_events").rowcount
    request.app.state.activity.record("firewall", "Firewall event list cleared", f"{n} rows by "
                                      f"{cu.user['username']}", severity="low", source="firewall")
    return {"deleted": n}


@router.get("/summary")
def summary(request: Request, days: int = Query(14, ge=1, le=365)):
    """Graphs: events per day by severity + blocks created, events by kind, rule mix, blocks by kind, score."""
    return _fw(request).summary(days)


@router.get("/log")
def packet_log(request: Request, hours: int = Query(24, ge=1, le=720), recent: int = Query(50, ge=0, le=500)):
    """Dropped / allowed packets per hour, top blocked sources and ports, port-scan suspects, latest drops."""
    return _run(_fw(request).log_summary, hours, recent)


# ================================================================== snapshots & reset
@router.get("/snapshots")
def snapshots(request: Request):
    return {"snapshots": _fw(request).snapshots()}


class SnapshotIn(BaseModel):
    note: str | None = Field(None, max_length=200)


@router.post("/snapshots", status_code=201)
def create_snapshot(request: Request, body: SnapshotIn, cu: CurrentUser = Depends(require_session)):
    """Export the whole firewall policy (netsh advfirewall export) so it can be put back later."""
    return _run(_fw(request).create_snapshot, cu.user["username"], body.note)


@router.post("/snapshots/{snap_id}/restore")
def restore_snapshot(request: Request, snap_id: int, cu: CurrentUser = Depends(require_admin)):
    """Takes an automatic safety snapshot first; refuses files changed since they were saved."""
    return _run(_fw(request).restore_snapshot, snap_id, cu.user["username"])


@router.delete("/snapshots/{snap_id}")
def delete_snapshot(request: Request, snap_id: int, cu: CurrentUser = Depends(require_admin)):
    _run(_fw(request).delete_snapshot, snap_id)
    return {"deleted": snap_id}


class ResetIn(BaseModel):
    confirm: bool


@router.post("/reset")
def reset(request: Request, body: ResetIn, cu: CurrentUser = Depends(require_admin)):
    """Restore Windows Firewall defaults (removes every custom rule, Cyber Hub blocks included).
    A safety snapshot is saved first."""
    if not body.confirm:
        raise HTTPException(400, "Send {\"confirm\": true} to reset the firewall")
    return _run(_fw(request).reset_defaults, cu.user["username"])
