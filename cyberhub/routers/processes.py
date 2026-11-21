"""
Cyber Hub Backend - Processes & Startup routes (Part 4)
Developed by Syed Muhammad Tayyab

Reading needs the API token + a signed-in, unlocked session.
Changing anything (end / suspend / priority / enable-disable startup)
needs an administrator account in Cyber Hub - and, for system-wide items,
the engine itself running with Windows administrator rights.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.processes import PRIORITIES, ProcessError, is_elevated
from ..services.startup import SOURCES, StartupError

router = APIRouter(prefix="/api/processes", tags=["processes"],
                   dependencies=[Depends(require_token), Depends(require_session)])
startup_router = APIRouter(prefix="/api/startup", tags=["startup"],
                           dependencies=[Depends(require_token), Depends(require_session)])


def _procs(request: Request):
    return request.app.state.processes


def _startup(request: Request):
    return request.app.state.startup


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except (ProcessError, StartupError) as e:
        raise HTTPException(e.status, e.message)


def _sig_enabled(request: Request) -> bool:
    return bool(request.app.state.settings_store.get("process_signature_check"))


# ================================================================== processes
@router.get("")
def list_processes(request: Request,
                   search: str | None = Query(None, max_length=120),
                   sort: Literal["cpu", "memory", "disk", "name", "pid", "threads", "risk", "started"] = "cpu",
                   order: Literal["asc", "desc"] = "desc",
                   limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
                   user: str | None = Query(None, max_length=120),
                   flagged_only: bool = False, signatures: bool = False):
    """Task-Manager list with risk flags. signatures=true verifies publishers (Windows, cached)."""
    return _procs(request).list(search, sort, order, limit, offset, user, flagged_only,
                                signatures and _sig_enabled(request))


@router.get("/tree")
def process_tree(request: Request):
    """Parent -> child tree with subtree CPU / memory totals."""
    return _procs(request).tree()


@router.get("/summary")
def process_summary(request: Request):
    """Counts for the Processes card: total, threads, flagged, by risk / status."""
    j = _procs(request).list(limit=10, sort="risk")
    return j["summary"] | {"top_risk": [r for r in j["items"] if r["flags"]][:5],
                           "engine_elevated": is_elevated()}


@router.get("/actions")
def action_history(request: Request, limit: int = Query(50, ge=1, le=500)):
    """Who ended / suspended / re-prioritised what, and when."""
    return {"items": _procs(request).history(limit)}


@router.get("/{pid}")
def process_details(request: Request, pid: int, hash: bool = False):
    """Full details: command line, parent/children, handles, files, connections, signature, risk.
    hash=true also returns the SHA-256 of the program file."""
    return _run(_procs(request).details, pid, hash)


class EndIn(BaseModel):
    create_time: float | None = Field(None, description="create_time from the list - guards against PID reuse")
    tree: bool = Field(False, description="also end every child process")
    force: bool = Field(False, description="kill immediately instead of asking the program to close")


class PidGuardIn(BaseModel):
    create_time: float | None = None


class PriorityIn(BaseModel):
    priority: Literal["idle", "below_normal", "normal", "above_normal", "high"]
    create_time: float | None = None


@router.post("/{pid}/end")
def end_process(request: Request, pid: int, body: EndIn | None = None,
                cu: CurrentUser = Depends(require_admin)):
    b = body or EndIn()
    return _run(_procs(request).end, pid, cu.user["username"], b.create_time, b.tree, b.force)


@router.post("/{pid}/suspend")
def suspend_process(request: Request, pid: int, body: PidGuardIn | None = None,
                    cu: CurrentUser = Depends(require_admin)):
    return _run(_procs(request).suspend, pid, cu.user["username"], (body or PidGuardIn()).create_time)


@router.post("/{pid}/resume")
def resume_process(request: Request, pid: int, body: PidGuardIn | None = None,
                   cu: CurrentUser = Depends(require_admin)):
    return _run(_procs(request).resume, pid, cu.user["username"], (body or PidGuardIn()).create_time)


@router.put("/{pid}/priority")
def set_priority(request: Request, pid: int, body: PriorityIn, cu: CurrentUser = Depends(require_admin)):
    return _run(_procs(request).set_priority, pid, body.priority, cu.user["username"], body.create_time)


# ================================================================== startup
@startup_router.get("")
def list_startup(request: Request,
                 source: Literal[tuple(SOURCES)] | None = None,          # type: ignore[valid-type]
                 state: Literal["all", "enabled", "disabled", "new"] = "all",
                 flagged_only: bool = False, search: str | None = Query(None, max_length=120),
                 services: bool = True, microsoft_tasks: bool = False, manual_services: bool = False,
                 refresh: bool = False):
    """Everything that starts with the PC, riskiest first. Results are cached ~20 s; refresh=true rescans."""
    return _run(_startup(request).list, source, state, flagged_only, search, services, microsoft_tasks,
                manual_services, refresh)


@startup_router.get("/summary")
def startup_summary(request: Request):
    """Counts per source, enabled/disabled, new and flagged - for the Startup card and donut."""
    svc = _startup(request)
    return svc.summary(svc.scan()) | {"engine_elevated": is_elevated(),
                                      "watch_enabled": request.app.state.settings_store.get("startup_watch_enabled")}


@startup_router.get("/sources")
def startup_sources():
    return [{"id": k, "label": v} for k, v in SOURCES.items()]


@startup_router.get("/changes")
def startup_changes(request: Request, limit: int = Query(50, ge=1, le=500)):
    return {"items": _startup(request).changes(limit)}


@startup_router.post("/watch/check")
def startup_watch_now(request: Request):
    """Rescan now and alert on new entries (the engine also does this in the background)."""
    return _run(_startup(request).watch_once)


@startup_router.post("/accept-all")
def accept_all(request: Request, cu: CurrentUser = Depends(require_admin)):
    """Mark every NEW item as reviewed."""
    n = _startup(request).accept()
    request.app.state.activity.record("startup", "Startup list reviewed", f"{n} new item(s) accepted",
                                      source="startup")
    return {"accepted": n}


@startup_router.get("/{item_id}")
def startup_item(request: Request, item_id: str):
    return _startup(request).public(_run(_startup(request).get, item_id, False))


@startup_router.post("/{item_id}/accept")
def accept_item(request: Request, item_id: str, cu: CurrentUser = Depends(require_admin)):
    if not _startup(request).accept(item_id):
        raise HTTPException(404, "Startup item not found")
    return {"accepted": 1}


@startup_router.post("/{item_id}/disable")
def disable_item(request: Request, item_id: str, cu: CurrentUser = Depends(require_admin)):
    return _run(_startup(request).set_enabled, item_id, False, cu.user["username"])


@startup_router.post("/{item_id}/enable")
def enable_item(request: Request, item_id: str, cu: CurrentUser = Depends(require_admin)):
    return _run(_startup(request).set_enabled, item_id, True, cu.user["username"])


__all__ = ["router", "startup_router", "PRIORITIES"]
