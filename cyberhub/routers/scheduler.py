"""
Cyber Hub Backend - Scheduler routes (Part 17)
Developed by Syed Muhammad Tayyab

Reading needs a signed-in session; creating / changing / deleting schedules and running one by hand need a
Cyber Hub administrator (a schedule can start scans, clean-ups and backups without anyone at the PC).

GET    /api/scheduler/status              on/off, next job, last run, runs per day, battery state
GET    /api/scheduler/actions             what can be scheduled (+ whether it is available on this PC)
GET    /api/scheduler/schedules           all schedules with their next / last run
POST   /api/scheduler/schedules           create {name, action, kind, at_time | every_minutes | weekdays | month_day
                                          | run_at, params?, enabled?, catch_up?}
GET    /api/scheduler/schedules/{id}      one schedule + its last 10 runs
PATCH  /api/scheduler/schedules/{id}      change any field (e.g. {enabled:false})
DELETE /api/scheduler/schedules/{id}
POST   /api/scheduler/schedules/{id}/run  run it now (in the background)
GET    /api/scheduler/upcoming            planned runs in the next N hours (calendar view)
GET    /api/scheduler/runs                run history (schedule_id?, status?, limit, offset)
POST   /api/scheduler/tick                check for due jobs now (the worker does it every 15 s)
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.scheduler import SchedulerError, SchedulerService

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"],
                   dependencies=[Depends(require_token), Depends(require_session)])

_FIELDS = {"name", "action", "kind", "every_minutes", "at_time", "weekdays", "month_day", "run_at", "params",
           "enabled", "catch_up"}


def _sc(request: Request) -> SchedulerService:
    return request.app.state.scheduler


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except SchedulerError as e:
        raise HTTPException(e.status, e.message)


def _clean(body: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(body) - _FIELDS)
    if unknown:
        raise HTTPException(422, f"Unknown field(s): {', '.join(unknown)}")
    return body


@router.get("/status")
def status(request: Request):
    return _sc(request).status()


@router.get("/actions")
def actions(request: Request):
    return {"items": _sc(request).actions()}


@router.get("/schedules")
def list_schedules(request: Request):
    return _sc(request).list()


@router.post("/schedules", status_code=201)
def create_schedule(request: Request, body: dict[str, Any] = Body(...), cu: CurrentUser = Depends(require_admin)):
    return _run(_sc(request).create, cu, _clean(body))


@router.get("/schedules/{sid}")
def get_schedule(request: Request, sid: int):
    return _run(_sc(request).get, sid)


@router.patch("/schedules/{sid}")
def update_schedule(request: Request, sid: int, body: dict[str, Any] = Body(...),
                    cu: CurrentUser = Depends(require_admin)):
    return _run(_sc(request).update, cu, sid, _clean(body))


@router.delete("/schedules/{sid}")
def delete_schedule(request: Request, sid: int, cu: CurrentUser = Depends(require_admin)):
    return _run(_sc(request).delete, cu, sid)


@router.post("/schedules/{sid}/run", status_code=202)
def run_schedule(request: Request, sid: int, cu: CurrentUser = Depends(require_admin), wait: bool = False):
    return _run(_sc(request).run_now, cu, sid, wait)


@router.get("/upcoming")
def upcoming(request: Request, hours: int = Query(168, ge=1, le=24 * 60), limit: int = Query(60, ge=1, le=500)):
    return {"items": _sc(request).upcoming(hours, limit)}


@router.get("/runs")
def runs(request: Request, schedule_id: int | None = None,
         status: Literal["running", "ok", "failed", "skipped", "interrupted"] | None = None,
         limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    return _sc(request).runs(schedule_id, status, limit, offset)


@router.post("/tick")
def tick(request: Request, cu: CurrentUser = Depends(require_admin)):
    return _sc(request).tick()
