"""
Cyber Hub Backend - Windows Security Posture routes (Part 11)
Developed by Syed Muhammad Tayyab

Permission model (same rule as Parts 7 / 9 / 10 - raising protection is open
to anyone signed in, lowering it needs a Cyber Hub administrator):

  anyone signed in : view everything, apply fixes that raise protection
                     (Defender, UAC, Guest off, WDigest off, SMBv1 off,
                     SmartScreen, BitLocker resume, updates resumed ...),
                     "fix all safe issues", update Defender definitions, start
                     a Defender scan, search for missing updates, open a
                     Windows settings page, run the watch, stop ignoring a
                     check, acknowledge alerts
  administrator    : fixes that could lock someone out (turn Remote Desktop
                     off, disable the built-in Administrator, remove Defender
                     exclusions), force=true past a safety guard, ignore a
                     check (accept the risk), undo a fix, re-baseline the
                     watch, clear the alert list

Fixes with side effects answer 428 with the warning text until they are sent
again with confirm=true. Windows itself only lets an elevated engine change
machine-wide settings (start_cyberhub_admin.bat) - otherwise 403 with that hint.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.posture import CATEGORY_NAMES, SEVERITIES, PostureError, PostureService

router = APIRouter(prefix="/api/posture", tags=["posture"],
                   dependencies=[Depends(require_token), Depends(require_session)])

CATS = "^(" + "|".join(CATEGORY_NAMES) + ")$"


def _ps(request: Request) -> PostureService:
    return request.app.state.posture


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except PostureError as e:
        raise HTTPException(e.status, e.message)


def _is_admin(cu: CurrentUser) -> bool:
    return cu.user["role"] == "admin"


# ================================================================== overview
@router.get("/status")
def status(request: Request):
    """The Security posture card: 0-100 score + grade, the six Windows Security sections (score, passed, failed,
    worst severity), counts per severity, top 5 issues, OS, engine elevated?, restart pending, unread alerts."""
    return _ps(request).status()


@router.get("/checks")
def checks(request: Request, category: str | None = Query(None, pattern=CATS),
           status: str | None = Query(None, pattern="^(pass|fail|unknown|ignored)$"), refresh: bool = False):
    """Every check: {id, category, title, status, severity, value, detail, why, evidence, fix{label, admin, confirm,
    reboot, needs_elevation, blocked, reversible}, manual{steps[], open}, managed, ignored}. Failing first."""
    a = _run(_ps(request).analyze, refresh)
    items = a["checks"]
    if category:
        items = [c for c in items if c["category"] == category]
    if status == "ignored":
        items = [c for c in items if c["ignored"]]
    elif status:
        items = [c for c in items if c["status"] == status and not (status == "fail" and c["ignored"])]
    return {k: a[k] for k in ("score", "grade", "categories", "counts", "totals", "checked_at", "elevated",
                              "platform")} | {"checks": items}


@router.get("/checks/{check_id}")
def get_check(request: Request, check_id: str, refresh: bool = False):
    return _run(_ps(request).get_check, check_id, refresh)


class FixIn(BaseModel):
    confirm: bool = False      # required for fixes with side effects (the 428 answer says which)
    force: bool = False        # admin: go past a safety guard (open Remote Desktop sessions ...)


@router.post("/checks/{check_id}/fix")
def fix_check(request: Request, check_id: str, body: FixIn | None = None,
              cu: CurrentUser = Depends(require_session)):
    """Apply the one-click fix, read the setting back and report {status: applied | not_applied, verified,
    message, reboot_required, change_id, check}. Half-done multi-step fixes are rolled back."""
    body = body or FixIn()
    if body.force and not _is_admin(cu):
        raise HTTPException(403, "Administrator rights required to use force")
    return _run(_ps(request).fix, check_id, cu.user["username"], _is_admin(cu), body.confirm, body.force)


class FixAllIn(BaseModel):
    categories: list[str] | None = Field(None, max_length=6)
    min_severity: str = Field("low", pattern="^(info|low|medium|high|critical)$")


@router.post("/fix-all")
def fix_all(request: Request, body: FixAllIn | None = None, cu: CurrentUser = Depends(require_session)):
    """Fix every safe issue in one go (skips fixes that need confirmation, administrator rights you do not have,
    or an elevated engine). Returns applied / not_applied / skipped + score before and after."""
    body = body or FixAllIn()
    if body.categories and any(c not in CATEGORY_NAMES for c in body.categories):
        raise HTTPException(422, f"categories must be from: {', '.join(CATEGORY_NAMES)}")
    return _run(_ps(request).fix_all, cu.user["username"], _is_admin(cu), body.categories, body.min_severity)


class IgnoreIn(BaseModel):
    reason: str | None = Field(None, max_length=300)
    days: int | None = Field(None, ge=1, le=3650)        # None = until switched back on


@router.post("/checks/{check_id}/ignore")
def ignore(request: Request, check_id: str, body: IgnoreIn | None = None, cu: CurrentUser = Depends(require_admin)):
    """Accept the risk: the check stays visible but no longer lowers the score or raises alerts."""
    body = body or IgnoreIn()
    return _run(_ps(request).ignore, check_id, cu.user["username"], body.reason, body.days)


@router.delete("/checks/{check_id}/ignore")
def unignore(request: Request, check_id: str, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).unignore, check_id, cu.user["username"])


@router.get("/ignored")
def ignored(request: Request):
    return {"items": _ps(request).ignored()}


# ================================================================== change history
@router.get("/changes")
def changes(request: Request, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Every fix Cyber Hub applied: what, by whom, previous values kept, reboot needed, reversible."""
    return _ps(request).changes(limit, offset)


@router.post("/changes/{change_id}/revert")
def revert(request: Request, change_id: int, cu: CurrentUser = Depends(require_admin)):
    """Undo a fix (puts the previous values back). Administrator only - it lowers protection."""
    return _run(_ps(request).revert, change_id, cu.user["username"])


# ================================================================== Defender
@router.get("/defender")
def defender(request: Request, refresh: bool = False):
    """Microsoft Defender details: engine / platform / definition versions + age, scan ages, every protection
    switch, preferences, exclusions with risk notes (admin engine only), other antivirus products."""
    return _run(_ps(request).defender, refresh)


@router.post("/defender/update")
def defender_update(request: Request, cu: CurrentUser = Depends(require_session)):
    return _run(_ps(request).update_signatures, cu.user["username"])


class ScanIn(BaseModel):
    type: str = Field("quick", pattern="^(quick|full)$")


@router.post("/defender/scan")
def defender_scan(request: Request, body: ScanIn | None = None, cu: CurrentUser = Depends(require_session)):
    """Start a Microsoft Defender scan in the background (Cyber Hub's own scanner is /api/scan)."""
    return _run(_ps(request).defender_scan, (body or ScanIn()).type, cu.user["username"])


# ================================================================== Windows Update
@router.get("/updates")
def updates(request: Request, refresh: bool = False):
    """Last install / search, history (title, date, result), paused until, policy, service, restart pending,
    Windows version + end-of-support date, and the last 'missing updates' search."""
    return _run(_ps(request).updates, refresh)


@router.post("/updates/search")
def search_updates(request: Request, cu: CurrentUser = Depends(require_session)):
    """Ask Windows Update which updates are missing (background; can take a few minutes). Poll GET."""
    return _run(_ps(request).start_update_search, cu.user["username"])


@router.get("/updates/search")
def search_status(request: Request):
    return _ps(request).search_status()


# ================================================================== accounts / open settings
@router.get("/accounts")
def accounts(request: Request):
    """Local Windows accounts: enabled, administrator, built-in Guest / Administrator, password required,
    last sign-in, password age - plus the Account protection checks."""
    return _run(_ps(request).accounts)


@router.post("/open/{target}")
def open_settings(request: Request, target: str):
    """Open the matching Windows Security / Settings page on this PC (manual fixes): windows_update,
    defender_settings, core_isolation, bitlocker, tpm, remote_desktop, accounts, app_browser, ..."""
    return _run(_ps(request).open_settings, target)


# ================================================================== watch & alerts
@router.post("/watch")
def watch_now(request: Request):
    """Re-check now: alerts for settings that got weaker since last time and for new Defender exclusions."""
    return _run(_ps(request).watch_once)


@router.post("/rebaseline")
def rebaseline(request: Request, cu: CurrentUser = Depends(require_admin)):
    return _run(_ps(request).rebaseline)


@router.get("/events")
def events(request: Request, after_id: int = Query(0, ge=0),
           severity: str | None = Query(None, pattern="^(" + "|".join(SEVERITIES) + ")$"),
           kind: str | None = Query(None, max_length=40), unacknowledged: bool = False,
           limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Alert timeline (poll with after_id=last_id): regression, resolved, exclusion_added, fix_applied,
    fix_not_applied, fix_failed, fix_reverted, ignored, updates_missing, baseline ..."""
    return _ps(request).events(after_id, severity, kind, unacknowledged, limit, offset)


class AckIn(BaseModel):
    ids: list[int] | None = Field(None, max_length=1000)


@router.post("/events/ack")
def ack(request: Request, body: AckIn | None = None):
    return {"acknowledged": _ps(request).acknowledge((body or AckIn()).ids)}


@router.delete("/events")
def clear_events(request: Request, cu: CurrentUser = Depends(require_admin)):
    n = _ps(request).clear_events()
    request.app.state.activity.record("posture", "Security posture alert list cleared",
                                      f"{n} events (by {cu.user['username']})", source="posture")
    return {"deleted": n}


@router.get("/summary")
def summary(request: Request, days: int = Query(30, ge=1, le=365)):
    """Graphs: score per day, alerts per day by severity, alerts by kind, fixes by status, section scores."""
    return _ps(request).summary(days)
