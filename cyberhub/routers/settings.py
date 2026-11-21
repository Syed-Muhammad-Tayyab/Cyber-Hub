"""
Cyber Hub Backend - Settings routes
Developed by Syed Muhammad Tayyab
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from ..security import CurrentUser, require_session_if_account, require_token
from ..services.settings_store import ADMIN_KEYS

router = APIRouter(prefix="/api/settings", tags=["settings"], dependencies=[Depends(require_token)])


@router.get("")
def get_settings(request: Request):
    return request.app.state.settings_store.all()


@router.patch("")
def update_settings(request: Request, changes: dict[str, Any] = Body(...),
                    cu: CurrentUser | None = Depends(require_session_if_account)):
    guarded = sorted(set(changes) & ADMIN_KEYS)
    if guarded and cu is not None and cu.user["role"] != "admin":
        raise HTTPException(403, f"Administrator rights required to change: {', '.join(guarded)}")
    try:
        result = request.app.state.settings_store.update(changes)
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(422, str(e).strip("'\""))
    request.app.state.activity.record("settings", "Settings updated", ", ".join(sorted(changes)))
    return result


@router.post("/reset")
def reset_settings(request: Request, cu: CurrentUser | None = Depends(require_session_if_account)):
    if cu is not None and cu.user["role"] != "admin":
        raise HTTPException(403, "Administrator rights required")
    request.app.state.activity.record("settings", "Settings reset to defaults", severity="low")
    return request.app.state.settings_store.reset()
