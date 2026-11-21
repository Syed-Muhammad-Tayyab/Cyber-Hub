"""
Cyber Hub Backend - Activity log routes
Developed by Syed Muhammad Tayyab
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import require_session_if_account, require_token

router = APIRouter(prefix="/api/activity", tags=["activity"], dependencies=[Depends(require_token)])

Severity = Literal["info", "low", "medium", "high", "critical"]


class ActivityIn(BaseModel):
    category: str = Field(..., examples=["system"])
    title: str = Field(..., min_length=1, max_length=200)
    detail: str | None = Field(None, max_length=4000)
    severity: Severity = "info"


@router.get("")
def list_activity(request: Request, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                  category: str | None = None, severity: Severity | None = None):
    return request.app.state.activity.list(limit, offset, category, severity)


@router.get("/summary")
def activity_summary(request: Request, days: int = Query(7, ge=1, le=365)):
    return request.app.state.activity.summary(days)


@router.post("", status_code=201)
def add_activity(request: Request, body: ActivityIn):
    """Lets the UI log user-side events (e.g. 'Opened Firewall page')."""
    try:
        return request.app.state.activity.record(body.category, body.title, body.detail, body.severity, source="ui")
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.delete("", dependencies=[Depends(require_session_if_account)])
def clear_activity(request: Request, older_than_days: int | None = Query(None, ge=0)):
    return {"deleted": request.app.state.activity.clear(older_than_days)}
