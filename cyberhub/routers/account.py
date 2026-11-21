"""
Cyber Hub Backend - Account routes (Part 2)
Developed by Syed Muhammad Tayyab

Session token goes in header  X-CyberHub-Session  (plus the API token from Part 1).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import (CurrentUser, require_admin, require_session,
                        require_session_allow_locked, require_token)
from ..services import passwords as pw
from ..services.accounts import AuthError, public_user

router = APIRouter(prefix="/api/account", tags=["account"], dependencies=[Depends(require_token)])


def _svc(request: Request):
    return request.app.state.accounts


def _device(request: Request, given: str | None) -> str:
    ua = request.headers.get("user-agent", "")[:120]
    return (given or ua or "Cyber Hub")[:120]


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except AuthError as e:
        raise HTTPException(e.status, e.message)


# ------------------------------------------------------------------ models
class SetupIn(BaseModel):
    username: str = Field(..., examples=["syed"])
    display_name: str = Field("", max_length=64)
    email: str | None = None
    password: str = Field(..., max_length=256)
    device: str | None = None


class LoginIn(BaseModel):
    username: str
    password: str | None = Field(None, max_length=256)
    pin: str | None = Field(None, max_length=8)
    device: str | None = None


class UnlockIn(BaseModel):
    pin: str | None = Field(None, max_length=8)
    password: str | None = Field(None, max_length=256)


class ProfileIn(BaseModel):
    display_name: str | None = Field(None, max_length=64)
    email: str | None = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(..., max_length=256)


class PinIn(BaseModel):
    password: str
    pin: str


class PasswordIn(BaseModel):
    password: str


class RecoveryResetIn(BaseModel):
    username: str
    recovery_code: str
    new_password: str = Field(..., max_length=256)
    device: str | None = None


class StrengthIn(BaseModel):
    password: str = Field(..., max_length=256)
    username: str | None = None


class NewUserIn(BaseModel):
    username: str
    display_name: str = ""
    email: str | None = None
    password: str = Field(..., max_length=256)
    role: str = Field("standard", pattern="^(admin|standard)$")


# ------------------------------------------------------------------ public (API token only)
@router.get("/status")
def status(request: Request):
    """UI start-up: decides between Setup screen and Login screen."""
    svc = _svc(request)
    return {"has_account": svc.has_account(), "setup_required": not svc.has_account()}


@router.post("/setup", status_code=201)
def setup(request: Request, body: SetupIn):
    """First-run: create the owner account and sign in."""
    return _run(_svc(request).setup_owner, body.username, body.display_name, body.password,
                body.email, _device(request, body.device))


@router.post("/login")
def login(request: Request, body: LoginIn):
    if bool(body.password) == bool(body.pin):
        raise HTTPException(422, "Provide either password or pin.")
    method, secret = ("pin", body.pin) if body.pin else ("password", body.password)
    return _run(_svc(request).login, body.username, secret, method, _device(request, body.device))


@router.post("/recover")
def recover(request: Request, body: RecoveryResetIn):
    """Forgot password: one-time recovery code -> new password + new session."""
    return _run(_svc(request).reset_with_recovery, body.username, body.recovery_code,
                body.new_password, _device(request, body.device))


@router.post("/password-strength")
def password_strength(body: StrengthIn):
    """Live strength meter for the signup / change-password forms."""
    return pw.strength(body.password, body.username)


# ------------------------------------------------------------------ signed in (locked allowed)
@router.get("/me")
def me(cu: CurrentUser = Depends(require_session_allow_locked)):
    return {"user": public_user(cu.user), "session": {
        "id": cu.session["id"], "expires_at": cu.session["expires_at"], "is_locked": bool(cu.session["is_locked"])}}


@router.post("/logout")
def logout(request: Request, cu: CurrentUser = Depends(require_session_allow_locked)):
    _svc(request).logout(cu.session)
    return {"ok": True}


@router.post("/unlock")
def unlock(request: Request, body: UnlockIn, cu: CurrentUser = Depends(require_session_allow_locked)):
    if not body.pin and not body.password:
        raise HTTPException(422, "Provide pin or password.")
    _run(_svc(request).unlock, cu.session, cu.user, body.pin, body.password)
    return {"ok": True, "is_locked": False}


# ------------------------------------------------------------------ signed in + unlocked
@router.post("/lock")
def lock(request: Request, cu: CurrentUser = Depends(require_session)):
    _svc(request).lock(cu.session)
    return {"ok": True, "is_locked": True}


@router.patch("/me")
def update_profile(request: Request, body: ProfileIn, cu: CurrentUser = Depends(require_session)):
    return _run(_svc(request).update_profile, cu.user, body.display_name, body.email)


@router.post("/change-password")
def change_password(request: Request, body: ChangePasswordIn, cu: CurrentUser = Depends(require_session)):
    n = _run(_svc(request).change_password, cu.user, cu.session, body.current_password, body.new_password)
    return {"ok": True, "other_sessions_signed_out": n}


@router.put("/pin")
def set_pin(request: Request, body: PinIn, cu: CurrentUser = Depends(require_session)):
    _run(_svc(request).set_pin, cu.user, body.password, body.pin)
    return {"ok": True, "has_pin": True}


@router.delete("/pin")
def remove_pin(request: Request, cu: CurrentUser = Depends(require_session)):
    _svc(request).remove_pin(cu.user)
    return {"ok": True, "has_pin": False}


@router.post("/recovery-codes")
def recovery_codes(request: Request, body: PasswordIn, cu: CurrentUser = Depends(require_session)):
    """Shown ONCE - the UI must tell the user to save/print them."""
    return {"codes": _run(_svc(request).generate_recovery_codes, cu.user, body.password)}


@router.get("/recovery-codes")
def recovery_status(request: Request, cu: CurrentUser = Depends(require_session)):
    return _svc(request).recovery_status(cu.user)


@router.get("/sessions")
def sessions(request: Request, cu: CurrentUser = Depends(require_session)):
    return _svc(request).list_sessions(cu.user, cu.session["id"])


@router.delete("/sessions/{session_id}")
def revoke(request: Request, session_id: int, cu: CurrentUser = Depends(require_session)):
    _run(_svc(request).revoke_session, cu.user, session_id)
    return {"ok": True}


@router.get("/login-history")
def login_history(request: Request, limit: int = Query(50, ge=1, le=500),
                  cu: CurrentUser = Depends(require_session)):
    svc = _svc(request)
    return {"stats": svc.login_stats(7), "items": svc.login_history(limit)}


@router.post("/delete")
def delete_account(request: Request, body: PasswordIn, cu: CurrentUser = Depends(require_session)):
    _run(_svc(request).delete_account, cu.user, body.password)
    return {"ok": True}


# ------------------------------------------------------------------ admin: extra local users
@router.get("/users")
def list_users(request: Request, cu: CurrentUser = Depends(require_admin)):
    return [public_user(u) for u in request.app.state.db.fetchall("SELECT * FROM users ORDER BY id")]


@router.post("/users", status_code=201)
def add_user(request: Request, body: NewUserIn, cu: CurrentUser = Depends(require_admin)):
    u = _run(_svc(request).create_user, body.username, body.display_name, body.password, body.email, body.role)
    return public_user(u)


@router.delete("/users/{user_id}")
def remove_user(request: Request, user_id: int, cu: CurrentUser = Depends(require_admin)):
    if user_id == cu.user["id"]:
        raise HTTPException(422, "Use /api/account/delete to delete your own account.")
    if not request.app.state.db.execute("DELETE FROM users WHERE id=?", (user_id,)).rowcount:
        raise HTTPException(404, "User not found.")
    request.app.state.activity.record("account", "User removed", f"id {user_id}", "low")
    _svc(request)._notify("revoke_user", user_id=user_id)      # Part 12: close their open password vault
    return {"ok": True}
