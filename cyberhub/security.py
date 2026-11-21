"""
Cyber Hub Backend - Local API protection
Developed by Syed Muhammad Tayyab

The backend listens only on 127.0.0.1, but any web page open in the user's
browser could still try to call http://127.0.0.1:8765. To stop that, every
/api request (except /api/health) must carry the per-install token in the
`X-CyberHub-Token` header. The token is generated on first run and stored in
the user's data folder; the desktop UI reads it at launch (Part 20 wires this
into the packaged app; in dev, GET /api/bootstrap hands it to allowed origins).
"""
from __future__ import annotations

import hmac
import os
import secrets
import stat
from pathlib import Path

from fastapi import Header, HTTPException, Request, status

TOKEN_HEADER = "X-CyberHub-Token"


def load_or_create_token(path: Path) -> str:
    if path.exists():
        tok = path.read_text(encoding="utf-8").strip()
        if len(tok) >= 32:
            return tok
    tok = secrets.token_urlsafe(32)
    path.write_text(tok, encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 where supported
    except OSError:
        pass
    return tok


def require_token(request: Request, x_cyberhub_token: str | None = Header(default=None)) -> None:
    expected: str = request.app.state.api_token
    if not x_cyberhub_token or not hmac.compare_digest(x_cyberhub_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid API token")


# ---------------------------------------------------------------- Part 2: sessions
SESSION_HEADER = "X-CyberHub-Session"


class CurrentUser:
    """Resolved signed-in user + session, injected into routes."""
    def __init__(self, session: dict, user: dict):
        self.session, self.user = session, user


def _auth(request: Request, token: str | None, allow_locked: bool) -> CurrentUser:
    from .services.accounts import AuthError
    try:
        s, u = request.app.state.accounts.authenticate(token, allow_locked=allow_locked)
    except AuthError as e:
        raise HTTPException(e.status, e.message)
    return CurrentUser(s, u)


def require_session(request: Request,
                    x_cyberhub_session: str | None = Header(default=None)) -> CurrentUser:
    """Signed in AND unlocked. Used by every module from Part 3 onward."""
    return _auth(request, x_cyberhub_session, allow_locked=False)


def require_session_allow_locked(request: Request,
                                 x_cyberhub_session: str | None = Header(default=None)) -> CurrentUser:
    """Signed in, may be locked (for /unlock, /logout, /me)."""
    return _auth(request, x_cyberhub_session, allow_locked=True)


def require_admin(request: Request, x_cyberhub_session: str | None = Header(default=None)) -> CurrentUser:
    cu = _auth(request, x_cyberhub_session, allow_locked=False)
    if cu.user["role"] != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator rights required")
    return cu


def require_session_if_account(request: Request,
                               x_cyberhub_session: str | None = Header(default=None)) -> CurrentUser | None:
    """Before setup there is no account yet, so allow; afterwards a session is required.
    Protects settings changes and log clearing."""
    if not request.app.state.accounts.has_account():
        return None
    return _auth(request, x_cyberhub_session, allow_locked=False)
