"""
Cyber Hub Backend - Account & session service (Part 2)
Developed by Syed Muhammad Tayyab

- One owner account is created on first launch (setup screen); more local
  users can be added by the owner later.
- Passwords/PINs/recovery codes are scrypt-hashed; session tokens are random
  and only their SHA-256 is stored, so a stolen database can't log anyone in.
- Brute-force protection: N failed attempts -> account locked for M minutes.
- Sessions expire, auto-lock after idle time and can be revoked.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone

from ..database import Database
from . import passwords as pw
from .activity import ActivityService
from .settings_store import SettingsStore

_DUMMY_HASH = pw.hash_secret("cyberhub-timing-equaliser")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PIN_RE = re.compile(r"^\d{4,8}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Same format SQLite strftime('%Y-%m-%dT%H:%M:%fZ') produces -> string-comparable."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def public_user(u: dict) -> dict:
    return {
        "id": u["id"], "username": u["username"], "display_name": u["display_name"],
        "email": u["email"], "role": u["role"], "has_pin": bool(u["pin_hash"]),
        "created_at": u["created_at"], "last_login_at": u["last_login_at"],
        "password_changed_at": u["password_changed_at"],
    }


class AccountService:
    def __init__(self, db: Database, settings: SettingsStore, activity: ActivityService):
        self.db, self.settings, self.activity = db, settings, activity
        self.listeners: list = []          # Part 12: fn(event, session_id=None, user_id=None) - vault auto-lock

    def _notify(self, event: str, session_id: int | None = None, user_id: int | None = None) -> None:
        """Tell other modules a session was locked / ended. A failing listener never breaks sign-in."""
        for fn in list(self.listeners):
            try:
                fn(event, session_id=session_id, user_id=user_id)
            except Exception:                                                    # pragma: no cover
                pass

    # ------------------------------------------------------------ queries
    def has_account(self) -> bool:
        return self.db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] > 0

    def _user_by_name(self, username: str) -> dict | None:
        return self.db.fetchone("SELECT * FROM users WHERE username=?", (username,))

    def _user(self, uid: int) -> dict:
        return self.db.fetchone("SELECT * FROM users WHERE id=?", (uid,))

    # ------------------------------------------------------------ validation
    @staticmethod
    def _check_username(username: str) -> None:
        if not USERNAME_RE.match(username or ""):
            raise AuthError(422, "Username must be 3-32 characters: letters, digits, _ . -")

    @staticmethod
    def _check_email(email: str | None) -> None:
        if email and not EMAIL_RE.match(email):
            raise AuthError(422, "Invalid email address.")

    @staticmethod
    def _check_password(password: str, username: str | None) -> None:
        try:
            pw.validate_policy(password, username)
        except ValueError as e:
            raise AuthError(422, str(e))

    # ------------------------------------------------------------ create
    def create_user(self, username: str, display_name: str, password: str,
                    email: str | None = None, role: str = "admin") -> dict:
        self._check_username(username)
        self._check_email(email)
        self._check_password(password, username)
        if self._user_by_name(username):
            raise AuthError(409, "Username already exists.")
        cur = self.db.execute(
            "INSERT INTO users(username, display_name, email, password_hash, role) VALUES (?,?,?,?,?)",
            (username, (display_name or username).strip()[:64], email, pw.hash_secret(password), role),
        )
        self.activity.record("account", "Account created", f"User '{username}' ({role})")
        return self._user(cur.lastrowid)

    def setup_owner(self, username: str, display_name: str, password: str,
                    email: str | None, device: str | None) -> dict:
        if self.has_account():
            raise AuthError(409, "Setup already completed - please log in.")
        user = self.create_user(username, display_name, password, email, role="admin")
        return self._start_session(user, "password", device)

    # ------------------------------------------------------------ login
    def _history(self, username: str, success: bool, method: str, reason: str | None, device: str | None):
        self.db.execute(
            "INSERT INTO login_history(username, success, method, reason, device) VALUES (?,?,?,?,?)",
            (username, int(success), method, reason, device),
        )

    def _fail(self, user: dict | None, username: str, method: str, reason: str, device: str | None):
        self._history(username, False, method, reason, device)
        if user:
            attempts = user["failed_attempts"] + 1
            max_fail = self.settings.get("max_failed_logins")
            locked_until = None
            if attempts >= max_fail:
                locked_until = iso(now() + timedelta(minutes=self.settings.get("lockout_minutes")))
                attempts = 0
                self.activity.record("account", "Account locked after failed logins",
                                     f"User '{user['username']}' locked until {locked_until}", "high")
            else:
                self.activity.record("account", "Failed login attempt",
                                     f"User '{user['username']}' via {method}", "medium")
            self.db.execute("UPDATE users SET failed_attempts=?, locked_until=COALESCE(?, locked_until) WHERE id=?",
                            (attempts, locked_until, user["id"]))
        else:
            self.activity.record("account", "Login attempt for unknown user", username[:64], "medium")
        raise AuthError(401, "Invalid username or credentials.")

    def _ensure_not_locked(self, user: dict) -> None:
        if user["locked_until"] and parse(user["locked_until"]) > now():
            secs = int((parse(user["locked_until"]) - now()).total_seconds())
            raise AuthError(423, f"Account temporarily locked. Try again in {secs // 60 + 1} minute(s).")

    def login(self, username: str, secret: str, method: str = "password", device: str | None = None) -> dict:
        user = self._user_by_name(username or "")
        if user:
            self._ensure_not_locked(user)
        if method == "pin":
            ok = bool(user and user["pin_hash"]) and pw.verify_secret(secret, user["pin_hash"])
        else:
            ok = pw.verify_secret(secret, user["password_hash"] if user else _DUMMY_HASH) and bool(user)
        if not ok:
            self._fail(user, username or "?", method, "bad credentials", device)
        if method == "password" and pw.needs_rehash(user["password_hash"]):
            self.db.execute("UPDATE users SET password_hash=? WHERE id=?", (pw.hash_secret(secret), user["id"]))
        return self._start_session(user, method, device)

    def _start_session(self, user: dict, method: str, device: str | None) -> dict:
        token = secrets.token_urlsafe(32)
        expires = now() + timedelta(minutes=self.settings.get("session_timeout_minutes"))
        cur = self.db.execute(
            "INSERT INTO sessions(user_id, token_hash, expires_at, device) VALUES (?,?,?,?)",
            (user["id"], pw.sha256(token), iso(expires), device),
        )
        self.db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=? WHERE id=?",
                        (iso(now()), user["id"]))
        self._history(user["username"], True, method, None, device)
        self.activity.record("account", "Signed in", f"User '{user['username']}' via {method}")
        return {"session_token": token, "session_id": cur.lastrowid, "expires_at": iso(expires),
                "user": public_user(self._user(user["id"]))}

    # ------------------------------------------------------------ sessions
    def authenticate(self, token: str | None, allow_locked: bool = False,
                     touch: bool = True) -> tuple[dict, dict]:
        """Returns (session, user) or raises. Applies expiry + idle auto-lock.
        touch=False (used by live streams) checks the session without counting as user activity,
        so an open monitor page cannot keep the app from auto-locking."""
        if not token:
            raise AuthError(401, "Not signed in.")
        s = self.db.fetchone("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (pw.sha256(token),))
        if not s or parse(s["expires_at"]) <= now():
            raise AuthError(401, "Session expired - please sign in again.")
        idle = self.settings.get("auto_lock_minutes")
        if idle and not s["is_locked"] and parse(s["last_seen_at"]) < now() - timedelta(minutes=idle):
            self.db.execute("UPDATE sessions SET is_locked=1 WHERE id=?", (s["id"],))
            s["is_locked"] = 1
            self.activity.record("account", "Session auto-locked after inactivity")
            self._notify("lock", session_id=s["id"], user_id=s["user_id"])
        if s["is_locked"] and not allow_locked:
            raise AuthError(423, "Session is locked - unlock with your PIN or password.")
        if touch and not s["is_locked"]:
            self.db.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (iso(now()), s["id"]))
        return s, self._user(s["user_id"])

    def logout(self, session: dict) -> None:
        self.db.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session["id"],))
        self.activity.record("account", "Signed out")
        self._notify("logout", session_id=session["id"], user_id=session["user_id"])

    def lock(self, session: dict) -> None:
        self.db.execute("UPDATE sessions SET is_locked=1 WHERE id=?", (session["id"],))
        self.activity.record("account", "Session locked")
        self._notify("lock", session_id=session["id"], user_id=session["user_id"])

    def unlock(self, session: dict, user: dict, pin: str | None, password: str | None) -> None:
        self._ensure_not_locked(user)
        ok = (pin is not None and pw.verify_secret(pin, user["pin_hash"])) or \
             (password is not None and pw.verify_secret(password, user["password_hash"]))
        if not ok:
            try:
                self._fail(user, user["username"], "pin" if pin else "password", "unlock failed", session["device"])
            except AuthError:
                raise AuthError(401, "Incorrect PIN or password.")
        self.db.execute("UPDATE sessions SET is_locked=0, last_seen_at=? WHERE id=?", (iso(now()), session["id"]))
        self.db.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user["id"],))
        self.activity.record("account", "Session unlocked")

    def list_sessions(self, user: dict, current_id: int) -> list[dict]:
        rows = self.db.fetchall(
            "SELECT id, created_at, last_seen_at, expires_at, is_locked, device FROM sessions "
            "WHERE user_id=? AND revoked=0 AND expires_at > ? ORDER BY last_seen_at DESC",
            (user["id"], iso(now())),
        )
        for r in rows:
            r["current"] = r["id"] == current_id
            r["is_locked"] = bool(r["is_locked"])
        return rows

    def revoke_session(self, user: dict, session_id: int) -> None:
        n = self.db.execute("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?", (session_id, user["id"])).rowcount
        if not n:
            raise AuthError(404, "Session not found.")
        self.activity.record("account", "Session revoked", f"Session #{session_id}", "low")
        self._notify("logout", session_id=session_id, user_id=user["id"])

    # ------------------------------------------------------------ profile & credentials
    def update_profile(self, user: dict, display_name: str | None, email: str | None) -> dict:
        self._check_email(email)
        self.db.execute(
            "UPDATE users SET display_name=COALESCE(?, display_name), email=COALESCE(?, email) WHERE id=?",
            (display_name.strip()[:64] if display_name else None, email, user["id"]),
        )
        self.activity.record("account", "Profile updated")
        return public_user(self._user(user["id"]))

    def change_password(self, user: dict, session: dict, current: str, new: str) -> int:
        if not pw.verify_secret(current, user["password_hash"]):
            self.activity.record("account", "Password change failed (wrong current password)", severity="medium")
            raise AuthError(401, "Current password is incorrect.")
        if current == new:
            raise AuthError(422, "New password must be different.")
        self._check_password(new, user["username"])
        self.db.execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?",
                        (pw.hash_secret(new), iso(now()), user["id"]))
        revoked = self.db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND id<>? AND revoked=0",
                                  (user["id"], session["id"])).rowcount
        self.activity.record("account", "Password changed", f"{revoked} other session(s) signed out", "low")
        self._notify("revoke_others", session_id=session["id"], user_id=user["id"])
        return revoked

    def set_pin(self, user: dict, password: str, pin: str) -> None:
        if not pw.verify_secret(password, user["password_hash"]):
            raise AuthError(401, "Password is incorrect.")
        if not PIN_RE.match(pin):
            raise AuthError(422, "PIN must be 4-8 digits.")
        if len(set(pin)) == 1 or pin in "0123456789" or pin in "9876543210":
            raise AuthError(422, "PIN is too easy to guess (avoid 1111, 1234).")
        self.db.execute("UPDATE users SET pin_hash=? WHERE id=?", (pw.hash_secret(pin), user["id"]))
        self.activity.record("account", "Quick-unlock PIN set")

    def remove_pin(self, user: dict) -> None:
        self.db.execute("UPDATE users SET pin_hash=NULL WHERE id=?", (user["id"],))
        self.activity.record("account", "Quick-unlock PIN removed", severity="low")

    # ------------------------------------------------------------ recovery
    def generate_recovery_codes(self, user: dict, password: str, count: int = 8) -> list[str]:
        if not pw.verify_secret(password, user["password_hash"]):
            raise AuthError(401, "Password is incorrect.")
        codes = [pw.new_recovery_code() for _ in range(count)]
        with self.db.tx() as c:
            c.execute("DELETE FROM recovery_codes WHERE user_id=?", (user["id"],))
            for code in codes:
                c.execute("INSERT INTO recovery_codes(user_id, code_hash) VALUES (?,?)", (user["id"], pw.sha256(code)))
        self.activity.record("account", "Recovery codes generated", f"{count} new codes; old codes invalidated")
        return codes

    def recovery_status(self, user: dict) -> dict:
        r = self.db.fetchone("SELECT COUNT(*) AS total, SUM(used_at IS NULL) AS left FROM recovery_codes WHERE user_id=?",
                             (user["id"],))
        return {"total": r["total"], "remaining": r["left"] or 0}

    def reset_with_recovery(self, username: str, code: str, new_password: str, device: str | None) -> dict:
        user = self._user_by_name(username or "")
        if user:
            self._ensure_not_locked(user)
        row = user and self.db.fetchone(
            "SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (user["id"], pw.sha256((code or "").strip().upper())),
        )
        if not row:
            self._fail(user, username or "?", "recovery", "bad recovery code", device)
        self._check_password(new_password, user["username"])
        self.db.execute("UPDATE recovery_codes SET used_at=? WHERE id=?", (iso(now()), row["id"]))
        self.db.execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?",
                        (pw.hash_secret(new_password), iso(now()), user["id"]))
        self.db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user["id"],))
        self.activity.record("account", "Password reset with recovery code", severity="medium")
        self._notify("revoke_user", user_id=user["id"])
        return self._start_session(self._user(user["id"]), "recovery", device)

    # ------------------------------------------------------------ history / delete
    def login_history(self, limit: int = 50) -> list[dict]:
        rows = self.db.fetchall("SELECT * FROM login_history ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["success"] = bool(r["success"])
        return rows

    def login_stats(self, days: int = 7) -> dict:
        r = self.db.fetchone(
            "SELECT SUM(success) AS ok, SUM(1-success) AS failed FROM login_history "
            "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)", (f"-{days} days",))
        return {"days": days, "successful": r["ok"] or 0, "failed": r["failed"] or 0}

    def delete_account(self, user: dict, password: str) -> None:
        if not pw.verify_secret(password, user["password_hash"]):
            raise AuthError(401, "Password is incorrect.")
        self.db.execute("DELETE FROM users WHERE id=?", (user["id"],))
        self.activity.record("account", "Account deleted", f"User '{user['username']}'", "high")
        self._notify("revoke_user", user_id=user["id"])
