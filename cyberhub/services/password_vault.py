"""
Cyber Hub Backend - Password Vault & Auditor (Part 12)
Developed by Syed Muhammad Tayyab

Key design (zero-knowledge at rest - the database alone reveals nothing):

    master password --scrypt(N=2^17, r=8, p=1)--> 32 bytes --HKDF(salt = device pepper)--> KEK
    device pepper   = HMAC(Part 6 vault master key, label)   (DPAPI-sealed on Windows)
    vault key (VK)  = 32 random bytes, stored only wrapped:
                        AES-GCM(KEK, VK)          - unlock with the master password
                        AES-GCM(HKDF(recovery), VK) - unlock with the 160-bit recovery key
    item            = AES-GCM(VK, json payload, AAD = user id | item id | type)

* Titles, user names, URLs, notes, cards and passwords exist only inside the
  encrypted blobs; events and the stored audit summary hold counts, never content.
* Device binding: a stolen copy of cyberhub.db can't even be brute-forced offline
  without this Windows user's DPAPI-sealed vault.key. The recovery key is not
  device-bound, so a new PC / reinstalled Windows can still open the vault.
* One vault per Cyber Hub user; an administrator can't read anyone else's vault.
* Unlocked keys live only in memory, per Cyber Hub session, and are dropped on
  idle (pv_auto_lock_minutes), when the app locks / signs out (Part 2 listener),
  on shutdown, and when the master password changes.
* Wrong master passwords: 5 free tries, then 30 s, 60 s, 120 s ... up to 30 min.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import APP_VERSION
from ..database import Database
from ..logger import get_logger
from . import password_io as pio
from . import password_tools as tools
from . import passwords as account_pw
from .clipboard import ClipboardError, ClipboardManager
from .password_tools import BreachChecker, ToolError, normalize

log = get_logger("passwords")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
TYPES = ("login", "card", "note", "identity")
MAX_ITEMS = 10000
MAX_BLOB = 256 * 1024
MAX_IMPORT_BYTES = 10 * 1024 * 1024
HISTORY_KEEP = 10
FREE_TRIES = 5
MAX_LOCKOUT = 1800
MASK = "••••••••"
PEPPER_LABEL = "password-vault-v1"
GRADES = [(90, "Excellent"), (75, "Good"), (50, "Needs attention"), (0, "At risk")]
WEIGHTS = {"breached": 1.0, "reused": 0.6, "weak": 0.6, "fair": 0.35, "empty_password": 0.3,
           "insecure_url": 0.2, "old": 0.15, "duplicate": 0.1, "expired_card": 0.1}
ISSUE_SEVERITY = {"breached": "critical", "reused": "high", "weak": "high", "fair": "medium",
                  "empty_password": "medium", "insecure_url": "low", "old": "low", "duplicate": "low",
                  "expired_card": "low"}


def kdf_params() -> dict:
    """scrypt cost for new / re-wrapped vaults. ~128 MB and ~0.4 s per unlock on a normal PC. Tests lower it with
    CYBERHUB_PV_KDF_N; existing vaults keep their own stored parameters and are upgraded on unlock."""
    try:
        n = int(os.environ.get("CYBERHUB_PV_KDF_N", str(2 ** 17)))
    except ValueError:
        n = 2 ** 17
    if not (2 ** 10 <= n <= 2 ** 20) or n & (n - 1):
        n = 2 ** 17
    return {"name": "scrypt", "n": n, "r": 8, "p": 1}


class PVError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    dt = dt or _now()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None


# ====================================================================== crypto helpers
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _scrypt(password: str, salt: bytes, kdf: dict) -> bytes:
    return hashlib.scrypt(normalize(password).encode("utf-8"), salt=salt, n=kdf["n"], r=kdf["r"], p=kdf["p"],
                          dklen=32, maxmem=1024 * 1024 * 1024)


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _seal(key: bytes, plain: bytes, aad: bytes) -> str:
    n = secrets.token_bytes(12)
    return _b64(n + AESGCM(key).encrypt(n, plain, aad))


def _unseal(key: bytes, sealed: str, aad: bytes) -> bytes:
    raw = base64.b64decode(sealed)
    if len(raw) < 12 + 16:
        raise InvalidTag()
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad)


def _aad_vk(uid: int, slot: str) -> bytes:
    return f"chpv-vk:{slot}:{uid}".encode()


def _aad_item(uid: int, item_id: str, kind: str) -> bytes:
    return f"chpv-item:{uid}:{item_id}:{kind}".encode()


def format_recovery(raw: bytes) -> str:
    s = base64.b32encode(raw).decode().rstrip("=")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def parse_recovery(text: str) -> bytes | None:
    s = re.sub(r"[\s-]", "", text or "").upper()
    if len(s) != 32 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in s):
        return None
    return base64.b32decode(s)


# ====================================================================== item helpers
def host_of(url: str) -> str:
    try:
        u = urlparse(url if "://" in url else "https://" + url)
        return (u.hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def insecure_url(url: str) -> bool:
    try:
        u = urlparse(url)
    except ValueError:
        return False
    if (u.scheme or "").lower() != "http":
        return False
    h = (u.hostname or "").lower()
    if h in ("localhost",) or h.endswith(".local") or h.endswith(".lan"):
        return False
    try:
        ip = ipaddress.ip_address(h)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return True


def card_brand(number: str) -> str | None:
    for brand, rx in (("Visa", r"^4"), ("Mastercard", r"^(5[1-5]|2[2-7])"), ("American Express", r"^3[47]"),
                      ("UnionPay", r"^62"), ("Discover", r"^6(011|5|4[4-9])"), ("JCB", r"^35"),
                      ("PayPak", r"^220[0-9]")):
        if re.match(rx, number):
            return brand
    return None


def luhn_ok(number: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(number)):
        n = int(d)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _s(v: Any, name: str, max_len: int, required: bool = False) -> str:
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise PVError(422, f"'{name}' must be text")
    v = v if name in ("password", "notes", "value") else v.strip()
    if required and not v.strip():
        raise PVError(422, f"'{name}' is required")
    if len(v) > max_len:
        raise PVError(422, f"'{name}' is too long (max {max_len})")
    return v


FIELDS = {
    "common": {"title", "notes", "folder", "favorite", "tags", "fields"},
    "login": {"username", "password", "urls", "totp"},
    "card": {"cardholder", "number", "exp_month", "exp_year", "cvv"},
    "identity": {"full_name", "email", "phone", "address", "company", "national_id"},
    "note": set(),
}
INTERNAL = {"password_history", "password_changed_at"}


def clean_payload(kind: str, data: dict, internal: bool = False) -> tuple[dict, list[str]]:
    """Validate one item. Returns (payload, warnings). internal=True also accepts history fields (imports of
    our own backups, updates)."""
    if kind not in TYPES:
        raise PVError(422, f"type must be one of: {', '.join(TYPES)}")
    if not isinstance(data, dict):
        raise PVError(422, "Item data must be an object")
    allowed = FIELDS["common"] | FIELDS[kind] | (INTERNAL if internal else set())
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PVError(422, f"Unknown field(s) for a {kind}: {', '.join(unknown)}")
    warnings: list[str] = []
    p: dict[str, Any] = {"title": _s(data.get("title"), "title", 200, required=True),
                         "notes": _s(data.get("notes"), "notes", 10000),
                         "folder": _s(data.get("folder"), "folder", 60),
                         "favorite": bool(data.get("favorite", False))}
    tags = data.get("tags") or []
    if not isinstance(tags, list) or len(tags) > 20:
        raise PVError(422, "tags must be a list of up to 20")
    p["tags"] = sorted({_s(t, "tag", 40) for t in tags if isinstance(t, str) and t.strip()})
    flds = data.get("fields") or []
    if not isinstance(flds, list) or len(flds) > 50:
        raise PVError(422, "fields must be a list of up to 50")
    p["fields"] = []
    for f in flds:
        if not isinstance(f, dict) or set(f) - {"name", "value", "hidden"}:
            raise PVError(422, "Each custom field is {name, value, hidden}")
        p["fields"].append({"name": _s(f.get("name"), "name", 60, required=True),
                            "value": _s(f.get("value"), "value", 2000), "hidden": bool(f.get("hidden", False))})
    if kind == "login":
        p["username"] = _s(data.get("username"), "username", 500)
        p["password"] = normalize(_s(data.get("password"), "password", 1024))
        urls = data.get("urls") or []
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list) or len(urls) > 20:
            raise PVError(422, "urls must be a list of up to 20")
        clean = []
        for u in urls:
            u = _s(u, "url", 2048)
            if not u:
                continue
            if "://" not in u and not u.startswith(("android:", "ios:")):
                u = "https://" + u
            if not host_of(u) and "://" in u and not u.startswith(("android:", "ios:")):
                raise PVError(422, f"Not a web address: {u[:80]}")
            clean.append(u)
        p["urls"] = clean
        p["totp"] = _s(data.get("totp"), "totp", 2048)
        if p["totp"]:
            try:
                tools.parse_totp(p["totp"])
            except ToolError as e:
                raise PVError(e.status, e.message) from e
        if any(insecure_url(u) for u in clean):
            warnings.append("This site address uses http:// - the password would be sent unencrypted.")
    elif kind == "card":
        p["cardholder"] = _s(data.get("cardholder"), "cardholder", 100)
        num = re.sub(r"[\s-]", "", _s(data.get("number"), "number", 40))
        if num and (not num.isdigit() or not 12 <= len(num) <= 19):
            raise PVError(422, "Card number must be 12-19 digits")
        if num and not luhn_ok(num):
            warnings.append("The card number fails the Luhn check - is it typed correctly?")
        p["number"] = num
        m, y = data.get("exp_month"), data.get("exp_year")
        if m in ("", None):
            m = None
        elif not (isinstance(m, int) and not isinstance(m, bool) and 1 <= m <= 12):
            raise PVError(422, "exp_month must be 1-12")
        if y in ("", None):
            y = None
        elif not (isinstance(y, int) and not isinstance(y, bool)):
            raise PVError(422, "exp_year must be a year")
        elif y < 100:
            y += 2000
        if y is not None and not 2000 <= y <= 2100:
            raise PVError(422, "exp_year must be 2000-2100")
        p["exp_month"], p["exp_year"] = m, y
        cvv = _s(data.get("cvv"), "cvv", 4)
        if cvv and not (cvv.isdigit() and len(cvv) in (3, 4)):
            raise PVError(422, "CVV must be 3 or 4 digits")
        p["cvv"] = cvv
    elif kind == "identity":
        for k, n in (("full_name", 200), ("email", 320), ("phone", 40), ("address", 500), ("company", 200),
                     ("national_id", 40)):
            p[k] = _s(data.get(k), k, n)
    if internal:
        hist = data.get("password_history") or []
        if isinstance(hist, list):
            p["password_history"] = [{"password": _s(h.get("password"), "password", 1024),
                                      "changed_at": h.get("changed_at") if isinstance(h.get("changed_at"), str) else None}
                                     for h in hist[:HISTORY_KEEP] if isinstance(h, dict)]
        if isinstance(data.get("password_changed_at"), str) and _parse(data["password_changed_at"]):
            p["password_changed_at"] = data["password_changed_at"]
    return p, warnings


def card_expired(p: dict, now: datetime) -> bool:
    if not p.get("exp_year") or not p.get("exp_month"):
        return False
    return (p["exp_year"], p["exp_month"]) < (now.year, now.month)


# ====================================================================== in-memory unlocked vault
@dataclass
class _Open:
    user_id: int
    session_id: int
    key: bytearray
    audit_key: bytes
    opened: float
    last_used: float
    items: dict[str, dict] = field(default_factory=dict)
    strength: dict[str, int] = field(default_factory=dict)          # password fp -> zxcvbn score
    alive: bool = True

    def vk(self) -> bytes:
        if not self.alive:
            raise PVError(423, "Password vault is locked")
        return bytes(self.key)

    def fp(self, password: str) -> str:
        return hmac.new(self.audit_key, normalize(password).encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def wipe(self) -> None:
        self.alive = False
        for i in range(len(self.key)):                     # best effort: Python may still hold copies
            self.key[i] = 0
        self.items.clear()
        self.strength.clear()


# ====================================================================== service
class PasswordVaultService:
    def __init__(self, db: Database, settings, activity, accounts=None, vault=None,
                 clipboard: ClipboardManager | None = None, breach: BreachChecker | None = None):
        self.db, self.settings, self.activity, self.vault = db, settings, activity, vault
        self.clipboard = clipboard or ClipboardManager()
        self.breach = breach or BreachChecker()
        self._lock = threading.RLock()
        self._opens: dict[int, _Open] = {}                # by Cyber Hub session id
        self._jobs: dict[int, dict] = {}                  # breach checks by user id
        if accounts is not None:
            accounts.listeners.append(self._on_account_event)

    # ------------------------------------------------------------------ basics
    def _vault_row(self, uid: int) -> dict | None:
        return self.db.fetchone("SELECT * FROM pv_vaults WHERE user_id=?", (uid,))

    def _require_vault(self, uid: int) -> dict:
        v = self._vault_row(uid)
        if not v:
            raise PVError(404, "No password vault yet - set one up first")
        return v

    def _event(self, uid: int | None, kind: str, severity: str, title: str, detail: str | None = None,
               item_id: str | None = None, data: Any = None, activity: bool = True) -> None:
        self.db.execute(
            "INSERT INTO pv_events(user_id, kind, severity, title, detail, item_id, data, acknowledged) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (uid, kind, severity, title, detail, item_id, json.dumps(data) if data is not None else None,
             0 if SEVERITIES.index(severity) >= 2 else 1))
        if activity:
            self.activity.record("passwords", title, detail, severity=severity, source="passwords")

    def _pepper(self, required: bool) -> bytes | None:
        if self.vault is None or not getattr(self.vault, "available", False):
            if required:
                raise PVError(503, "This vault is tied to this PC's Cyber Hub key (vault.key), which can't be "
                                   "opened right now - unlock with your recovery key instead")
            return None
        return self.vault.derive_subkey(PEPPER_LABEL)

    def _kek(self, password: str, salt: bytes, kdf: dict, bound: bool) -> bytes:
        pepper = self._pepper(required=True) if bound else None
        return _hkdf(_scrypt(password, salt, kdf), pepper, b"cyberhub-pv-kek-v1")

    @staticmethod
    def _recovery_kek(raw: bytes, salt: bytes) -> bytes:
        return _hkdf(raw, salt, b"cyberhub-pv-recovery-v1")

    def _wrap_master(self, uid: int, vk: bytes, password: str) -> dict:
        """New salt + current KDF cost, device-bound whenever the device key is available."""
        kdf, salt = kdf_params(), secrets.token_bytes(16)
        pepper = self._pepper(required=False)
        kek = _hkdf(_scrypt(password, salt, kdf), pepper, b"cyberhub-pv-kek-v1")
        return {"kdf": json.dumps(kdf), "salt": _b64(salt), "wrapped_pw": _seal(kek, vk, _aad_vk(uid, "pw")),
                "device_bound": int(pepper is not None)}

    def _wrap_recovery(self, uid: int, vk: bytes) -> tuple[str, dict]:
        raw, salt = secrets.token_bytes(20), secrets.token_bytes(16)
        return format_recovery(raw), {"recovery_salt": _b64(salt),
                                      "wrapped_recovery": _seal(self._recovery_kek(raw, salt), vk,
                                                                _aad_vk(uid, "rk"))}

    def _check_master(self, password: str, user: dict, hint: str | None) -> None:
        if not isinstance(password, str) or len(password) < 10:
            raise PVError(422, "The master password needs at least 10 characters (a 4-5 word passphrase is ideal)")
        if len(password) > 256:
            raise PVError(422, "The master password is too long (max 256)")
        s = tools.strength(password, [user.get("username"), user.get("display_name"), user.get("email")])
        if s["score"] < 3:
            why = s["warning"] or (s["suggestions"][0] if s["suggestions"] else "")
            raise PVError(422, f"The master password is too easy to guess ({s['label']}). {why} "
                               "Try the passphrase generator.".replace("  ", " "))
        if account_pw.verify_secret(password, user.get("password_hash")):
            raise PVError(422, "Use a master password that is different from your Cyber Hub sign-in password")
        if hint and normalize(password).lower() in normalize(hint).lower():
            raise PVError(422, "The hint must not contain the master password")

    # ------------------------------------------------------------------ lock / unlock bookkeeping
    def _get_open(self, session_id: int, uid: int, touch: bool = True) -> _Open | None:
        self.sweep(only_session=session_id)
        with self._lock:
            o = self._opens.get(session_id)
            if o and o.user_id != uid:                       # session ids are never reused, but be strict
                return None
            if o and touch:
                o.last_used = time.monotonic()
            return o

    def _require_open(self, cu) -> _Open:
        uid = cu.user["id"]
        o = self._get_open(cu.session["id"], uid)
        if o is None:
            if not self._vault_row(uid):
                raise PVError(404, "No password vault yet - set one up first")
            raise PVError(423, "Password vault is locked - unlock it with your master password")
        return o

    def _close(self, session_id: int) -> bool:
        with self._lock:
            o = self._opens.pop(session_id, None)
        if o:
            o.wipe()
            return True
        return False

    def _close_user(self, uid: int, keep_session: int | None = None) -> int:
        with self._lock:
            ids = [sid for sid, o in self._opens.items() if o.user_id == uid and sid != keep_session]
        return sum(self._close(s) for s in ids)

    def _on_account_event(self, event: str, session_id: int | None = None, user_id: int | None = None) -> None:
        if event == "lock" and session_id is not None:
            if self.settings.get("pv_lock_with_session"):
                self._close(session_id)
        elif event == "logout" and session_id is not None:
            self._close(session_id)
        elif event == "revoke_others" and user_id is not None:
            self._close_user(user_id, keep_session=session_id)
        elif event == "revoke_user" and user_id is not None:
            self._close_user(user_id)

    def sweep(self, only_session: int | None = None) -> int:
        """Lock vaults that sat unused too long or whose Cyber Hub session is locked / gone."""
        idle_min = self.settings.get("pv_auto_lock_minutes")
        with_session = self.settings.get("pv_lock_with_session")
        with self._lock:
            opens = [o for o in self._opens.values() if only_session is None or o.session_id == only_session]
        closed = 0
        now_m, now_s = time.monotonic(), _iso()
        for o in opens:
            why = None
            if idle_min and now_m - o.last_used > idle_min * 60:
                why = "idle"
            else:
                s = self.db.fetchone("SELECT revoked, is_locked, expires_at FROM sessions WHERE id=?", (o.session_id,))
                if not s or s["revoked"] or s["expires_at"] <= now_s:
                    why = "session ended"
                elif s["is_locked"] and with_session:
                    why = "app locked"
            if why and self._close(o.session_id):
                closed += 1
                log.info("Password vault locked (%s)", why)
        return closed

    def _fail(self, uid: int, v: dict, how: str) -> None:
        n = v["failed_unlocks"] + 1
        until = None
        if n >= FREE_TRIES:
            wait = min(30 * 2 ** (n - FREE_TRIES), MAX_LOCKOUT)
            until = _iso(_now() + timedelta(seconds=wait))
        self.db.execute("UPDATE pv_vaults SET failed_unlocks=?, locked_until=? WHERE user_id=?", (n, until, uid))
        if until:
            self._event(uid, "lockout", "high", "Password vault: too many wrong attempts",
                        f"{n} wrong {how} attempts in a row - next try allowed after {until}")
        else:
            self._event(uid, "unlock_failed", "medium" if n >= 3 else "low", "Password vault: wrong " + how,
                        f"attempt {n}")

    def _check_lockout(self, v: dict) -> None:
        until = _parse(v["locked_until"])
        if until and until > _now():
            secs = int((until - _now()).total_seconds()) + 1
            raise PVError(429, f"Too many wrong attempts - try again in {secs} s", retry_after=secs)

    def _verify_master(self, uid: int, v: dict, password: str, count_failure: bool = True) -> bytes:
        """Returns the vault key or raises 401 (and counts the failure)."""
        self._check_lockout(v)
        kdf = json.loads(v["kdf"])
        try:
            kek = self._kek(password or "", base64.b64decode(v["salt"]), kdf, bool(v["device_bound"]))
            vk = _unseal(kek, v["wrapped_pw"], _aad_vk(uid, "pw"))
        except InvalidTag:
            if count_failure:
                self._fail(uid, v, "master password")
            raise PVError(401, "Wrong master password")
        return vk

    def _open_session(self, cu, vk: bytes) -> _Open:
        uid = cu.user["id"]
        o = _Open(uid, cu.session["id"], bytearray(vk), _hkdf(vk, None, b"cyberhub-pv-audit-v1"),
                  time.monotonic(), time.monotonic())
        for r in self.db.fetchall("SELECT * FROM pv_items WHERE user_id=?", (uid,)):
            o.items[r["id"]] = self._decrypt_row(uid, vk, r)
        with self._lock:
            old = self._opens.pop(cu.session["id"], None)
            self._opens[cu.session["id"]] = o
        if old:
            old.wipe()
        return o

    def _decrypt_row(self, uid: int, vk: bytes, r: dict) -> dict:
        base = {"id": r["id"], "type": r["type"], "rev": r["rev"], "created_at": r["created_at"],
                "updated_at": r["updated_at"], "deleted_at": r["deleted_at"], "payload": None, "damaged": False}
        try:
            base["payload"] = json.loads(_unseal(vk, r["blob"], _aad_item(uid, r["id"], r["type"])))
        except (InvalidTag, ValueError, TypeError):
            base["damaged"] = True                          # tampered / corrupted row: shown, never used
            log.warning("Password vault item %s failed its integrity check", r["id"])
        return base

    # ------------------------------------------------------------------ status / setup / unlock
    def status(self, cu) -> dict:
        uid = cu.user["id"]
        v = self._vault_row(uid)
        o = self._get_open(cu.session["id"], uid, touch=False) if v else None
        out: dict[str, Any] = {
            "exists": bool(v), "unlocked": bool(o), "auto_lock_minutes": self.settings.get("pv_auto_lock_minutes"),
            "lock_with_session": self.settings.get("pv_lock_with_session"),
            "breach_check": self.settings.get("pv_breach_check"), "clipboard": self.clipboard.status(),
            "device_key_available": bool(self.vault is not None and getattr(self.vault, "available", False)),
            "strength_engine": "zxcvbn" if tools._zxcvbn is not None else "basic",
        }
        if not v:
            return out
        counts = {t: 0 for t in TYPES}
        for r in self.db.fetchall("SELECT type, COUNT(*) AS n FROM pv_items WHERE user_id=? AND deleted_at IS NULL "
                                  "GROUP BY type", (uid,)):
            counts[r["type"]] = r["n"]
        trash = self.db.fetchone("SELECT COUNT(*) AS n FROM pv_items WHERE user_id=? AND deleted_at IS NOT NULL",
                                 (uid,))["n"]
        until = _parse(v["locked_until"])
        idle = None
        if o and out["auto_lock_minutes"]:
            idle = max(0, int(out["auto_lock_minutes"] * 60 - (time.monotonic() - o.last_used)))
        out.update(
            device_bound=bool(v["device_bound"]), hint_set=bool(v["hint"]), counts=counts,
            total=sum(counts.values()), trash=trash, kdf=json.loads(v["kdf"]), created_at=v["created_at"],
            master_changed_at=v["master_changed_at"], recovery_created_at=v["recovery_created_at"],
            last_unlock_at=v["last_unlock_at"], failed_unlocks=v["failed_unlocks"],
            locked_until=v["locked_until"] if until and until > _now() else None,
            auto_lock_in_seconds=idle, audit=json.loads(v["last_audit"]) if v["last_audit"] else None,
            breach_job=self._jobs.get(uid, {}).get("public"),
            unread_alerts=self.db.fetchone("SELECT COUNT(*) AS n FROM pv_events WHERE user_id=? AND acknowledged=0",
                                           (uid,))["n"])
        if v["device_bound"] and not out["device_key_available"]:
            out["warning"] = ("This PC's Cyber Hub key (vault.key) can't be opened, so the master password alone "
                              "can't unlock the vault - use your recovery key")
        return out

    def setup(self, cu, master_password: str, hint: str | None = None) -> dict:
        uid, user = cu.user["id"], cu.user
        if self._vault_row(uid):
            raise PVError(409, "You already have a password vault")
        hint = (hint or "").strip()[:200] or None
        self._check_master(master_password, user, hint)
        vk = secrets.token_bytes(32)
        m = self._wrap_master(uid, vk, master_password)
        key, rk = self._wrap_recovery(uid, vk)
        now = _iso()
        self.db.execute(
            "INSERT INTO pv_vaults(user_id, kdf, salt, wrapped_pw, recovery_salt, wrapped_recovery, device_bound, "
            "hint, created_at, master_changed_at, recovery_created_at, last_unlock_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, m["kdf"], m["salt"], m["wrapped_pw"], rk["recovery_salt"], rk["wrapped_recovery"],
             m["device_bound"], hint, now, now, now, now))
        self._open_session(cu, vk)
        self._event(uid, "vault_created", "info", "Password vault created",
                    "device-bound" if m["device_bound"] else "not device-bound (device key unavailable)")
        return {"recovery_key": key, "status": self.status(cu),
                "message": "Write the recovery key down and keep it offline - it is the only way back in if you "
                           "forget the master password. It is shown once."}

    def unlock(self, cu, master_password: str | None = None, recovery_key: str | None = None,
               new_master_password: str | None = None) -> dict:
        uid = cu.user["id"]
        v = self._require_vault(uid)
        self._check_lockout(v)
        new_key = None
        if recovery_key:
            if not new_master_password:
                raise PVError(422, "Choose a new master password when unlocking with the recovery key")
            self._check_master(new_master_password, cu.user, v["hint"])
            raw = parse_recovery(recovery_key)
            try:
                if raw is None:
                    raise InvalidTag()
                vk = _unseal(self._recovery_kek(raw, base64.b64decode(v["recovery_salt"])), v["wrapped_recovery"],
                             _aad_vk(uid, "rk"))
            except InvalidTag:
                self._fail(uid, v, "recovery key")
                raise PVError(401, "Wrong recovery key")
            m = self._wrap_master(uid, vk, new_master_password)
            new_key, rk = self._wrap_recovery(uid, vk)                       # the used key is retired
            now = _iso()
            self.db.execute("UPDATE pv_vaults SET kdf=?, salt=?, wrapped_pw=?, device_bound=?, recovery_salt=?, "
                            "wrapped_recovery=?, master_changed_at=?, recovery_created_at=? WHERE user_id=?",
                            (m["kdf"], m["salt"], m["wrapped_pw"], m["device_bound"], rk["recovery_salt"],
                             rk["wrapped_recovery"], now, now, uid))
            self._close_user(uid)
            self._event(uid, "recovery_used", "medium", "Password vault opened with the recovery key",
                        "new master password set; a new recovery key was issued")
        else:
            if not master_password:
                raise PVError(422, "Enter your master password")
            vk = self._verify_master(uid, v, master_password)
            kdf = json.loads(v["kdf"])
            cur = kdf_params()
            want_bind = not v["device_bound"] and self._pepper(required=False) is not None
            if kdf["n"] < cur["n"] or want_bind:                              # upgrade cost / bind to this PC
                m = self._wrap_master(uid, vk, master_password)
                self.db.execute("UPDATE pv_vaults SET kdf=?, salt=?, wrapped_pw=?, device_bound=? WHERE user_id=?",
                                (m["kdf"], m["salt"], m["wrapped_pw"], m["device_bound"], uid))
                self._event(uid, "kdf_upgraded", "info", "Password vault protection upgraded",
                            f"scrypt N={json.loads(m['kdf'])['n']}, device-bound={bool(m['device_bound'])}",
                            activity=False)
        self.db.execute("UPDATE pv_vaults SET failed_unlocks=0, locked_until=NULL, last_unlock_at=? WHERE user_id=?",
                        (_iso(), uid))
        o = self._open_session(cu, vk)
        self._event(uid, "unlocked", "info", "Password vault unlocked", None, activity=False)
        out = {"unlocked": True, "status": self.status(cu)}
        if new_key:
            out["recovery_key"] = new_key
        damaged = sum(1 for i in list(o.items.values()) if i["damaged"])
        if damaged:
            self._event(uid, "damaged_items", "high", "Password vault: damaged items found",
                        f"{damaged} item(s) failed their integrity check and can't be opened")
            out["damaged_items"] = damaged
        if self.settings.get("pv_breach_check") == "auto":
            last = (json.loads(v["last_audit"]) if v["last_audit"] else {}).get("breach_checked_at")
            if not last or (_parse(last) or _now()) < _now() - timedelta(days=7):
                self._start_breach_job(o, None, quiet=True)
        return out

    def lock(self, cu) -> dict:
        self._close(cu.session["id"])
        return {"unlocked": False}

    def hint(self, cu) -> dict:
        return {"hint": self._require_vault(cu.user["id"])["hint"]}

    def change_master(self, cu, current: str, new: str, hint: str | None = None, keep_hint: bool = True) -> dict:
        uid = cu.user["id"]
        v = self._require_vault(uid)
        vk = self._verify_master(uid, v, current)
        if normalize(current) == normalize(new):
            raise PVError(422, "The new master password must be different")
        new_hint = v["hint"] if keep_hint and hint is None else ((hint or "").strip()[:200] or None)
        self._check_master(new, cu.user, new_hint)
        m = self._wrap_master(uid, vk, new)
        self.db.execute("UPDATE pv_vaults SET kdf=?, salt=?, wrapped_pw=?, device_bound=?, hint=?, "
                        "master_changed_at=?, failed_unlocks=0, locked_until=NULL WHERE user_id=?",
                        (m["kdf"], m["salt"], m["wrapped_pw"], m["device_bound"], new_hint, _iso(), uid))
        closed = self._close_user(uid, keep_session=cu.session["id"])
        if self._get_open(cu.session["id"], uid, touch=False) is None:
            self._open_session(cu, vk)
        self._event(uid, "master_changed", "low", "Password vault master password changed",
                    f"{closed} other open window(s) locked")
        return {"changed": True, "status": self.status(cu)}

    def new_recovery_key(self, cu, master_password: str) -> dict:
        uid = cu.user["id"]
        v = self._require_vault(uid)
        vk = self._verify_master(uid, v, master_password)
        key, rk = self._wrap_recovery(uid, vk)
        self.db.execute("UPDATE pv_vaults SET recovery_salt=?, wrapped_recovery=?, recovery_created_at=? "
                        "WHERE user_id=?", (rk["recovery_salt"], rk["wrapped_recovery"], _iso(), uid))
        self._event(uid, "recovery_regenerated", "low", "New password vault recovery key created",
                    "the previous recovery key no longer works")
        return {"recovery_key": key}

    def delete_vault(self, cu, account_password: str, confirm: bool) -> dict:
        uid = cu.user["id"]
        self._require_vault(uid)
        if not account_pw.verify_secret(account_password or "", cu.user.get("password_hash")):
            raise PVError(401, "Your Cyber Hub sign-in password is incorrect")
        if not confirm:
            raise PVError(428, "This permanently destroys every item in your password vault. Export a backup "
                               "first, then send again with confirm=true.")
        n = self.db.fetchone("SELECT COUNT(*) AS n FROM pv_items WHERE user_id=?", (uid,))["n"]
        self._close_user(uid)
        self._jobs.pop(uid, None)
        with self.db.tx() as c:
            c.execute("DELETE FROM pv_items WHERE user_id=?", (uid,))
            c.execute("DELETE FROM pv_vaults WHERE user_id=?", (uid,))
            c.execute("DELETE FROM pv_scores WHERE user_id=?", (uid,))
        self._event(uid, "vault_deleted", "high", "Password vault deleted", f"{n} item(s) destroyed")
        return {"deleted": True, "items": n}

    # ------------------------------------------------------------------ items: storage
    def _store(self, o: _Open, item_id: str, kind: str, payload: dict, insert: bool,
               created: str | None = None) -> dict:
        blob = _seal(o.vk(), json.dumps(payload, separators=(",", ":")).encode(), _aad_item(o.user_id, item_id, kind))
        if len(blob) > MAX_BLOB:
            raise PVError(413, "This item is too large")
        now = _iso()
        if insert:
            self.db.execute("INSERT INTO pv_items(id, user_id, type, blob, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                            (item_id, o.user_id, kind, blob, created or now, now))
        else:
            self.db.execute("UPDATE pv_items SET blob=?, rev=rev+1, updated_at=? WHERE id=? AND user_id=?",
                            (blob, now, item_id, o.user_id))
        r = self.db.fetchone("SELECT * FROM pv_items WHERE id=?", (item_id,))
        rec = {"id": item_id, "type": kind, "rev": r["rev"], "created_at": r["created_at"],
               "updated_at": r["updated_at"], "deleted_at": r["deleted_at"], "payload": payload, "damaged": False}
        with self._lock:
            o.items[item_id] = rec
        return rec

    def _item(self, o: _Open, item_id: str, allow_trash: bool = True) -> dict:
        it = o.items.get(item_id)
        if not it:
            raise PVError(404, "Item not found")
        if it["damaged"]:
            raise PVError(409, "This item failed its integrity check (damaged or tampered) - it can only be deleted")
        if it["deleted_at"] and not allow_trash:
            raise PVError(409, "This item is in the trash - restore it first")
        return it

    def _count_live(self, o: _Open) -> int:
        return sum(1 for i in list(o.items.values()) if not i["deleted_at"])

    # ------------------------------------------------------------------ items: analysis
    def _strength(self, o: _Open, fp: str, password: str, inputs: list[str]) -> int:
        s = o.strength.get(fp)
        if s is None:
            s = tools.strength(password, inputs)["score"]
            o.strength[fp] = s
        return s

    def _analyze(self, o: _Open) -> dict[str, dict]:
        """Per live item: fp, strength, reused_with, breach, issues[]."""
        now = _now()
        old_days = self.settings.get("pv_old_password_days")
        live = [i for i in list(o.items.values()) if not i["deleted_at"] and not i["damaged"]]
        breach = {r["item_id"]: r for r in self.db.fetchall(
            "SELECT b.item_id, b.fp, b.count, b.checked_at FROM pv_breach b JOIN pv_items i ON i.id=b.item_id "
            "WHERE i.user_id=?", (o.user_id,))}
        by_fp: dict[str, list[str]] = {}
        by_account: dict[tuple, list[str]] = {}
        out: dict[str, dict] = {}
        for it in live:
            p = it["payload"]
            info: dict[str, Any] = {"issues": [], "fp": None, "strength": None, "breach": None, "reused_with": []}
            out[it["id"]] = info
            if it["type"] == "login":
                pw = p.get("password") or ""
                hosts = sorted({host_of(u) for u in p.get("urls") or [] if host_of(u)})
                if pw:
                    fp = o.fp(pw)
                    info["fp"] = fp
                    by_fp.setdefault(fp, []).append(it["id"])
                    info["strength"] = self._strength(o, fp, pw, [p.get("username"), p.get("title")] + hosts)
                    b = breach.get(it["id"])
                    if b and b["fp"] == fp:
                        info["breach"] = {"count": b["count"], "checked_at": b["checked_at"]}
                    changed = _parse(p.get("password_changed_at")) or _parse(it["created_at"])
                    if changed and (now - changed).days > old_days:
                        info["issues"].append(("old", f"not changed for {(now - changed).days} days"))
                elif p.get("username") or p.get("urls"):
                    info["issues"].append(("empty_password", "no password saved"))
                if any(insecure_url(u) for u in p.get("urls") or []):
                    info["issues"].append(("insecure_url", "site address uses http://"))
                if p.get("username") and hosts:
                    by_account.setdefault((p["username"].lower(), hosts[0]), []).append(it["id"])
            elif it["type"] == "card" and card_expired(p, now):
                info["issues"].append(("expired_card", f"expired {p['exp_month']:02d}/{p['exp_year']}"))
        for fp, ids in by_fp.items():
            for i in ids:
                out[i]["reused_with"] = [x for x in ids if x != i]
                if len(ids) > 1:
                    out[i]["issues"].append(("reused", f"same password as {len(ids) - 1} other item(s)"))
        for ids in by_account.values():
            if len(ids) > 1:
                for i in ids:
                    out[i]["issues"].append(("duplicate", f"{len(ids) - 1} other item(s) for the same account"))
        for info in out.values():
            if info["breach"] and info["breach"]["count"] > 0:
                info["issues"].append(("breached", f"seen {info['breach']['count']:,} times in data breaches"))
            if info["strength"] is not None and info["strength"] <= 1:
                info["issues"].append(("weak", tools.LABELS[info["strength"]]))
            elif info["strength"] == 2:
                info["issues"].append(("fair", "Fair - could be guessed by a determined attacker"))
            info["issues"].sort(key=lambda x: -WEIGHTS[x[0]])
        return out

    def _public(self, it: dict, info: dict | None) -> dict:
        base = {"id": it["id"], "type": it["type"], "created_at": it["created_at"], "updated_at": it["updated_at"],
                "deleted_at": it["deleted_at"], "damaged": it["damaged"], "rev": it["rev"]}
        if it["damaged"]:
            return base | {"title": "(damaged item)"}
        p = it["payload"]
        base.update(title=p["title"], folder=p.get("folder") or "", favorite=p.get("favorite", False),
                    tags=p.get("tags") or [])
        if it["type"] == "login":
            base.update(username=p.get("username", ""), urls=p.get("urls") or [],
                        host=host_of(p["urls"][0]) if p.get("urls") else "", has_password=bool(p.get("password")),
                        has_totp=bool(p.get("totp")), password_changed_at=p.get("password_changed_at"))
        elif it["type"] == "card":
            num = p.get("number", "")
            base.update(cardholder=p.get("cardholder", ""), brand=card_brand(num), last4=num[-4:] if num else "",
                        exp_month=p.get("exp_month"), exp_year=p.get("exp_year"),
                        expired=card_expired(p, _now()))
        elif it["type"] == "identity":
            base.update(full_name=p.get("full_name", ""), email=p.get("email", ""))
        if info is not None:
            base.update(strength=info["strength"],
                        strength_label=tools.LABELS[info["strength"]] if info["strength"] is not None else None,
                        reused=len(info["reused_with"]) if info["fp"] else 0,
                        breached=info["breach"]["count"] if info["breach"] else None,
                        issues=[{"kind": k, "severity": ISSUE_SEVERITY[k], "detail": d} for k, d in info["issues"]])
        return base

    def _warnings(self, o: _Open, item_id: str) -> list[str]:
        info = self._analyze(o).get(item_id) or {"issues": []}
        msgs = {"reused": "This password is also used for {d}.", "weak": "Weak password ({d}).",
                "fair": "This password is only Fair - consider a generated one.",
                "breached": "This password has been {d}."}
        return [msgs[k].format(d=d.replace("same password as ", "")) for k, d in info["issues"] if k in msgs]

    # ------------------------------------------------------------------ items: API
    def list_items(self, cu, q: str | None = None, kind: str | None = None, folder: str | None = None,
                   favorite: bool | None = None, trash: bool = False, issue: str | None = None) -> dict:
        o = self._require_open(cu)
        info = self._analyze(o)
        items = []
        qq = (q or "").strip().lower()
        for it in list(o.items.values()):
            if bool(it["deleted_at"]) != trash:
                continue
            if kind and it["type"] != kind:
                continue
            pub = self._public(it, info.get(it["id"]))
            if it["damaged"]:
                if not (qq or folder or favorite or issue):
                    items.append(pub)
                continue
            p = it["payload"]
            if folder is not None and (p.get("folder") or "") != folder:
                continue
            if favorite is not None and bool(p.get("favorite")) != favorite:
                continue
            if issue and not any(x["kind"] == issue for x in pub.get("issues") or []):
                continue
            if qq:
                hay = " ".join([p.get("title", ""), p.get("username", ""), " ".join(p.get("urls") or []),
                                p.get("notes", ""), p.get("folder", ""), " ".join(p.get("tags") or []),
                                p.get("cardholder", ""), p.get("full_name", ""), p.get("email", "")]).lower()
                if qq not in hay:
                    continue
            items.append(pub)
        items.sort(key=lambda x: (not x.get("favorite", False), x["title"].lower()))
        return {"total": len(items), "items": items}

    def create_item(self, cu, kind: str, data: dict) -> dict:
        o = self._require_open(cu)
        if self._count_live(o) >= MAX_ITEMS:
            raise PVError(413, f"The vault holds at most {MAX_ITEMS} items")
        payload, warnings = clean_payload(kind, data)
        if kind == "login":
            payload["password_history"] = []
            payload["password_changed_at"] = _iso() if payload.get("password") else None
        item_id = secrets.token_hex(16)
        self._store(o, item_id, kind, payload, insert=True)
        warnings += self._warnings(o, item_id)
        self._auto_breach(o, item_id)
        return {"item": self.get_item(cu, item_id)["item"], "warnings": warnings}

    def get_item(self, cu, item_id: str, reveal: bool = False) -> dict:
        o = self._require_open(cu)
        it = o.items.get(item_id)
        if not it:
            raise PVError(404, "Item not found")
        pub = self._public(it, self._analyze(o).get(item_id))
        if it["damaged"]:
            return {"item": pub}
        p = dict(it["payload"])
        p.pop("password_history", None)
        if not reveal:
            for k in ("password", "cvv", "national_id"):
                if p.get(k):
                    p[k] = MASK
            if p.get("number"):
                p["number"] = "•••• " + p["number"][-4:]
            if p.get("totp"):
                p["totp"] = MASK
            p["fields"] = [dict(f, value=MASK) if f["hidden"] and f["value"] else f for f in p.get("fields") or []]
        pub["data"] = p
        pub["revealed"] = reveal
        pub["history_count"] = len(it["payload"].get("password_history") or [])
        return {"item": pub}

    def update_item(self, cu, item_id: str, data: dict) -> dict:
        o = self._require_open(cu)
        it = self._item(o, item_id, allow_trash=False)
        old = it["payload"]
        if "type" in data:
            raise PVError(422, "An item's type can't be changed")
        merged = {k: v for k, v in old.items() if k not in INTERNAL}
        for k, v in data.items():
            if k in INTERNAL:
                raise PVError(422, f"'{k}' is managed by Cyber Hub")
            if v == MASK or (k == "number" and isinstance(v, str) and v.startswith("•")):
                continue                                          # a masked value sent back = unchanged
            merged[k] = v
        if isinstance(data.get("fields"), list):                  # masked hidden fields keep their old value
            old_vals = {f["name"]: f["value"] for f in old.get("fields") or []}
            merged["fields"] = [dict(f, value=old_vals.get(f.get("name"), "")) if isinstance(f, dict)
                                and f.get("value") == MASK else f for f in data["fields"]]
        payload, warnings = clean_payload(it["type"], merged)
        if it["type"] == "login":
            hist = list(old.get("password_history") or [])
            payload["password_changed_at"] = old.get("password_changed_at")
            if normalize(old.get("password") or "") != payload["password"]:
                if old.get("password"):
                    hist.insert(0, {"password": old["password"], "changed_at": old.get("password_changed_at"),
                                    "replaced_at": _iso()})
                payload["password_changed_at"] = _iso() if payload["password"] else None
                self.db.execute("DELETE FROM pv_breach WHERE item_id=?", (item_id,))
            payload["password_history"] = hist[:HISTORY_KEEP]
        self._store(o, item_id, it["type"], payload, insert=False)
        warnings += self._warnings(o, item_id)
        if it["type"] == "login" and normalize(old.get("password") or "") != payload["password"]:
            self._auto_breach(o, item_id)
        return {"item": self.get_item(cu, item_id)["item"], "warnings": warnings}

    def delete_item(self, cu, item_id: str, permanent: bool = False) -> dict:
        o = self._require_open(cu)
        it = o.items.get(item_id)
        if not it:
            raise PVError(404, "Item not found")
        if permanent or it["damaged"]:
            self.db.execute("DELETE FROM pv_items WHERE id=? AND user_id=?", (item_id, o.user_id))
            with self._lock:
                o.items.pop(item_id, None)
            return {"deleted": True, "permanent": True}
        now = _iso()
        self.db.execute("UPDATE pv_items SET deleted_at=? WHERE id=? AND user_id=?", (now, item_id, o.user_id))
        it["deleted_at"] = now
        return {"deleted": True, "permanent": False, "trash_days": self.settings.get("pv_trash_days")}

    def restore_item(self, cu, item_id: str) -> dict:
        o = self._require_open(cu)
        it = self._item(o, item_id)
        if not it["deleted_at"]:
            raise PVError(409, "This item is not in the trash")
        if self._count_live(o) >= MAX_ITEMS:
            raise PVError(413, f"The vault holds at most {MAX_ITEMS} items")
        self.db.execute("UPDATE pv_items SET deleted_at=NULL WHERE id=? AND user_id=?", (item_id, o.user_id))
        it["deleted_at"] = None
        return self.get_item(cu, item_id)

    def empty_trash(self, cu) -> dict:
        o = self._require_open(cu)
        n = self.db.execute("DELETE FROM pv_items WHERE user_id=? AND deleted_at IS NOT NULL", (o.user_id,)).rowcount
        with self._lock:
            for k in [k for k, v in list(o.items.items()) if v["deleted_at"]]:
                o.items.pop(k, None)
        return {"deleted": n}

    def purge_trash(self) -> int:
        """Background: items in the trash longer than pv_trash_days are deleted (no key needed - whole rows)."""
        cutoff = _iso(_now() - timedelta(days=self.settings.get("pv_trash_days")))
        ids = [r["id"] for r in self.db.fetchall("SELECT id FROM pv_items WHERE deleted_at IS NOT NULL AND "
                                                 "deleted_at < ?", (cutoff,))]
        if not ids:
            return 0
        self.db.execute("DELETE FROM pv_items WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
        with self._lock:
            for o in self._opens.values():
                for i in ids:
                    o.items.pop(i, None)
        return len(ids)

    def history(self, cu, item_id: str) -> dict:
        o = self._require_open(cu)
        it = self._item(o, item_id)
        return {"item_id": item_id, "history": it["payload"].get("password_history") or []}

    def totp(self, cu, item_id: str) -> dict:
        o = self._require_open(cu)
        it = self._item(o, item_id)
        secret = it["payload"].get("totp")
        if not secret:
            raise PVError(404, "This item has no 2FA secret")
        try:
            return tools.totp(secret)
        except ToolError as e:
            raise PVError(e.status, e.message) from e

    COPYABLE = {"login": {"password", "username", "totp", "url"}, "card": {"number", "cvv", "cardholder"},
                "identity": {"email", "phone", "national_id", "full_name", "address"}, "note": {"notes"}}

    def copy(self, cu, item_id: str, what: str) -> dict:
        o = self._require_open(cu)
        it = self._item(o, item_id)
        p = it["payload"]
        allowed = self.COPYABLE[it["type"]] | {"notes"}
        if what not in allowed:
            raise PVError(422, f"Can copy: {', '.join(sorted(allowed))}")
        if what == "totp":
            value = self.totp(cu, item_id)["code"] if p.get("totp") else ""
        elif what == "url":
            value = (p.get("urls") or [""])[0]
        else:
            value = p.get(what) or ""
        if not value:
            raise PVError(404, f"This item has no {what.replace('_', ' ')}")
        secret = what in ("password", "totp", "number", "cvv", "national_id")
        try:
            res = self.clipboard.copy(str(value), self.settings.get("pv_clipboard_clear_seconds") if secret else 0)
        except ClipboardError as e:
            raise PVError(e.status, e.message) from e
        return res | {"field": what}

    def clear_clipboard(self) -> dict:
        return {"cleared": self.clipboard.clear_now()}

    def folders(self, cu) -> dict:
        o = self._require_open(cu)
        counts: dict[str, int] = {}
        for it in list(o.items.values()):
            if it["deleted_at"] or it["damaged"]:
                continue
            f = it["payload"].get("folder") or ""
            counts[f] = counts.get(f, 0) + 1
        return {"folders": [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: x[0].lower())]}

    def rename_folder(self, cu, old: str, new: str) -> dict:
        o = self._require_open(cu)
        new = _s(new, "folder", 60)
        n = 0
        for it in list(o.items.values()):
            if it["damaged"] or (it["payload"].get("folder") or "") != old:
                continue
            p = dict(it["payload"], folder=new)
            self._store(o, it["id"], it["type"], p, insert=False)
            n += 1
        if not n:
            raise PVError(404, "No items in that folder")
        return {"renamed": n, "folder": new}

    # ------------------------------------------------------------------ tools
    def check_password(self, password: str, inputs: list[str], breach: bool) -> dict:
        out = {"strength": tools.strength(password, inputs), "breach": None}
        if breach:
            if self.settings.get("pv_breach_check") == "off":
                out["breach"] = {"checked": False, "error": "Breach checks are switched off in Settings"}
            elif password:
                try:
                    n = self.breach.check(password)
                    out["breach"] = {"checked": True, "count": n, "found": n > 0}
                except ToolError as e:
                    out["breach"] = {"checked": False, "error": e.message}
        return out

    @staticmethod
    def generate(mode: str, opts: dict) -> dict:
        try:
            g = tools.generate(mode, **opts)
        except ToolError as e:
            raise PVError(e.status, e.message) from e
        g["strength"] = {k: v for k, v in tools.strength(g["password"]).items()
                         if k in ("score", "label", "guesses_log10", "crack_times")}
        return g

    # ------------------------------------------------------------------ audit
    def audit(self, cu, record: bool = True) -> dict:
        return self._audit_open(self._require_open(cu), record)

    def _audit_open(self, o: _Open, record: bool) -> dict:
        info = self._analyze(o)
        live = {i["id"]: i for i in list(o.items.values()) if not i["deleted_at"] and not i["damaged"]}
        considered = [i for i in live.values() if i["type"] in ("login", "card")]
        counts = {k: 0 for k in WEIGHTS}
        issues, dist, risk = [], [0] * 5, 0.0
        unchecked = 0
        for iid, inf in info.items():
            it = live[iid]
            if inf["strength"] is not None:
                dist[inf["strength"]] += 1
            if inf["fp"] and inf["breach"] is None:
                unchecked += 1
            for k, d in inf["issues"]:
                counts[k] += 1
                issues.append({"item_id": iid, "title": it["payload"]["title"], "type": it["type"], "kind": k,
                               "severity": ISSUE_SEVERITY[k], "detail": d})
            if inf["issues"]:
                risk += max(WEIGHTS[k] for k, _ in inf["issues"])
        score = None
        if considered:
            score = max(0, round(100 * (1 - risk / len(considered))))
            if counts["breached"]:
                score = min(score, 49)
            elif counts["reused"] or counts["weak"]:
                score = min(score, 84)
        grade = next(g for t, g in GRADES if score is not None and score >= t) if score is not None else "No passwords yet"
        groups: dict[str, list[str]] = {}
        for iid, inf in info.items():
            if inf["fp"] and inf["reused_with"]:
                groups.setdefault(inf["fp"], []).append(iid)
        issues.sort(key=lambda x: (-SEVERITIES.index(x["severity"]), x["title"].lower()))
        prev = self._vault_row(o.user_id)
        prev_audit = json.loads(prev["last_audit"]) if prev and prev["last_audit"] else {}
        summary = {"score": score, "grade": grade, "total": len(live), "logins": sum(1 for i in live.values()
                                                                                       if i["type"] == "login"),
                   "counts": {"weak": counts["weak"] + counts["fair"], **{k: v for k, v in counts.items()
                                                                            if k not in ("weak", "fair")}},
                   "very_weak_or_weak": counts["weak"], "fair": counts["fair"], "unchecked": unchecked,
                   "strength_distribution": dist, "checked_at": _iso(),
                   "breach_checked_at": prev_audit.get("breach_checked_at")}
        if record:
            self._record_audit(o.user_id, summary)
        return summary | {"issues": issues,
                          "reused_groups": [{"count": len(v), "item_ids": v} for v in groups.values()],
                          "breach_job": self._jobs.get(o.user_id, {}).get("public"),
                          "breach_check": self.settings.get("pv_breach_check")}

    def _record_audit(self, uid: int, summary: dict) -> None:
        self.db.execute("UPDATE pv_vaults SET last_audit=? WHERE user_id=?", (json.dumps(summary), uid))
        last = self.db.fetchone("SELECT ts, score FROM pv_scores WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,))
        if last and last["score"] == summary["score"] and (_parse(last["ts"]) or _now()) > _now() - timedelta(hours=1):
            return
        c = summary["counts"]
        self.db.execute("INSERT INTO pv_scores(user_id, score, total, weak, reused, breached, old) VALUES (?,?,?,?,?,?,?)",
                        (uid, summary["score"], summary["total"], c["weak"], c["reused"], c["breached"], c["old"]))

    def health(self, uid: int) -> dict | None:
        """Part 18: last stored audit summary (counts only) - readable while the vault is locked."""
        v = self._vault_row(uid)
        return json.loads(v["last_audit"]) if v and v["last_audit"] else None

    # ------------------------------------------------------------------ breach checks (k-anonymity)
    def start_breach_check(self, cu, item_ids: list[str] | None = None) -> dict:
        if self.settings.get("pv_breach_check") == "off":
            raise PVError(403, "Breach checks are switched off in Settings (pv_breach_check)")
        o = self._require_open(cu)
        return self._start_breach_job(o, item_ids)

    def breach_status(self, cu) -> dict:
        self._require_vault(cu.user["id"])
        return self._jobs.get(cu.user["id"], {}).get("public") or {"state": "idle"}

    def _start_breach_job(self, o: _Open, item_ids: list[str] | None, quiet: bool = False) -> dict:
        uid = o.user_id
        with self._lock:
            job = self._jobs.get(uid)
            if job and job["public"]["state"] == "running":
                return job["public"]
            targets: dict[str, tuple[str, list[str]]] = {}            # fp -> (password, item ids)
            for it in list(o.items.values()):
                if it["deleted_at"] or it["damaged"] or it["type"] != "login" or not it["payload"].get("password"):
                    continue
                if item_ids and it["id"] not in item_ids:
                    continue
                pw = it["payload"]["password"]
                fp = o.fp(pw)
                targets.setdefault(fp, (pw, []))[1].append(it["id"])
            public = {"state": "running", "total": len(targets), "done": 0, "found": 0, "items_found": 0,
                      "error": None, "started_at": _iso(), "finished_at": None, "full": item_ids is None}
            self._jobs[uid] = {"public": public}
        threading.Thread(target=self._breach_worker, args=(o, targets, public, quiet), daemon=True,
                         name=f"pv-breach-{uid}").start()
        return public

    def _breach_worker(self, o: _Open, targets: dict, public: dict, quiet: bool) -> None:
        uid = o.user_id
        newly: list[str] = []
        try:
            for fp, (pw, ids) in list(targets.items()):
                if not o.alive:
                    public.update(state="stopped", error="The vault was locked - check stopped")
                    return
                n = self.breach.check(pw)
                now = _iso()
                for iid in ids:
                    prev = self.db.fetchone("SELECT fp, count FROM pv_breach WHERE item_id=?", (iid,))
                    if n > 0 and not (prev and prev["fp"] == fp and prev["count"] > 0):
                        newly.append(iid)
                    try:                                           # the item may have been deleted meanwhile
                        self.db.execute("INSERT INTO pv_breach(item_id, fp, count, checked_at) VALUES (?,?,?,?) "
                                        "ON CONFLICT(item_id) DO UPDATE SET fp=excluded.fp, count=excluded.count, "
                                        "checked_at=excluded.checked_at", (iid, fp, n, now))
                    except sqlite3.IntegrityError:
                        continue
                public["done"] += 1
                if n > 0:
                    public["found"] += 1
                    public["items_found"] += len(ids)
                time.sleep(0.05)                                       # be polite to the free API
            public["state"] = "done"
            if public["full"]:
                v = self._vault_row(uid)
                if v:
                    a = json.loads(v["last_audit"]) if v["last_audit"] else {}
                    a["breach_checked_at"] = _iso()
                    self.db.execute("UPDATE pv_vaults SET last_audit=? WHERE user_id=?", (json.dumps(a), uid))
            if o.alive:                                                # refresh the stored score (no key touch)
                try:
                    self._audit_open(o, record=True)
                except Exception:                                     # pragma: no cover
                    pass
        except ToolError as e:
            public.update(state="failed", error=e.message)
            if not quiet:
                log.warning("Breach check failed: %s", e.message)
        except Exception as e:                                        # pragma: no cover
            public.update(state="failed", error=f"{type(e).__name__}")
            log.exception("Breach check crashed")
        finally:
            targets.clear()
            public["finished_at"] = _iso()
            if newly:
                self._event(uid, "breach_found", "high", "Password vault: breached passwords found",
                            f"{len(newly)} item(s) use a password that appears in known data breaches - change them",
                            data={"item_ids": newly})

    def _auto_breach(self, o: _Open, item_id: str) -> None:
        if self.settings.get("pv_breach_check") == "auto":
            it = o.items.get(item_id)
            if it and it["type"] == "login" and it["payload"].get("password"):
                self._start_breach_job(o, [item_id], quiet=True)

    # ------------------------------------------------------------------ import / export
    def import_items(self, cu, fmt: str = "auto", content: str | None = None, path: str | None = None,
                     password: str | None = None, folder: str | None = None, skip_duplicates: bool = True,
                     delete_source: bool = False) -> dict:
        o = self._require_open(cu)
        if bool(content) == bool(path):
            raise PVError(422, "Send either the file content or a path")
        if delete_source and not path:
            raise PVError(422, "delete_source works with a path")
        if path:
            p = Path(path)
            if not p.is_file():
                raise PVError(404, "File not found")
            if p.stat().st_size > MAX_IMPORT_BYTES:
                raise PVError(413, "File too large (max 10 MB)")
            raw = p.read_bytes()
            content = raw.decode("utf-8-sig", errors="replace")
        elif len(content.encode("utf-8", "ignore")) > MAX_IMPORT_BYTES:
            raise PVError(413, "File too large (max 10 MB)")
        is_backup = fmt == "chvault" or (fmt == "auto" and content.lstrip().startswith("{")
                                         and pio.EXPORT_MAGIC in content[:400])
        skipped: list[dict] = []
        try:
            if is_backup:
                if not password:
                    raise PVError(422, "Enter the backup password")
                found = "chvault"
                raw_items = pio.decrypt_backup(content, password)
                parsed = []
                for n, it in enumerate(raw_items, start=1):
                    if not isinstance(it, dict):
                        skipped.append({"line": n, "reason": "not an item"})
                        continue
                    parsed.append((it.get("type"), it.get("payload") or {}, it.get("created_at"), n))
            else:
                found, rows, skipped = pio.parse_csv(content, fmt)
                parsed = [(r.pop("type"), r, None, n) for n, r in enumerate(rows, start=1)]
        except ToolError as e:
            raise PVError(e.status, e.message) from e
        seen = set()
        for it in list(o.items.values()):
            if not it["deleted_at"] and not it["damaged"]:
                seen.add(self._sig(it["type"], it["payload"]))
        imported, dupes, notes = 0, 0, []
        room = MAX_ITEMS - self._count_live(o)
        for kind, data, created, n in parsed:
            if folder and isinstance(data, dict):
                data = dict(data, folder=folder)
            try:
                payload, _ = clean_payload(kind, data, internal=is_backup)
            except PVError as e:
                if kind == "login" and isinstance(data, dict) and data.get("totp"):
                    try:                                              # keep the login, drop the odd 2FA secret
                        payload, _ = clean_payload(kind, dict(data, totp=""), internal=is_backup)
                        notes.append({"line": n, "reason": f"2FA secret not imported: {e.message}"})
                    except PVError as e2:
                        skipped.append({"line": n, "reason": e2.message})
                        continue
                else:
                    skipped.append({"line": n, "reason": e.message})
                    continue
            sig = self._sig(kind, payload)
            if skip_duplicates and sig in seen:
                dupes += 1
                continue
            if imported >= room:
                skipped.append({"line": n, "reason": "vault is full"})
                continue
            seen.add(sig)
            if kind == "login":
                payload.setdefault("password_history", [])
                if payload.get("password") and not payload.get("password_changed_at"):
                    payload["password_changed_at"] = _iso()
            self._store(o, secrets.token_hex(16), kind, payload, insert=True,
                        created=created if isinstance(created, str) and _parse(created) else None)
            imported += 1
        removed = False
        if delete_source and path and imported:
            removed = self._overwrite_delete(Path(path))
        self._event(o.user_id, "imported", "low", "Passwords imported",
                    f"{imported} imported, {dupes} duplicates skipped, {len(skipped)} rows skipped ({found})")
        if imported and self.settings.get("pv_breach_check") == "auto":
            self._start_breach_job(o, None, quiet=True)
        return {"format": found, "imported": imported, "duplicates": dupes, "skipped": skipped[:200],
                "skipped_count": len(skipped), "notes": notes[:200], "source_deleted": removed,
                "tip": None if removed or not path else "Delete the exported CSV file - it holds your passwords in "
                                                         "plain text (Part 13's shredder can wipe it)."}

    @staticmethod
    def _sig(kind: str, p: dict) -> tuple:
        if kind == "login":
            return (kind, (p.get("title") or "").lower(), (p.get("username") or "").lower(),
                    host_of((p.get("urls") or [""])[0]), p.get("password") or "")
        return (kind, (p.get("title") or "").lower(), p.get("number") or "", (p.get("notes") or "")[:200])

    @staticmethod
    def _overwrite_delete(p: Path) -> bool:
        try:
            size = p.stat().st_size
            with open(p, "r+b") as f:
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
            p.unlink()
            return True
        except OSError as e:
            log.warning("Could not wipe the imported file: %s", e)
            return False

    def export(self, cu, fmt: str, master_password: str, export_password: str | None = None,
               confirm: bool = False, path: str | None = None, overwrite: bool = False) -> dict:
        uid = cu.user["id"]
        o = self._require_open(cu)
        v = self._require_vault(uid)
        if fmt not in ("csv", "chvault"):
            raise PVError(422, "format must be csv or chvault")
        if fmt == "csv" and not confirm:
            raise PVError(428, "A CSV export holds every password in plain text. Anyone who gets the file can read "
                               "them all. Send again with confirm=true - or use the encrypted .chvault backup.")
        if fmt == "chvault":
            if not export_password or len(export_password) < 10:
                raise PVError(422, "Choose a backup password of at least 10 characters")
            if tools.strength(export_password)["score"] < 3:
                raise PVError(422, "The backup password is too easy to guess - try a passphrase")
        self._verify_master(uid, v, master_password)
        items = [{"type": i["type"], "payload": i["payload"], "created_at": i["created_at"],
                  "updated_at": i["updated_at"]} for i in list(o.items.values()) if not i["deleted_at"] and not i["damaged"]]
        stamp = _now().strftime("%Y%m%d-%H%M")
        if fmt == "csv":
            content, name = pio.to_csv(items), f"cyberhub-passwords-{stamp}.csv"
        else:
            content = pio.encrypt_backup(items, export_password, kdf_params(), APP_VERSION)
            name = f"cyberhub-vault-{stamp}.chvault"
        out: dict[str, Any] = {"format": fmt, "count": len(items), "filename": name}
        if path:
            dest = Path(path)
            if dest.is_dir():
                dest = dest / name
            if not dest.parent.is_dir():
                raise PVError(404, "That folder doesn't exist")
            if dest.exists() and not overwrite:
                raise PVError(409, "A file with that name already exists")
            tmp = dest.with_name(dest.name + ".tmp")
            tmp.write_text(content, encoding="utf-8", newline="")
            os.replace(tmp, dest)
            out["path"] = str(dest)
        else:
            out["content"] = content
        if fmt == "csv":
            self._event(uid, "exported_plaintext", "medium", "Passwords exported as plain text (CSV)",
                        f"{len(items)} item(s){' to ' + out['path'] if path else ''}")
        else:
            self._event(uid, "exported", "low", "Encrypted password vault backup created", f"{len(items)} item(s)")
        return out

    # ------------------------------------------------------------------ events / summary
    def events(self, cu, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100, offset: int = 0) -> dict:
        uid = cu.user["id"]
        where, params = ["user_id=?", "id > ?"], [uid, after_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if kind:
            where.append("kind=?"); params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        clause = "WHERE " + " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM pv_events {clause}", tuple(params))["n"]
        items = self.db.fetchall(f"SELECT * FROM pv_events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                 tuple(params) + (limit, offset))
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM pv_events WHERE user_id=?", (uid,))["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM pv_events WHERE user_id=? AND acknowledged=0", (uid,))["n"]
        return {"total": total, "last_id": last, "unacknowledged": unack,
                "items": [dict(i, acknowledged=bool(i["acknowledged"]),
                               data=json.loads(i["data"]) if i["data"] else None) for i in items]}

    def acknowledge(self, cu, ids: list[int] | None = None) -> int:
        uid = cu.user["id"]
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE pv_events SET acknowledged=1 WHERE user_id=? AND id IN ({q})",
                                   (uid, *ids)).rowcount
        return self.db.execute("UPDATE pv_events SET acknowledged=1 WHERE user_id=? AND acknowledged=0",
                               (uid,)).rowcount

    def clear_events(self, cu) -> int:
        return self.db.execute("DELETE FROM pv_events WHERE user_id=?", (cu.user["id"],)).rowcount

    def summary(self, cu, days: int = 30) -> dict:
        uid = cu.user["id"]
        now = _now()
        since = _iso(now - timedelta(days=days))
        day_list = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
        per_day = {d: {"day": d, "score": None, "weak": None, "reused": None, "breached": None,
                       **{s: 0 for s in SEVERITIES}} for d in day_list}
        for r in self.db.fetchall("SELECT substr(ts,1,10) AS day, score, weak, reused, breached FROM pv_scores "
                                  "WHERE user_id=? AND ts >= ? ORDER BY id", (uid, since)):
            if r["day"] in per_day:
                per_day[r["day"]].update(score=r["score"], weak=r["weak"], reused=r["reused"], breached=r["breached"])
        for r in self.db.fetchall("SELECT substr(ts,1,10) AS day, severity, COUNT(*) AS n FROM pv_events WHERE "
                                  "user_id=? AND ts >= ? GROUP BY day, severity", (uid, since)):
            if r["day"] in per_day:
                per_day[r["day"]][r["severity"]] += r["n"]
        by_kind = {r["kind"]: r["n"] for r in self.db.fetchall(
            "SELECT kind, COUNT(*) AS n FROM pv_events WHERE user_id=? AND ts >= ? GROUP BY kind ORDER BY n DESC",
            (uid, since))}
        types = {t: 0 for t in TYPES}
        for r in self.db.fetchall("SELECT type, COUNT(*) AS n FROM pv_items WHERE user_id=? AND deleted_at IS NULL "
                                  "GROUP BY type", (uid,)):
            types[r["type"]] = r["n"]
        return {"days": days, "per_day": list(per_day.values()), "events_by_kind": by_kind, "items_by_type": types,
                "audit": self.health(uid)}

    def prune(self) -> int:
        keep = self.settings.get("pv_score_retention_days")
        return self.db.execute("DELETE FROM pv_scores WHERE ts < ?", (_iso(_now() - timedelta(days=keep)),)).rowcount

    def shutdown(self) -> None:
        with self._lock:
            ids = list(self._opens)
        for s in ids:
            self._close(s)
        self.clipboard.shutdown()


async def password_vault_loop(svc: PasswordVaultService, tick: float = 15) -> None:
    """Every 15 s: lock idle vaults / vaults whose session ended. Hourly: empty old trash, prune score history."""
    last_purge = 0.0
    while True:
        await asyncio.sleep(tick)
        try:
            await asyncio.to_thread(svc.sweep)
            if time.monotonic() - last_purge >= 3600:
                last_purge = time.monotonic()
                await asyncio.to_thread(svc.purge_trash)
                await asyncio.to_thread(svc.prune)
        except Exception as e:                                        # never let the loop die
            log.warning("Password vault housekeeping failed: %s", getattr(e, "message", e))
