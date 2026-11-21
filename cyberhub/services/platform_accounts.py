"""
Cyber Hub Backend - Social & Platform Accounts (Part 16)
Developed by Syed Muhammad Tayyab

One service behind /api/platforms.

Accounts registry   - the accounts you use (Google, Facebook, GitHub, Fiverr, JazzCash ... 55 catalog platforms or any
                      site), per Cyber Hub user. Handle / e-mail / phone ending / notes are sealed with AES-256-GCM
                      under a key derived from Part 6's DPAPI-protected vault key (Vault.derive_subkey) - the database
                      never holds them in clear. Accounts can be imported from your Part 12 password vault.
Security checklist  - per platform: 2FA, app / passkey instead of SMS, backup codes, recovery e-mail / phone, sign-in
                      alerts, devices, connected apps, SSH keys / tokens, privacy, mail forwarding rules, password
                      changed after the site's breach. Facts beat ticks: Part 12 vault (reused / weak / breached
                      password, saved 2FA code), GitHub's own API (2FA on / off, old SSH keys) and breach data fill
                      items in automatically. Review items go stale after platform_review_days.
Recovery chain      - which e-mail account can reset which accounts and which login (Google / Microsoft / GitHub)
                      protects which apps; "blast radius" of each one and alerts when a recovery account is weak.
Breach monitoring   - your e-mail addresses checked with XposedOrNot (free) or Have I Been Pwned (API key); the public
                      HIBP breach list (no personal data sent) tells you when a site you use is breached and whether
                      your password there pre-dates it.
Link / sender check - "is this link / e-mail really from Facebook?" = official-domain check + Part 15 threat intel
                      (feeds + phishing analyser).
Extensions audit    - browser (Chrome / Edge / Brave / Vivaldi / Firefox) and editor (VS Code, Cursor ...) extensions
                      with an explainable risk score, new risky extensions alerted, one-click Part 5 antivirus scan.

Feeds Part 18 through health(user_id) and Part 17 through platform_events.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..database import Database
from ..logger import get_logger
from . import breach_watch as bw
from . import extensions_audit as ext
from . import intel_feeds as feeds
from . import ioc
from . import phishing as ph
from . import platform_catalog as cat

log = get_logger("platforms")

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV = {s: i for i, s in enumerate(SEVERITIES)}
ISSUE_POINTS = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
MAX_ACCOUNTS = 500
MAX_EMAILS = 50
GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = re.compile(r"^(gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})$")
GITHUB_BROAD = {"repo", "delete_repo", "admin:org", "write:org", "admin:public_key", "write:public_key",
                "admin:repo_hook", "admin:org_hook", "write:packages", "delete:packages", "workflow", "user",
                "admin:enterprise", "admin:gpg_key", "write:gpg_key", "admin:ssh_signing_key", "codespace",
                "project", "gist", "write:discussion"}
GITHUB_TOKEN_HELP = ("Create a token that can only read your profile: Settings > Developer settings > Personal access "
                     "tokens > Tokens (classic) with only 'read:user' + 'read:public_key', or a fine-grained token with "
                     "no repository access. Cyber Hub stores it encrypted and only reads.")
OLD_KEY_DAYS = 365
EVENT_KINDS = ("email_breach", "platform_breach", "review_due", "github_2fa_off", "github_old_keys",
               "extension_new", "catalog_error", "recovery_weak")
RECOVERS_DOMAINS = {"gmail.com": "google", "googlemail.com": "google", "outlook.com": "microsoft",
                    "hotmail.com": "microsoft", "live.com": "microsoft", "msn.com": "microsoft", "icloud.com": "apple",
                    "me.com": "apple", "yahoo.com": "yahoo", "proton.me": "proton", "protonmail.com": "proton"}
APPS = {   # process name (lower, no .exe) -> platform key, for "apps on this PC" discovery
    "whatsapp": "whatsapp", "whatsapp.root": "whatsapp", "telegram": "telegram", "discord": "discord",
    "slack": "slack", "zoom": "zoom", "code": "vscode", "cursor": "vscode", "chrome": "chrome", "msedge": "edge",
    "firefox": "firefox", "teams": "microsoft_teams", "ms-teams": "microsoft_teams", "spotify": "spotify",
    "steam": "steam", "figma": "figma", "notion": "notion", "dropbox": "dropbox", "onedrive": "microsoft",
    "github desktop": "github", "githubdesktop": "github", "docker desktop": "docker_hub",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s[:19].replace(" ", "T"), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _ago(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def _days_since(s: str | None) -> int | None:
    d = _parse_ts(s)
    return (datetime.now(timezone.utc) - d).days if d else None


def _clean(v: Any, field: str, limit: int) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str):
        raise PlatformError(422, f"{field} must be text")
    v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v).strip()
    if len(v) > limit:
        raise PlatformError(422, f"{field} is too long (max {limit})")
    return v or None


class PlatformError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


class _Job:
    def __init__(self, kind: str, username: str, email_ids: list[int]):
        self.id = secrets.token_hex(8)
        self.kind, self.username, self.email_ids = kind, username, email_ids
        self.status = "running"
        self.created_at = _now()
        self.finished_at: str | None = None
        self.progress = {"done": 0, "total": len(email_ids), "percent": 0}
        self.result: dict = {"checked": 0, "breached": 0, "new_breaches": 0, "errors": {}}
        self.error: str | None = None

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "by": self.username,
                "created_at": self.created_at, "finished_at": self.finished_at, "progress": dict(self.progress),
                "result": self.result, "error": self.error}


class PlatformService:
    def __init__(self, db: Database, settings, activity, vault=None, passwords=None, intel=None, scanner=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.vault, self.passwords, self.intel, self.scanner = vault, passwords, intel, scanner
        self.transport = feeds.urllib_transport             # tests swap this for a fake
        self.pace = {"xposedornot": 1.1, "hibp": 6.5, "github": 0.0}     # seconds between requests per provider
        self._last_call: dict[str, float] = {}
        self._lock = threading.RLock()
        self._jobs: dict[str, _Job] = {}
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._ext_cache: tuple[float, dict] | None = None
        self._last_ext_watch = 0.0
        self.stats = {"emails_checked": 0, "catalog_updates": 0, "github_syncs": 0, "extension_audits": 0}

    # ================================================================== basics
    def _g(self, key: str):
        return self.settings.get(key)

    def _state(self, key: str, value: Any = ...) -> Any:
        if value is ...:
            r = self.db.fetchone("SELECT value FROM platform_state WHERE key=?", (key,))
            return json.loads(r["value"]) if r else None
        self.db.execute("INSERT INTO platform_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))
        return value

    def _event(self, kind: str, severity: str, title: str, detail: str | None = None, data: dict | None = None,
               ref: str | None = None, uid: int | None = None, account_id: int | None = None) -> int | None:
        if ref and self.db.fetchone("SELECT 1 FROM platform_events WHERE ref=? LIMIT 1", (ref,)):
            return None
        cur = self.db.execute("INSERT INTO platform_events(user_id, account_id, kind, severity, title, detail, ref, "
                              "data) VALUES (?,?,?,?,?,?,?,?)", (uid, account_id, kind, severity, title, detail, ref,
                                                                 json.dumps(data) if data else None))
        try:
            self.activity.record("platform", title, detail, severity=severity, source="platforms")
        except ValueError:                                              # pragma: no cover
            pass
        return cur.lastrowid

    @staticmethod
    def _is_admin(cu) -> bool:
        return cu is None or cu.user.get("role") == "admin"

    def _need_admin(self, cu, what: str) -> None:
        if not self._is_admin(cu):
            raise PlatformError(403, f"Administrator rights required to {what}")

    # ---- sealing (device key from Part 6, never stored)
    def _key(self, label: str) -> bytes:
        if self.vault is None or not getattr(self.vault, "available", False):
            raise PlatformError(503, "Cyber Hub's device key (vault.key) can't be opened right now, so account "
                                     "details can't be stored or read safely")
        return self.vault.derive_subkey(label)

    def _seal(self, obj: dict, aad: str) -> str:
        n = secrets.token_bytes(12)
        ct = AESGCM(self._key("platform-accounts-v1")).encrypt(n, json.dumps(obj).encode(), aad.encode())
        return "v1:" + base64.b64encode(n + ct).decode()

    def _open(self, blob: str | None, aad: str) -> dict | None:
        if not blob:
            return {}
        try:
            raw = base64.b64decode(blob.split(":", 1)[1])
            return json.loads(AESGCM(self._key("platform-accounts-v1")).decrypt(raw[:12], raw[12:], aad.encode()))
        except (InvalidTag, ValueError, IndexError):
            return None                                                   # damaged / moved row

    def _fp(self, email: str) -> str:
        import hmac
        import hashlib
        return hmac.new(self._key("platform-email-fp-v1"), email.encode(), hashlib.sha256).hexdigest()[:40]

    # ---- HTTP
    def _http(self, method: str, url: str, headers: dict, provider: str) -> tuple[int, bytes, dict]:
        wait = self.pace.get(provider, 0) - (time.monotonic() - self._last_call.get(provider, 0))
        if wait > 0 and self._stopping.wait(wait):
            raise PlatformError(503, "Engine is shutting down")
        self._last_call[provider] = time.monotonic()
        hdr = {"User-Agent": bw.USER_AGENT, **headers}
        try:
            if self.transport is feeds.urllib_transport:
                return feeds.urllib_transport(method, url, hdr, None, 25.0, bw.MAX_CATALOG_BYTES + 1)
            return self.transport(method, url, hdr, None, 25.0)
        except (OSError, ValueError) as e:
            raise PlatformError(502, f"Couldn't reach {provider} ({type(e).__name__}) - check the internet "
                                     "connection") from e

    # ================================================================== catalog
    def catalog(self) -> dict:
        return {"reviewed": cat.CATALOG_REVIEWED, "platforms": [cat.public(p) for p in cat.PLATFORMS],
                "categories": cat.CATEGORIES, "importance": list(cat.IMPORTANCE),
                "checklist": [{k: i[k] for k in ("id", "label", "weight", "help")} for i in cat.ITEMS],
                "statuses": list(cat.STATUSES), "mfa": cat.MFA_LABELS, "recovery": cat.RECOVERY_LABELS}

    def platform(self, key: str) -> dict:
        if key not in cat.BY_KEY:
            raise PlatformError(404, "Unknown platform")
        p = cat.BY_KEY[key]
        out = cat.public(p)
        out["breaches"] = self._domain_breaches(p["domains"])
        return out

    # ================================================================== accounts: storage
    def _row(self, cu, aid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM platform_accounts WHERE id=? AND user_id=?", (aid, cu.user["id"]))
        if not r:
            raise PlatformError(404, "Account not found")
        return r

    def _rows(self, uid: int) -> list[dict]:
        return self.db.fetchall("SELECT * FROM platform_accounts WHERE user_id=? ORDER BY id", (uid,))

    def _secret(self, r: dict) -> dict | None:
        return self._open(r["secret"], f"{r['user_id']}:{r['id']}")

    def _plat(self, r: dict) -> dict:
        if r["platform"] == "custom":
            p = dict(cat.CUSTOM, name=r["custom_name"] or "Other site",
                     domains=(r["custom_domain"],) if r["custom_domain"] else ())
            return p
        return cat.get(r["platform"])

    def _ensure_email(self, uid: int, email: str, source: str, monitor: bool = True) -> int:
        fp = self._fp(email)
        r = self.db.fetchone("SELECT id FROM platform_emails WHERE user_id=? AND fp=?", (uid, fp))
        if r:
            return r["id"]
        if self.db.fetchone("SELECT COUNT(*) AS n FROM platform_emails WHERE user_id=?", (uid,))["n"] >= MAX_EMAILS:
            raise PlatformError(413, f"At most {MAX_EMAILS} e-mail addresses can be monitored")
        cur = self.db.execute("INSERT INTO platform_emails(user_id, fp, secret, masked, domain, monitor, source) "
                              "VALUES (?,?,?,?,?,?,?)", (uid, fp, "", bw.mask_email(email), email.split("@")[1],
                                                         int(monitor), source))
        eid = cur.lastrowid
        self.db.execute("UPDATE platform_emails SET secret=? WHERE id=?",
                        (self._seal({"email": email}, f"email:{uid}:{eid}"), eid))
        return eid

    def _email_of(self, e: dict) -> str | None:
        d = self._open(e["secret"], f"email:{e['user_id']}:{e['id']}")
        return d.get("email") if d else None

    def _validate(self, platform: str, data: dict) -> dict:
        out: dict[str, Any] = {}
        if platform != "custom" and platform not in cat.BY_KEY:
            raise PlatformError(422, "Unknown platform - pick one from /api/platforms/catalog or use 'custom'")
        out["label"] = _clean(data.get("label"), "label", 60)
        out["handle"] = _clean(data.get("handle"), "handle", 200)
        if data.get("email"):
            try:
                out["email"] = bw.normalize_email(data["email"])
            except bw.BreachError as e:
                raise PlatformError(e.status, e.message)
        else:
            out["email"] = None
        ph_ = _clean(data.get("phone_last4"), "phone_last4", 4)
        if ph_ and not re.fullmatch(r"\d{2,4}", ph_):
            raise PlatformError(422, "phone_last4 = only the last 2-4 digits of the number (never the full number)")
        out["phone_last4"] = ph_
        out["notes"] = _clean(data.get("notes"), "notes", 1000)
        imp = data.get("importance")
        if imp is not None and imp not in cat.IMPORTANCE:
            raise PlatformError(422, f"importance must be one of: {', '.join(cat.IMPORTANCE)}")
        out["importance"] = imp
        if platform == "custom":
            out["custom_name"] = _clean(data.get("custom_name"), "custom_name", 80)
            dom = _clean(data.get("custom_domain"), "custom_domain", 253)
            if not out["custom_name"]:
                raise PlatformError(422, "Give the site a name (custom_name)")
            if dom:
                try:
                    c = ioc.classify(dom)
                except ioc.IOCError:
                    raise PlatformError(422, "custom_domain must be a web address like example.com")
                host = c.get("host") or (c["value"] if c["type"] == "domain" else None)
                if not host or c["type"] not in ("domain", "url"):
                    raise PlatformError(422, "custom_domain must be a web address like example.com")
                dom = ioc.registrable(host)
            out["custom_domain"] = dom
        return out

    def _link_ids(self, cu, data: dict, aid: int | None) -> dict:
        out = {}
        for k in ("recovery_account_id", "sso_account_id"):
            if k in data:
                v = data[k]
                if v is not None:
                    if v == aid:
                        raise PlatformError(422, f"{k} can't point to the same account")
                    self._row(cu, int(v))
                    if aid is not None and self._would_loop(cu.user["id"], aid, int(v), k):
                        raise PlatformError(422, "That would make a loop (A recovers B recovers A)")
                out[k] = v
        return out

    def _would_loop(self, uid: int, aid: int, target: int, col: str) -> bool:
        seen, cur = set(), target
        while cur is not None and cur not in seen:
            if cur == aid:
                return True
            seen.add(cur)
            r = self.db.fetchone(f"SELECT {col} AS n FROM platform_accounts WHERE id=? AND user_id=?", (cur, uid))
            cur = r["n"] if r else None
        return False

    # ================================================================== accounts: API
    def add_account(self, cu, platform: str, data: dict) -> dict:
        uid = cu.user["id"]
        v = self._validate(platform, data)
        if self.db.fetchone("SELECT COUNT(*) AS n FROM platform_accounts WHERE user_id=?", (uid,))["n"] >= MAX_ACCOUNTS:
            raise PlatformError(413, f"At most {MAX_ACCOUNTS} accounts")
        ident = (v["handle"] or "").lower(), (v["email"] or "")
        for r in self._rows(uid):
            if r["platform"] == platform and (platform != "custom" or r["custom_name"] == v.get("custom_name")):
                s = self._secret(r) or {}
                if (ident[0] and (s.get("handle") or "").lower() == ident[0]) or \
                        (ident[1] and s.get("email") == ident[1]) or (not any(ident) and not s.get("handle")
                                                                      and not s.get("email") and
                                                                      (r["label"] or None) == v["label"]):
                    raise PlatformError(409, "This account is already in your list")
        links = self._link_ids(cu, data, None)
        email_id = self._ensure_email(uid, v["email"], "account") if v["email"] else None
        cur = self.db.execute(
            "INSERT INTO platform_accounts(user_id, platform, custom_name, custom_domain, label, importance, secret, "
            "email_id, recovery_account_id, sso_account_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, platform, v.get("custom_name"), v.get("custom_domain"), v["label"], v["importance"], "", email_id,
             links.get("recovery_account_id"), links.get("sso_account_id"), _now(), _now()))
        aid = cur.lastrowid
        self.db.execute("UPDATE platform_accounts SET secret=? WHERE id=?",
                        (self._seal({k: v[k] for k in ("handle", "email", "phone_last4", "notes")}, f"{uid}:{aid}"),
                         aid))
        self._autolink(uid)
        if data.get("vault_item_id"):
            self.link_vault(cu, aid, data["vault_item_id"])
        p = cat.get(platform) if platform != "custom" else None
        self.activity.record("platform", f"Account added: {(p or {}).get('name') or v.get('custom_name')}",
                             severity="info", source="platforms")
        return self.get_account(cu, aid)

    def _autolink(self, uid: int) -> None:
        """Fill missing SSO parents (YouTube -> your Google account) and recovery accounts (an account signed up
        with you@gmail.com -> your Google account whose address is you@gmail.com)."""
        rows = self._rows(uid)
        by_plat: dict[str, list[dict]] = {}
        for r in rows:
            by_plat.setdefault(r["platform"], []).append(r)
        mail_owner: dict[str, int] = {}
        for r in rows:
            p = self._plat(r)
            if p.get("recovers") and not p.get("sso") and r["email_id"]:
                mail_owner.setdefault(r["email_id"], r["id"])
        for r in rows:
            p = self._plat(r)
            if p.get("sso") and r["sso_account_id"] is None and len(by_plat.get(p["sso"], [])) == 1:
                self.db.execute("UPDATE platform_accounts SET sso_account_id=? WHERE id=?",
                                (by_plat[p["sso"]][0]["id"], r["id"]))
            if r["recovery_account_id"] is None and r["email_id"] and mail_owner.get(r["email_id"]) not in (None,
                                                                                                         r["id"]):
                owner = mail_owner[r["email_id"]]
                if not self._would_loop(uid, r["id"], owner, "recovery_account_id"):
                    self.db.execute("UPDATE platform_accounts SET recovery_account_id=? WHERE id=?", (owner, r["id"]))

    def update_account(self, cu, aid: int, data: dict) -> dict:
        r = self._row(cu, aid)
        uid = cu.user["id"]
        s = self._secret(r)
        if s is None:
            raise PlatformError(409, "This account's details failed their integrity check - delete and add it again")
        merged = {**s, "label": r["label"], "importance": r["importance"], "custom_name": r["custom_name"],
                  "custom_domain": r["custom_domain"]}
        for k in ("label", "handle", "email", "phone_last4", "notes", "importance", "custom_name", "custom_domain"):
            if k in data:
                merged[k] = data[k]
        v = self._validate(r["platform"], merged)
        links = self._link_ids(cu, data, aid)
        email_id = r["email_id"]
        if v["email"] != s.get("email"):
            email_id = self._ensure_email(uid, v["email"], "account") if v["email"] else None
        sets = {"label": v["label"], "importance": v["importance"], "custom_name": v.get("custom_name"),
                "custom_domain": v.get("custom_domain"), "email_id": email_id, "updated_at": _now(),
                "secret": self._seal({k: v[k] for k in ("handle", "email", "phone_last4", "notes")}, f"{uid}:{aid}"),
                **links}
        self.db.execute(f"UPDATE platform_accounts SET {', '.join(k + '=?' for k in sets)} WHERE id=?",
                        tuple(sets.values()) + (aid,))
        self._autolink(uid)
        return self.get_account(cu, aid)

    def delete_account(self, cu, aid: int) -> dict:
        r = self._row(cu, aid)
        self.db.execute("DELETE FROM platform_accounts WHERE id=?", (aid,))
        self._drop_orphan_email(r["email_id"])
        self.activity.record("platform", "Account removed from the list", severity="info", source="platforms")
        return {"deleted": True}

    def _drop_orphan_email(self, email_id: int | None) -> None:
        if email_id and not self.db.fetchone("SELECT 1 FROM platform_accounts WHERE email_id=?", (email_id,)):
            self.db.execute("DELETE FROM platform_emails WHERE id=? AND source='account'", (email_id,))

    def set_checks(self, cu, aid: int, items: dict[str, str], note: str | None = None) -> dict:
        r = self._row(cu, aid)
        p = self._plat(r)
        has_pw_breach = any(bw.has_secrets(b["data_classes"]) for b in self._domain_breaches(p["domains"]))
        for k, st in items.items():
            if k not in cat.ITEM_BY_ID:
                raise PlatformError(422, f"Unknown checklist item '{k}'")
            if st not in cat.STATUSES:
                raise PlatformError(422, f"Status must be one of: {', '.join(cat.STATUSES)}")
            if not cat.item_applies(k, p, has_pw_breach) and st != "not_applicable":
                raise PlatformError(422, f"'{k}' doesn't apply to {p['name']}")
        note = _clean(note, "note", 300)
        with self.db.tx() as c:
            for k, st in items.items():
                if st == "unknown":
                    c.execute("DELETE FROM platform_checks WHERE account_id=? AND item=?", (aid, k))
                else:
                    c.execute("INSERT INTO platform_checks(account_id, item, status, source, note, updated_at) VALUES "
                              "(?,?,?,?,?,?) ON CONFLICT(account_id, item) DO UPDATE SET status=excluded.status, "
                              "source=excluded.source, note=excluded.note, updated_at=excluded.updated_at",
                              (aid, k, st, "you", note, _now()))
            c.execute("UPDATE platform_accounts SET updated_at=? WHERE id=?", (_now(), aid))
        return self.get_account(cu, aid)

    def mark_reviewed(self, cu, aid: int) -> dict:
        """'I just went through this account's security page' - all applicable review items done, timer reset."""
        r = self._row(cu, aid)
        p = self._plat(r)
        items = {k: "done" for k in cat.REVIEW_ITEMS if cat.item_applies(k, p)}
        if items:
            self.set_checks(cu, aid, items)
        self.db.execute("UPDATE platform_accounts SET last_reviewed_at=? WHERE id=?", (_now(), aid))
        return self.get_account(cu, aid)

    # ================================================================== evidence
    def _vault_view(self, cu) -> dict[str, dict] | None:
        """Part 12 vault items (masked metadata only) while the vault is unlocked in this session, else None."""
        if self.passwords is None or cu is None or not getattr(cu, "session", None):
            return None
        # Read without "touching" the vault: looking at Platforms must not keep the vault from auto-locking.
        o = self.passwords._get_open(cu.session["id"], cu.user["id"], touch=False)
        if o is None:
            return None
        info = self.passwords._analyze(o)
        return {it["id"]: self.passwords._public(it, info.get(it["id"])) for it in list(o.items.values())
                if it["type"] == "login" and not it["deleted_at"] and not it["damaged"]}

    @staticmethod
    def _signals(item: dict) -> dict:
        kinds = [i["kind"] for i in item.get("issues") or []]
        return {"exists": True, "title": None, "has_password": bool(item.get("has_password")),
                "strength": item.get("strength"), "reused": "reused" in kinds, "breached": "breached" in kinds,
                "weak": "weak" in kinds, "fair": "fair" in kinds, "old": "old" in kinds,
                "has_totp": bool(item.get("has_totp")), "password_changed_at": item.get("password_changed_at"),
                "checked_at": _now()}

    def refresh_vault(self, cu, view: dict | None = None) -> int:
        """Store the latest vault signals (no secrets, no titles) for linked accounts - used while locked."""
        view = view if view is not None else self._vault_view(cu)
        if view is None:
            return 0
        n = 0
        for r in self.db.fetchall("SELECT id, vault_item_id FROM platform_accounts WHERE user_id=? AND vault_item_id "
                                  "IS NOT NULL", (cu.user["id"],)):
            it = view.get(r["vault_item_id"])
            snap = self._signals(it) if it else {"exists": False, "checked_at": _now()}
            self.db.execute("UPDATE platform_accounts SET vault_snapshot=? WHERE id=?", (json.dumps(snap), r["id"]))
            n += 1
        return n

    def vault_matches(self, cu, aid: int) -> dict:
        r = self._row(cu, aid)
        view = self._vault_view(cu)
        if view is None:
            raise PlatformError(423, "Unlock your password vault (Passwords) to match accounts with saved logins")
        p = self._plat(r)
        s = self._secret(r) or {}
        out = []
        for it in view.values():
            if self._owns(p, it.get("host") or ""):
                u = (it.get("username") or "").lower()
                out.append({"item_id": it["id"], "title": it["title"], "username": it.get("username"),
                            "host": it.get("host"), "has_totp": it.get("has_totp"),
                            "same_user": bool(u) and u in {(s.get("handle") or "").lower(), s.get("email") or ""}})
        out.sort(key=lambda x: (not x["same_user"], x["title"].lower()))
        return {"items": out, "linked": r["vault_item_id"]}

    def link_vault(self, cu, aid: int, item_id: str | None, create: bool = False, password: str | None = None) -> dict:
        r = self._row(cu, aid)
        if create:
            if self.passwords is None:
                raise PlatformError(501, "The password vault is not available")
            p = self._plat(r)
            s = self._secret(r) or {}
            url = (p["links"].get("security") or ("https://" + p["domains"][0] if p["domains"] else None))
            data = {"title": p["name"] if r["platform"] != "custom" else r["custom_name"],
                    "username": s.get("email") or s.get("handle") or "", "urls": [url] if url else [],
                    "password": password or "", "notes": "Added from Cyber Hub > Platforms"}
            from .password_vault import PVError
            try:
                item_id = self.passwords.create_item(cu, "login", data)["item"]["id"]
            except PVError as e:
                raise PlatformError(e.status, e.message)
        if item_id is not None:
            view = self._vault_view(cu)
            if view is None:
                raise PlatformError(423, "Unlock your password vault first")
            if item_id not in view:
                raise PlatformError(404, "That vault item doesn't exist (or isn't a login)")
            self.db.execute("UPDATE platform_accounts SET vault_item_id=?, vault_snapshot=? WHERE id=?",
                            (item_id, json.dumps(self._signals(view[item_id])), aid))
        else:
            self.db.execute("UPDATE platform_accounts SET vault_item_id=NULL, vault_snapshot=NULL WHERE id=?", (aid,))
        return self.get_account(cu, aid)

    @staticmethod
    def _owns(p: dict, host: str) -> bool:
        host = (host or "").lower().rstrip(".").removeprefix("www.")
        if not host:
            return False
        reg = ioc.registrable(host)
        return any(host == d or host.endswith("." + d) or reg == d for d in p["domains"])

    def _domain_breaches(self, domains) -> list[dict]:
        regs = sorted({ioc.registrable(d) for d in domains if d})
        if not regs:
            return []
        rows = self.db.fetchall(f"SELECT * FROM platform_breach_catalog WHERE domain IN ({','.join('?' * len(regs))}) "
                                "ORDER BY breach_date DESC", tuple(regs))
        return [self._breach_public(b) for b in rows]

    @staticmethod
    def _breach_public(b: dict) -> dict:
        classes = json.loads(b["data_classes"] or "[]")
        flags = json.loads(b["flags"] or "{}")
        return {"name": b["name"], "title": b["title"], "domain": b["domain"], "breach_date": b["breach_date"],
                "added_date": b["added_date"], "pwn_count": b["pwn_count"], "data_classes": classes,
                "description": b["description"], "passwords_exposed": bw.has_secrets(classes),
                "severity": bw.severity(classes, flags.get("stealer_log")), **flags,
                "advice": bw.advice(classes, flags.get("stealer_log"))}

    # ================================================================== analysis
    def _analyze(self, uid: int, rows: list[dict] | None = None) -> dict[int, dict]:
        """Checklist with effective statuses + issues + score for every account of one user (vault snapshots,
        GitHub results and breach data included; works while the vault is locked)."""
        rows = rows if rows is not None else self._rows(uid)
        if not rows:
            return {}
        ids = [r["id"] for r in rows]
        q = ",".join("?" * len(ids))
        checks: dict[int, dict] = {}
        for c in self.db.fetchall(f"SELECT * FROM platform_checks WHERE account_id IN ({q})", tuple(ids)):
            checks.setdefault(c["account_id"], {})[c["item"]] = c
        conns = {c["account_id"]: c for c in self.db.fetchall(
            f"SELECT * FROM platform_connections WHERE account_id IN ({q})", tuple(ids))}
        email_br: dict[int, list[dict]] = {}
        for b in self.db.fetchall("SELECT eb.*, c.domain AS cdomain, c.data_classes, c.breach_date, c.title, c.flags "
                                  "FROM platform_email_breaches eb JOIN platform_emails e ON e.id=eb.email_id "
                                  "LEFT JOIN platform_breach_catalog c ON lower(c.name)=lower(eb.name) "
                                  "WHERE e.user_id=?", (uid,)):
            email_br.setdefault(b["email_id"], []).append(b)
        review_days = int(self._g("platform_review_days"))
        by_id = {r["id"]: r for r in rows}
        out: dict[int, dict] = {}
        # pass 1: own checklist
        for r in rows:
            p = self._plat(r)
            snap = json.loads(r["vault_snapshot"]) if r["vault_snapshot"] else None
            conn = conns.get(r["id"])
            gh = json.loads(conn["last_result"]) if conn and conn["last_result"] else None
            pbreaches = [b for b in self._domain_breaches(p["domains"])
                         if not b.get("spam_list") and not b.get("fabricated")]
            pw_breaches = [b for b in pbreaches if b["passwords_exposed"]]
            items = []
            for it in cat.ITEMS:
                if not cat.item_applies(it["id"], p, bool(pw_breaches)):
                    continue
                c = checks.get(r["id"], {}).get(it["id"])
                st, src, upd, note = (c["status"], c["source"], c["updated_at"], c["note"]) if c else \
                    ("unknown", None, None, None)
                ev = None
                if snap and snap.get("exists"):
                    if it["id"] == "unique_password" and snap.get("has_password"):
                        ev = ("not_done" if snap.get("reused") else "done", "vault")
                    elif it["id"] == "strong_password" and snap.get("strength") is not None:
                        ev = ("done" if snap["strength"] >= 3 else "not_done", "vault")
                    elif it["id"] == "two_factor" and snap.get("has_totp"):
                        ev = ("done", "vault")
                    elif it["id"] == "strong_two_factor" and snap.get("has_totp"):
                        ev = ("done", "vault")
                if gh and it["id"] == "two_factor" and gh.get("two_factor") is not None:
                    ev = ("done" if gh["two_factor"] else "not_done", "github")
                if gh and it["id"] == "keys_tokens_reviewed" and gh.get("old_keys"):
                    ev = ("not_done", "github")
                if it["id"] == "password_after_breach":
                    changed = _parse_ts((snap or {}).get("password_changed_at"))
                    newest = max((_parse_ts(b["breach_date"]) for b in pw_breaches if b["breach_date"]),
                                 default=None)
                    if changed and newest:
                        ev = ("done" if changed > newest else "not_done", "vault")
                if ev and st != "not_applicable":          # facts beat ticks (except "doesn't apply to me")
                    st, src = ev
                stale = False
                if it["id"] in cat.REVIEW_ITEMS and st == "done" and src == "you":
                    age = _days_since(upd)
                    stale = age is not None and age > review_days
                items.append({"id": it["id"], "label": it["label"], "weight": it["weight"], "help": it["help"],
                              "status": st, "source": src, "updated_at": upd, "note": note, "stale": stale})
            out[r["id"]] = {"platform": p, "items": items, "snap": snap, "github": gh, "conn": conn,
                            "platform_breaches": pbreaches, "pw_breaches": pw_breaches,
                            "email_breaches": email_br.get(r["email_id"], []) if r["email_id"] else []}
        # pass 2: issues (needs the other accounts' 2FA)
        def tfa(aid: int, depth: int = 0) -> str:
            a = out.get(aid)
            if not a or depth > 5:
                return "unknown"
            if a["platform"].get("sso") and by_id[aid]["sso_account_id"]:
                return tfa(by_id[aid]["sso_account_id"], depth + 1)
            it = next((i for i in a["items"] if i["id"] == "two_factor"), None)
            if it is None:
                return "none_offered" if not a["platform"]["mfa"] else "unknown"
            return it["status"]

        children: dict[int, list[int]] = {}
        for r in rows:
            for col in ("recovery_account_id", "sso_account_id"):
                if r[col] in by_id:
                    children.setdefault(r[col], []).append(r["id"])

        def radius(aid: int, seen: set) -> set:
            for ch in children.get(aid, []):
                if ch not in seen:
                    seen.add(ch)
                    radius(ch, seen)
            return seen

        for r in rows:
            a = out[r["id"]]
            p = a["platform"]
            imp = r["importance"] or p["importance"]
            sev_imp = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}[imp]
            issues: list[dict] = []
            st = {i["id"]: i for i in a["items"]}
            reach = radius(r["id"], set())

            def add(code, sev, text, fix=None):
                issues.append({"code": code, "severity": sev, "text": text, "fix": fix})

            if "two_factor" in st and st["two_factor"]["status"] != "done":
                extra = f" - it can reset {len(reach)} other account(s)" if reach else ""
                sev = "critical" if reach and imp in ("critical", "high") else sev_imp
                add("no_2fa", sev, ("Two-step verification is OFF" if st["two_factor"]["status"] == "not_done" else
                                    "Two-step verification not confirmed yet") + extra, "two_factor")
            elif "strong_two_factor" in st and st["strong_two_factor"]["status"] != "done" and \
                    st.get("two_factor", {}).get("status") == "done":
                add("sms_only", "medium" if imp in ("critical", "high") else "low",
                    "2FA may rely on SMS codes - switch to an authenticator app / passkey", "strong_two_factor")
            if p.get("sso"):
                parent = r["sso_account_id"]
                pname = cat.BY_KEY.get(p["sso"], {}).get("name", p["sso"])
                if not parent:
                    add("sso_missing", "medium" if imp in ("critical", "high") else "low",
                        f"Add your {pname} - that account protects this one")
                elif tfa(parent) == "not_done":
                    add("sso_no_2fa", sev_imp, f"Protected by {pname}, which has no two-step verification")
            if not p["mfa"] and not p.get("sso"):
                add("no_2fa_offered", "low", f"{p['name']} offers no two-step verification - a unique password is "
                                              "the only protection")
            snap = a["snap"]
            if snap and snap.get("exists"):
                if snap.get("breached"):
                    add("password_breached", "critical", "The saved password appears in known data breaches",
                        "unique_password")
                if snap.get("reused"):
                    add("password_reused", "high", "The password is also used for other accounts", "unique_password")
                if snap.get("weak"):
                    add("password_weak", "medium" if imp != "critical" else "high", "The password is weak",
                        "strong_password")
            elif snap and not snap.get("exists"):
                add("vault_link_broken", "low", "The linked vault item was deleted")
            if st.get("password_after_breach", {}).get("status") != "done" and a["pw_breaches"]:
                b = a["pw_breaches"][0]
                add("platform_breach", "high" if imp in ("critical", "high") else "medium",
                    f"{b['title']} lost passwords in a breach ({b['breach_date']}) - change the password if it is "
                    "older than that", "password_after_breach")
            hit = [b for b in a["email_breaches"] if not b["acknowledged"]]
            same_site = [b for b in hit if b["cdomain"] and self._owns(p, b["cdomain"])]
            if same_site:
                add("account_in_breach", "critical", f"Your e-mail for this account is in the {same_site[0]['title']} "
                                                     "breach of this very site - change the password now")
            elif hit:
                worst = max((bw.severity(json.loads(b["data_classes"] or "[]")) for b in hit), key=lambda s: SEV[s],
                            default="low")
                add("email_breached", "high" if worst == "high" else "medium",
                    f"The e-mail used here appears in {len(hit)} breach(es) of other sites")
            rec = r["recovery_account_id"]
            if rec and tfa(rec) == "not_done":
                rn = self._plat(by_id[rec])["name"]
                add("recovery_weak", "high", f"{rn} can reset this account but has no two-step verification")
            gh = a["github"]
            if gh and gh.get("old_keys"):
                add("old_ssh_keys", "medium", f"{gh['old_keys']} SSH key(s) older than a year on GitHub",
                    "keys_tokens_reviewed")
            stale = [i for i in a["items"] if i["stale"]]
            age = _days_since(r["last_reviewed_at"]) if r["last_reviewed_at"] else None
            if stale or (age is not None and age > review_days):
                add("review_due", "low", f"Security review is due (last {age if age is not None else '?'} days ago)")
            elif r["last_reviewed_at"] is None and (_days_since(r["created_at"]) or 0) >= 7:
                add("never_reviewed", "low", "Go through this account's security page once and press 'Reviewed'")
            # score
            total = sum(i["weight"] for i in a["items"] if i["status"] != "not_applicable")
            got = sum(i["weight"] * (0.5 if i["stale"] else 1) for i in a["items"] if i["status"] == "done")
            base = 100 * got / total if total else (100 if p.get("sso") else 70)
            pen = sum(ISSUE_POINTS[i["severity"]] for i in issues)
            score = round(base * 100 / (100 + pen))
            if any(i["severity"] == "critical" for i in issues):
                score = min(score, 49)
            elif any(i["severity"] == "high" for i in issues):
                score = min(score, 84)
            issues.sort(key=lambda i: -SEV[i["severity"]])
            a.update(issues=issues, score=score, importance=imp, two_factor=tfa(r["id"]),
                     recovers=sorted(reach), done=sum(1 for i in a["items"] if i["status"] == "done"),
                     applicable=sum(1 for i in a["items"] if i["status"] != "not_applicable"))
        return out

    def _public(self, r: dict, a: dict, detail: bool = False) -> dict:
        s = self._secret(r)
        p = a["platform"]
        out = {"id": r["id"], "platform": r["platform"], "name": p["name"], "category": p["category"],
               "category_label": cat.CATEGORIES.get(p["category"]), "label": r["label"],
               "importance": a["importance"], "importance_set": r["importance"] is not None,
               "handle": (s or {}).get("handle"), "email": (s or {}).get("email"),
               "phone_last4": (s or {}).get("phone_last4"), "damaged": s is None,
               "score": a["score"], "two_factor": a["two_factor"], "issues": a["issues"][:3] if not detail else
               a["issues"], "issue_count": len(a["issues"]),
               "worst": a["issues"][0]["severity"] if a["issues"] else None,
               "checklist_done": a["done"], "checklist_total": a["applicable"],
               "recovery_account_id": r["recovery_account_id"], "sso_account_id": r["sso_account_id"],
               "can_reset": len(a["recovers"]), "vault_linked": bool(r["vault_item_id"]),
               "github_connected": bool(a["conn"]), "last_reviewed_at": r["last_reviewed_at"],
               "created_at": r["created_at"], "updated_at": r["updated_at"],
               "security_url": p["links"].get("security"), "where": p["where"],
               "custom_domain": r["custom_domain"]}
        if detail:
            out.update(notes=(s or {}).get("notes"), checklist=a["items"], platform_info=cat.public(p)
                       if r["platform"] != "custom" else {"name": p["name"], "domains": list(p["domains"])},
                       platform_breaches=a["platform_breaches"][:10],
                       email_breaches=[{"name": b["name"], "title": b["title"] or b["name"], "breach_date":
                                        b["breach_date"], "acknowledged": bool(b["acknowledged"])}
                                       for b in a["email_breaches"]],
                       vault=a["snap"], vault_item_id=r["vault_item_id"], github=self._conn_public(a["conn"]),
                       recovers_ids=a["recovers"], email_id=r["email_id"])
        return out

    # ================================================================== listing
    def list_accounts(self, cu, category: str | None = None, q: str | None = None,
                      issue: str | None = None) -> dict:
        uid = cu.user["id"]
        view = self._vault_view(cu)
        if view is not None:
            self.refresh_vault(cu, view)
        rows = self._rows(uid)
        info = self._analyze(uid, rows)
        items = []
        qq = (q or "").strip().lower()
        for r in rows:
            pub = self._public(r, info[r["id"]])
            if category and pub["category"] != category:
                continue
            if issue and not any(i["code"] == issue for i in info[r["id"]]["issues"]):
                continue
            if qq and qq not in " ".join(str(pub.get(k) or "") for k in ("name", "label", "handle", "email",
                                                                         "platform")).lower():
                continue
            items.append(pub)
        imp_order = {k: i for i, k in enumerate(cat.IMPORTANCE)}
        items.sort(key=lambda x: (-SEV.get(x["worst"] or "info", 0), imp_order[x["importance"]], x["name"].lower()))
        return {"total": len(items), "items": items, "vault_unlocked": view is not None,
                "overview": self._overview(uid, rows, info)}

    def get_account(self, cu, aid: int) -> dict:
        view = self._vault_view(cu)
        if view is not None:
            self.refresh_vault(cu, view)
        r = self._row(cu, aid)
        info = self._analyze(cu.user["id"])
        return {"account": self._public(r, info[aid], detail=True), "vault_unlocked": view is not None}

    def _overview(self, uid: int, rows: list[dict], info: dict) -> dict:
        if not rows:
            return {"score": None, "accounts": 0, "grade": "No accounts yet", "two_fa": {}, "issues": {}}
        wsum = sum(cat.IMPORTANCE_WEIGHT[info[r["id"]]["importance"]] for r in rows)
        score = round(sum(info[r["id"]]["score"] * cat.IMPORTANCE_WEIGHT[info[r["id"]]["importance"]]
                          for r in rows) / wsum)
        all_issues = [i for r in rows for i in info[r["id"]]["issues"]]
        if any(i["severity"] == "critical" for i in all_issues):
            score = min(score, 49)
        elif any(i["severity"] == "high" for i in all_issues):
            score = min(score, 84)
        tf = {"done": 0, "not_done": 0, "unknown": 0, "none_offered": 0, "not_applicable": 0}
        for r in rows:
            tf[info[r["id"]]["two_factor"]] = tf.get(info[r["id"]]["two_factor"], 0) + 1
        offered = tf["done"] + tf["not_done"] + tf["unknown"]
        by_sev = {s: 0 for s in SEVERITIES}
        for i in all_issues:
            by_sev[i["severity"]] += 1
        grade = ("Excellent" if score >= 90 else "Good" if score >= 75 else "Needs attention" if score >= 50 else
                 "At risk")
        return {"score": score, "grade": grade, "accounts": len(rows), "two_fa": tf,
                "two_fa_coverage": round(100 * tf["done"] / offered) if offered else None, "issues": by_sev,
                "critical_without_2fa": sum(1 for r in rows if info[r["id"]]["importance"] == "critical"
                                            and info[r["id"]]["two_factor"] in ("not_done", "unknown")
                                            and info[r["id"]]["platform"]["mfa"])}

    def recovery_graph(self, cu) -> dict:
        uid = cu.user["id"]
        rows = self._rows(uid)
        info = self._analyze(uid, rows)
        nodes = [{"id": r["id"], "name": info[r["id"]]["platform"]["name"], "label": r["label"],
                  "platform": r["platform"], "importance": info[r["id"]]["importance"],
                  "two_factor": info[r["id"]]["two_factor"], "score": info[r["id"]]["score"],
                  "can_reset": len(info[r["id"]]["recovers"])} for r in rows]
        edges = []
        for r in rows:
            if r["recovery_account_id"]:
                edges.append({"from": r["recovery_account_id"], "to": r["id"], "kind": "recovers"})
            if r["sso_account_id"]:
                edges.append({"from": r["sso_account_id"], "to": r["id"], "kind": "signs_in"})
        hubs = sorted((n for n in nodes if n["can_reset"]), key=lambda n: -n["can_reset"])
        return {"nodes": nodes, "edges": edges, "hubs": hubs,
                "weak_hubs": [n for n in hubs if n["two_factor"] != "done"]}

    # ================================================================== discovery
    def discover(self, cu, sources: list[str] | None = None, create: bool = False,
                 keys: list[str] | None = None) -> dict:
        sources = sources or ["vault", "apps"]
        uid = cu.user["id"]
        have = {r["platform"] for r in self._rows(uid)}
        found: dict[str, dict] = {}
        locked = False
        if "vault" in sources:
            view = self._vault_view(cu)
            if view is None:
                locked = True
            else:
                for it in view.values():
                    host = it.get("host") or ""
                    if not host:
                        continue
                    p = None
                    for cand in cat.PLATFORMS:
                        if not cand.get("sso") and self._owns(cand, host):
                            p = cand
                            break
                    if not p:
                        continue
                    f = found.setdefault(p["key"], {"platform": p["key"], "name": p["name"], "from": set(),
                                                    "vault_items": [], "registered": p["key"] in have})
                    f["from"].add("vault")
                    f["vault_items"].append({"item_id": it["id"], "title": it["title"], "username": it.get("username")})
        if "apps" in sources:
            for key in self._running_apps():
                p = cat.BY_KEY[key]
                f = found.setdefault(key, {"platform": key, "name": p["name"], "from": set(), "vault_items": [],
                                           "registered": key in have})
                f["from"].add("apps")
        items = []
        for f in found.values():
            f["from"] = sorted(f["from"])
            items.append(f)
        items.sort(key=lambda x: (x["registered"], x["name"]))
        created = []
        if create:
            for f in items:
                if f["registered"] or (keys and f["platform"] not in keys):
                    continue
                vi = f["vault_items"][0] if f["vault_items"] else None
                data = {"vault_item_id": vi["item_id"]} if vi else {}
                if vi and vi.get("username"):
                    data["email" if "@" in vi["username"] else "handle"] = vi["username"]
                try:
                    created.append(self.add_account(cu, f["platform"], data)["account"]["id"])
                except PlatformError as e:
                    if e.status != 409:
                        raise
        return {"items": items, "vault_locked": locked, "created": created}

    @staticmethod
    def _running_apps() -> set[str]:
        import psutil
        out = set()
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").lower().removesuffix(".exe")
            if n in APPS:
                out.add(APPS[n])
        return out

    # ================================================================== link / sender check
    def check_link(self, cu, value: str, platform: str | None = None, deep: bool = False) -> dict:
        if platform and platform not in cat.BY_KEY:
            raise PlatformError(422, "Unknown platform")
        try:
            c = ioc.classify(value)
        except ioc.IOCError as e:
            raise PlatformError(422, str(e))
        if c["type"] not in ("url", "domain", "email"):
            raise PlatformError(422, "Paste a link, a web address or the sender's e-mail address")
        host = c.get("host") if c["type"] == "url" else c["domain"] if c["type"] == "email" else c["value"]
        reg = ioc.registrable(host) if not c.get("ip") else host
        claimed = cat.BY_KEY.get(platform) if platform else None
        owner = None
        for p in cat.PLATFORMS:
            if not p.get("sso") and self._owns(p, host):
                owner = p
                break
        official = self._owns(claimed, host) if claimed else (owner is not None)
        if self.intel is not None:
            from .threat_intel import IntelError
            try:
                rep = self.intel.check(cu, value, None, deep, False)
            except IntelError as e:
                raise PlatformError(e.status, e.message)
            verdict, score = rep["verdict"], rep["score"]
            reasons = list(rep["reasons"])
            phish = rep.get("phishing") or {}
            matches = len(rep["matches"])
        else:
            phish = ph.analyze_url(value)
            score = phish["score"]
            verdict = "malicious" if score >= 80 else "suspicious" if score >= 50 else "low_risk" if score >= 25 \
                else "clean"
            reasons = [f["text"] for f in phish["findings"] if f["points"] >= 15]
            rep, matches = None, 0
        out_reasons = []
        if claimed:
            if official:
                out_reasons.append(f"{host} is one of {claimed['name']}'s official addresses")
            else:
                out_reasons.append(f"{host} is NOT one of {claimed['name']}'s addresses "
                                   f"({', '.join(claimed['domains'][:4])})")
                looks = claimed["brand"] in (phish.get("brands") or []) or any(
                    f["code"].startswith(("typosquat", "lookalike", "homoglyph", "brand")) for f in
                    phish.get("findings") or [])
                if looks:
                    score = max(score, 85)
                elif score < 50:
                    score = max(score, 50)
        elif owner:
            out_reasons.append(f"Official address of {owner['name']}")
        verdict = ("malicious" if score >= 80 else "suspicious" if score >= 50 else "low_risk" if score >= 25
                   else verdict if verdict in ("clean", "unknown") else "clean")
        advice = []
        if verdict in ("malicious", "suspicious"):
            advice = ["Don't open it and don't type any password or code there.",
                      "If you already did: change that password now and sign out other sessions.",
                      f"Report it to {(claimed or owner or {}).get('name', 'the platform')} and delete the message."]
        elif official:
            advice = ["The address is genuine - still, open the app or type the address yourself instead of "
                      "following links in messages."]
        else:
            advice = ["Nothing bad is known - but treat unexpected links asking you to sign in with care."]
        if c["type"] == "email" and not official and claimed:
            advice.insert(0, f"Real {claimed['name']} e-mails come from {', '.join(claimed['domains'][:3])}.")
        return {"value": c.get("display") or c["value"], "kind": c["type"], "host": host, "registrable": reg,
                "claimed_platform": claimed["key"] if claimed else None,
                "owner_platform": owner["key"] if owner else None, "official": official if (claimed or owner)
                else None, "verdict": verdict, "score": int(score),
                "summary": (out_reasons + reasons)[0] if (out_reasons + reasons) else "Nothing known about this "
                                                                                     "address",
                "reasons": list(dict.fromkeys(out_reasons + reasons)), "advice": advice, "feed_matches": matches,
                "intel": {k: rep[k] for k in ("verdict", "score", "matches", "phishing", "page")} if rep else None,
                "engine": "threat_intel" if rep else "phishing_only"}

    # ================================================================== e-mail breach monitoring
    def _email_pub(self, e: dict, reveal: bool = False) -> dict:
        br = self.db.fetchall("SELECT eb.name, eb.acknowledged, eb.first_seen_at, eb.provider, c.title, c.breach_date, "
                              "c.data_classes, c.domain, c.flags FROM platform_email_breaches eb LEFT JOIN "
                              "platform_breach_catalog c ON lower(c.name)=lower(eb.name) WHERE eb.email_id=? "
                              "ORDER BY c.breach_date DESC", (e["id"],))
        accts = self.db.fetchall("SELECT id, platform FROM platform_accounts WHERE email_id=?", (e["id"],))
        out = {"id": e["id"], "masked": e["masked"], "domain": e["domain"], "monitor": bool(e["monitor"]),
               "source": e["source"], "created_at": e["created_at"], "last_checked_at": e["last_checked_at"],
               "last_provider": e["last_provider"], "last_error": e["last_error"], "breach_count": len(br),
               "unacknowledged": sum(1 for b in br if not b["acknowledged"]),
               "accounts": [{"id": a["id"], "platform": a["platform"], "name": cat.get(a["platform"])["name"]}
                            for a in accts],
               "breaches": []}
        for b in br:
            classes = json.loads(b["data_classes"] or "[]")
            flags = json.loads(b["flags"] or "{}")
            out["breaches"].append({"name": b["name"], "title": b["title"] or b["name"], "domain": b["domain"],
                                    "breach_date": b["breach_date"], "data_classes": classes,
                                    "severity": bw.severity(classes, flags.get("stealer_log")) if classes else "low",
                                    "passwords_exposed": bw.has_secrets(classes), "found_at": b["first_seen_at"],
                                    "provider": b["provider"], "acknowledged": bool(b["acknowledged"]),
                                    "advice": bw.advice(classes, flags.get("stealer_log")),
                                    "your_accounts_there": [a["id"] for a in out["accounts"]
                                                            if b["domain"] and self._owns(cat.get(a["platform"]),
                                                                                          b["domain"])]})
        out["worst"] = max((b["severity"] for b in out["breaches"] if not b["acknowledged"]), key=lambda s: SEV[s],
                           default=None)
        if reveal:
            out["email"] = self._email_of(e)
        return out

    def emails(self, cu) -> dict:
        rows = self.db.fetchall("SELECT * FROM platform_emails WHERE user_id=? ORDER BY id", (cu.user["id"],))
        mode = self._g("platform_breach_check")
        return {"items": [self._email_pub(e) for e in rows], "mode": mode, "providers": self.providers(),
                "attribution": bw.ATTRIBUTION, "job": self._running_job()}

    def email(self, cu, eid: int, reveal: bool = False) -> dict:
        return self._email_pub(self._email_row(cu, eid), reveal)

    def _email_row(self, cu, eid: int) -> dict:
        e = self.db.fetchone("SELECT * FROM platform_emails WHERE id=? AND user_id=?", (eid, cu.user["id"]))
        if not e:
            raise PlatformError(404, "E-mail address not found")
        return e

    def add_email(self, cu, email: str, monitor: bool = True) -> dict:
        try:
            e = bw.normalize_email(email)
        except bw.BreachError as ex:
            raise PlatformError(ex.status, ex.message)
        uid = cu.user["id"]
        existed = self.db.fetchone("SELECT id FROM platform_emails WHERE user_id=? AND fp=?", (uid, self._fp(e)))
        eid = self._ensure_email(uid, e, "manual", monitor)
        if existed:
            self.db.execute("UPDATE platform_emails SET monitor=? WHERE id=?", (int(monitor), eid))
        return self._email_pub(self._email_row(cu, eid)) | {"existing": bool(existed)}

    def update_email(self, cu, eid: int, monitor: bool) -> dict:
        self._email_row(cu, eid)
        self.db.execute("UPDATE platform_emails SET monitor=? WHERE id=?", (int(monitor), eid))
        return self.email(cu, eid)

    def delete_email(self, cu, eid: int) -> dict:
        self._email_row(cu, eid)
        self.db.execute("UPDATE platform_accounts SET email_id=NULL WHERE email_id=?", (eid,))
        self.db.execute("DELETE FROM platform_emails WHERE id=?", (eid,))
        return {"deleted": True}

    def suggest_emails(self, cu) -> dict:
        """The Cyber Hub sign-in e-mail (Part 2) if it isn't monitored yet."""
        em = cu.user.get("email")
        out = []
        if em:
            try:
                e = bw.normalize_email(em)
                if not self.db.fetchone("SELECT 1 FROM platform_emails WHERE user_id=? AND fp=?",
                                        (cu.user["id"], self._fp(e))):
                    out.append({"email": e, "masked": bw.mask_email(e), "from": "Your Cyber Hub account"})
            except bw.BreachError:
                pass
        return {"items": out}

    def acknowledge_breaches(self, cu, eid: int, names: list[str] | None = None) -> dict:
        self._email_row(cu, eid)
        if names:
            n = sum(self.db.execute("UPDATE platform_email_breaches SET acknowledged=1 WHERE email_id=? AND name=?",
                                    (eid, x)).rowcount for x in names)
        else:
            n = self.db.execute("UPDATE platform_email_breaches SET acknowledged=1 WHERE email_id=?", (eid,)).rowcount
        return {"acknowledged": n}

    # ---- providers / key
    def _hibp_key(self) -> str | None:
        r = self.db.fetchone("SELECT wrapped FROM platform_api_keys WHERE provider='hibp'")
        if not r or self.vault is None or not self.vault.available:
            return None
        try:
            return self.vault.unwrap_key(r["wrapped"], "platform:hibp").decode()
        except Exception:
            log.warning("Stored HIBP key can't be decrypted")
            return None

    def providers(self) -> dict:
        r = self.db.fetchone("SELECT hint, updated_at FROM platform_api_keys WHERE provider='hibp'")
        sel = list(self._g("platform_breach_providers"))
        return {"xposedornot": {"label": bw.PROVIDER_LABELS["xposedornot"], "ready": True, "needs_key": False,
                                "selected": "xposedornot" in sel, "home": bw.ATTRIBUTION["xposedornot"]},
                "hibp": {"label": bw.PROVIDER_LABELS["hibp"], "ready": bool(r) and self._hibp_key() is not None,
                         "needs_key": True, "key_hint": r["hint"] if r else None,
                         "updated_at": r["updated_at"] if r else None, "selected": "hibp" in sel,
                         "get_key": bw.HIBP_KEY_URL, "home": bw.ATTRIBUTION["hibp"]},
                "order": [p for p in ("hibp", "xposedornot") if p in sel], "mode": self._g("platform_breach_check")}

    def set_key(self, cu, provider: str, key: str | None) -> dict:
        self._need_admin(cu, "change API keys")
        if provider != "hibp":
            raise PlatformError(422, "Only the Have I Been Pwned key is stored here (XposedOrNot needs none)")
        if not key:
            self.db.execute("DELETE FROM platform_api_keys WHERE provider='hibp'")
            self.activity.record("settings", "Have I Been Pwned API key removed", severity="low", source="platforms")
            return self.providers()
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z0-9]{32}", key):
            raise PlatformError(422, "A Have I Been Pwned API key is 32 letters / digits")
        if self.vault is None or not self.vault.available:
            raise PlatformError(503, "The key store is unavailable (vault key missing)")
        self.db.execute("INSERT INTO platform_api_keys(provider, wrapped, hint, updated_at, updated_by) VALUES "
                        "('hibp',?,?,?,?) ON CONFLICT(provider) DO UPDATE SET wrapped=excluded.wrapped, "
                        "hint=excluded.hint, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                        (self.vault.wrap_key(key.encode(), "platform:hibp"), "…" + key[-4:], _now(),
                         cu.user["username"] if cu else "system"))
        self.activity.record("settings", "Have I Been Pwned API key saved", severity="low", source="platforms")
        return self.providers()

    # ---- jobs
    def _running_job(self) -> dict | None:
        with self._lock:
            j = next((j for j in self._jobs.values() if j.status == "running"), None)
            return j.public() if j else None

    def check_emails(self, cu, ids: list[int] | None = None, background: bool = True) -> dict:
        mode = self._g("platform_breach_check")
        if mode == "off":
            raise PlatformError(403, "E-mail breach checks are switched off in Settings (platform_breach_check)")
        order = self.providers()["order"]
        if not order:
            raise PlatformError(409, "Choose a breach provider in Settings (platform_breach_providers)")
        if order == ["hibp"] and not self._hibp_key():
            raise PlatformError(409, "Add a Have I Been Pwned API key, or select XposedOrNot (free)")
        if cu is not None:
            rows = self.db.fetchall("SELECT id FROM platform_emails WHERE user_id=?" + (
                f" AND id IN ({','.join('?' * len(ids))})" if ids else ""), (cu.user["id"],) + tuple(ids or ()))
            if ids and len(rows) != len(set(ids)):
                raise PlatformError(404, "E-mail address not found")
        else:
            rows = [{"id": i} for i in ids or []]
        if not rows:
            raise PlatformError(422, "Add an e-mail address to check first")
        with self._lock:
            if self._running_job():
                raise PlatformError(409, "A breach check is already running")
            job = _Job("breach_check", cu.user["username"] if cu else "auto", [r["id"] for r in rows])
            self._jobs[job.id] = job
            for old in [k for k, j in self._jobs.items() if j.status != "running"][:-20]:
                self._jobs.pop(old, None)
            self._stopping.clear()
        if background:
            self._thread = threading.Thread(target=self._run_check, args=(job,), daemon=True,
                                            name="platform-breach-check")
            self._thread.start()
        else:
            self._run_check(job)
        return job.public()

    def job(self, job_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if not j:
            raise PlatformError(404, "Job not found")
        return j.public()

    def wait(self, job_id: str, timeout: float = 60) -> dict:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            j = self.job(job_id)
            if j["status"] != "running":
                return j
            time.sleep(0.05)
        return self.job(job_id)

    def _run_check(self, job: _Job) -> None:
        try:
            for eid in job.email_ids:
                if self._stopping.is_set():
                    job.status = "cancelled"
                    break
                e = self.db.fetchone("SELECT * FROM platform_emails WHERE id=?", (eid,))
                if e:
                    try:
                        res = self._check_one(e)
                        job.result["checked"] += 1
                        job.result["breached"] += int(res["total"] > 0)
                        job.result["new_breaches"] += len(res["new"])
                    except PlatformError as ex:
                        job.result["errors"][e["masked"]] = ex.message
                        self.db.execute("UPDATE platform_emails SET last_error=? WHERE id=?", (ex.message, eid))
                        if ex.status == 409:                 # key refused -> no point trying the others
                            break
                job.progress["done"] += 1
                job.progress["percent"] = round(100 * job.progress["done"] / max(1, job.progress["total"]))
            if job.status == "running":
                job.status = "done" if not job.result["errors"] or job.result["checked"] else "failed"
                if job.status == "failed":
                    job.error = next(iter(job.result["errors"].values()))
        except Exception as ex:                                          # pragma: no cover
            log.exception("Breach check failed")
            job.status, job.error = "failed", str(ex)
        finally:
            job.finished_at = _now()

    def _check_one(self, e: dict) -> dict:
        email = self._email_of(e)
        if not email:
            raise PlatformError(409, "This address failed its integrity check - remove and add it again")
        order = self.providers()["order"]
        key = self._hibp_key()
        provider = "hibp" if "hibp" in order and key else "xposedornot" if "xposedornot" in order else None
        if provider is None:
            raise PlatformError(409, "No breach provider is ready")
        details: list[dict] = []
        try:
            if provider == "hibp":
                st, body, hdr = self._http("GET", bw.hibp_url(email), {"hibp-api-key": key,
                                                                      "Accept": "application/json"}, "hibp")
                details = bw.parse_hibp_account(st, body, hdr)
                names = [d["name"] for d in details]
            else:
                st, body, _h = self._http("GET", bw.xon_url(email), {"Accept": "application/json"}, "xposedornot")
                names = bw.parse_xon(st, body)
        except bw.BreachError as ex:
            raise PlatformError(ex.status, ex.message, ex.retry_after)
        self.stats["emails_checked"] += 1
        for d in details:
            self._upsert_catalog([d], quiet=True)
        canon = []
        for n in names:                                                  # XposedOrNot names -> HIBP catalog names
            r = self.db.fetchone("SELECT name FROM platform_breach_catalog WHERE lower(name)=lower(?) OR "
                                 "lower(title)=lower(?) OR lower(replace(title,' ',''))=lower(replace(?,' ',''))",
                                 (n, n, n))
            canon.append(r["name"] if r else n)
        names = sorted(set(canon), key=str.lower)
        old = {r["name"] for r in self.db.fetchall("SELECT name FROM platform_email_breaches WHERE email_id=?",
                                                   (e["id"],))}
        new = [n for n in names if n not in old]
        for n in new:
            self.db.execute("INSERT OR IGNORE INTO platform_email_breaches(email_id, name, provider, first_seen_at) "
                            "VALUES (?,?,?,?)", (e["id"], n, provider, _now()))
        self.db.execute("UPDATE platform_emails SET last_checked_at=?, last_provider=?, last_error=NULL WHERE id=?",
                        (_now(), provider, e["id"]))
        if new and self._g("platform_alert_breaches"):
            rows = [self.db.fetchone("SELECT * FROM platform_breach_catalog WHERE name=?", (n,)) for n in new]
            classes = [c for r in rows if r for c in json.loads(r["data_classes"] or "[]")]
            sev = max((bw.severity(json.loads(r["data_classes"] or "[]"),
                                   json.loads(r["flags"] or "{}").get("stealer_log")) for r in rows if r),
                      key=lambda s: SEV[s], default="medium")
            first = e["last_checked_at"] is None
            titles = [(r["title"] if r else n) for r, n in zip(rows, new)]
            title = (f"{e['masked']} found in {len(new)} data breach(es)" if first else
                     f"New data breach for {e['masked']}: {', '.join(titles[:3])}")
            self._event("email_breach", sev, title, ", ".join(titles[:10]) + (" ..." if len(titles) > 10 else ""),
                        {"email_id": e["id"], "breaches": new[:50], "advice": bw.advice(classes),
                         "fix": {"endpoint": f"GET /api/platforms/emails/{e['id']}"}}, uid=e["user_id"])
        return {"total": len(names), "new": new}

    # ================================================================== breach catalog (public, no personal data)
    def catalog_status(self) -> dict:
        n = self.db.fetchone("SELECT COUNT(*) AS n FROM platform_breach_catalog")["n"]
        return {"breaches": n, "updated_at": self._state("catalog_ok_at"), "checked_at": self._state("catalog_at"),
                "error": self._state("catalog_error"), "source": bw.HIBP_CATALOG_URL, "attribution": bw.ATTRIBUTION,
                "auto_update": bool(self._g("platform_catalog_auto_update"))}

    def refresh_catalog(self, force: bool = False) -> dict:
        hdr = {"Accept": "application/json"}
        etag = self._state("catalog_etag")
        if etag and not force:
            hdr["If-None-Match"] = etag
        self._state("catalog_at", _now())
        try:
            st, body, h = self._http("GET", bw.HIBP_CATALOG_URL, hdr, "hibp_catalog")
            if st == 304:
                self._state("catalog_ok_at", _now())
                return self.catalog_status() | {"changed": False, "added": 0}
            rows = bw.parse_catalog(st, body)
        except (PlatformError, bw.BreachError) as ex:
            msg = ex.message
            self._state("catalog_error", msg)
            self._event("catalog_error", "low", "Breach list update failed", msg,
                        ref=f"catalog_error:{_now()[:10]}")
            raise PlatformError(ex.status if ex.status != 429 else 502, msg)
        self._state("catalog_etag", h.get("etag"))
        added = self._upsert_catalog(rows)
        self._state("catalog_ok_at", _now())
        self._state("catalog_error", None)
        self.stats["catalog_updates"] += 1
        return self.catalog_status() | {"changed": True, "added": len(added)}

    def _upsert_catalog(self, rows: list[dict], quiet: bool = False) -> list[dict]:
        baseline = self._state("catalog_baseline")
        known = {r["name"] for r in self.db.fetchall("SELECT name FROM platform_breach_catalog")}
        added = []
        with self.db.tx() as c:
            for b in rows:
                flags = {k: b[k] for k in ("verified", "sensitive", "spam_list", "malware", "stealer_log",
                                           "fabricated", "retired")}
                c.execute("INSERT INTO platform_breach_catalog(name, title, domain, breach_date, added_date, pwn_count, "
                          "data_classes, description, flags, first_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
                          "ON CONFLICT(name) DO UPDATE SET title=excluded.title, domain=excluded.domain, "
                          "breach_date=excluded.breach_date, added_date=excluded.added_date, pwn_count=excluded.pwn_count, "
                          "data_classes=excluded.data_classes, description=excluded.description, flags=excluded.flags",
                          (b["name"], b["title"], b["domain"], b["breach_date"], b["added_date"], b["pwn_count"],
                           json.dumps(b["data_classes"]), b["description"], json.dumps(flags), _now()))
                if b["name"] not in known:
                    added.append(b)
        if quiet:
            return added
        if not baseline:
            self._state("catalog_baseline", _now())
            recent = _ago(24 * 30)
            alert = [b for b in added if (b["added_date"] or "") >= recent[:19]]
        else:
            alert = added
        self._platform_breach_alerts(alert)
        return added

    def _platform_breach_alerts(self, breaches: list[dict]) -> int:
        if not breaches or not self._g("platform_alert_breaches"):
            return 0
        n = 0
        rows = self.db.fetchall("SELECT * FROM platform_accounts")
        for b in breaches:
            if not b["domain"] or b.get("spam_list") or b.get("fabricated"):
                continue
            for r in rows:
                p = self._plat(r)
                if not self._owns(p, b["domain"]):
                    continue
                sev = bw.severity(b["data_classes"], b.get("stealer_log"))
                if self._event("platform_breach", sev, f"{b['title']} was breached - you have an account there",
                               f"{b['breach_date'] or ''}: {', '.join(b['data_classes'][:6])}",
                               {"breach": b["name"], "account_id": r["id"], "advice": bw.advice(b["data_classes"]),
                                "fix": {"endpoint": f"GET /api/platforms/accounts/{r['id']}"}},
                               ref=f"pbreach:{r['user_id']}:{r['id']}:{b['name']}", uid=r["user_id"],
                               account_id=r["id"]):
                    n += 1
        return n

    def breaches(self, q: str | None = None, domain: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        where, params = [], []
        if q:
            where.append("(name LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\')")
            like = "%" + re.sub(r"([%_\\])", r"\\\1", q.strip()) + "%"
            params += [like, like, like]
        if domain:
            where.append("domain=?")
            params.append(ioc.registrable(domain.strip().lower()))
        sql = "FROM platform_breach_catalog" + (" WHERE " + " AND ".join(where) if where else "")
        total = self.db.fetchone("SELECT COUNT(*) AS n " + sql, tuple(params))["n"]
        rows = self.db.fetchall("SELECT * " + sql + " ORDER BY added_date DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        return {"total": total, "items": [self._breach_public(r) for r in rows], "attribution": bw.ATTRIBUTION}

    # ================================================================== GitHub connection (read-only token)
    def _conn_public(self, c: dict | None) -> dict | None:
        if not c:
            return None
        res = json.loads(c["last_result"]) if c["last_result"] else None
        return {"provider": c["provider"], "key_hint": c["hint"], "scopes": json.loads(c["scopes"] or "null"),
                "last_sync_at": c["last_sync_at"], "last_error": c["last_error"], "result": res,
                "created_at": c["created_at"]}

    def connect_github(self, cu, aid: int, token: str, allow_broad: bool = False) -> dict:
        r = self._row(cu, aid)
        if r["platform"] != "github":
            raise PlatformError(422, "Only GitHub accounts can be connected with a token")
        token = (token or "").strip()
        if not GITHUB_TOKEN.match(token):
            raise PlatformError(422, "That doesn't look like a GitHub token (ghp_... or github_pat_...). "
                                + GITHUB_TOKEN_HELP)
        res, scopes = self._github_fetch(token)
        broad = sorted(set(scopes or []) & GITHUB_BROAD)
        if broad and not allow_broad:
            raise PlatformError(422, f"This token can change things ({', '.join(broad)}) - Cyber Hub only needs to "
                                     f"read. {GITHUB_TOKEN_HELP}")
        if self.vault is None or not self.vault.available:
            raise PlatformError(503, "The key store is unavailable (vault key missing)")
        wrapped = self.vault.wrap_key(token.encode(), f"platform:github:{aid}")
        self.db.execute("INSERT INTO platform_connections(account_id, provider, wrapped, hint, scopes, created_at) "
                        "VALUES (?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET wrapped=excluded.wrapped, "
                        "hint=excluded.hint, scopes=excluded.scopes", (aid, "github", wrapped, "…" + token[-4:],
                                                                       json.dumps(scopes), _now()))
        self._store_github(r, res)
        s = self._secret(r) or {}
        if not s.get("handle") and res.get("login"):
            self.update_account(cu, aid, {"handle": res["login"]})
        self.activity.record("platform", "GitHub account connected (read-only)", res.get("login"), severity="info",
                             source="platforms")
        out = self.get_account(cu, aid)
        out["warnings"] = [f"Token has write scopes: {', '.join(broad)}"] if broad else []
        return out

    def disconnect(self, cu, aid: int) -> dict:
        self._row(cu, aid)
        self.db.execute("DELETE FROM platform_connections WHERE account_id=?", (aid,))
        return self.get_account(cu, aid)

    def _github_fetch(self, token: str) -> tuple[dict, list[str] | None]:
        hdr = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
        st, body, h = self._http("GET", GITHUB_API + "/user", hdr, "github")
        if st == 401:
            raise PlatformError(422, "GitHub refused the token (wrong, expired or revoked)")
        if st == 403 and h.get("x-ratelimit-remaining") == "0":
            raise PlatformError(429, "GitHub rate limit - try again later", 600)
        if st != 200:
            raise PlatformError(502, f"GitHub answered HTTP {st}")
        try:
            u = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise PlatformError(502, "GitHub sent an answer Cyber Hub can't read")
        scopes = [s.strip() for s in h["x-oauth-scopes"].split(",") if s.strip()] if "x-oauth-scopes" in h else None
        res: dict[str, Any] = {"login": u.get("login"), "two_factor": u.get("two_factor_authentication"),
                               "created_at": u.get("created_at"), "public_repos": u.get("public_repos"),
                               "plan": (u.get("plan") or {}).get("name"), "token_type": "classic" if scopes is not None
                               else "fine-grained", "synced_at": _now()}
        if not isinstance(res["two_factor"], bool):
            res["two_factor"] = None
            res["two_factor_note"] = "The token can't see the 2FA setting - classic tokens need 'read:user'"
        st, body, _h = self._http("GET", GITHUB_API + "/user/keys?per_page=100", hdr, "github")
        if st == 200:
            try:
                keys = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                keys = []
            ks = []
            for k in keys if isinstance(keys, list) else []:
                age = _days_since(k.get("created_at"))
                ks.append({"id": k.get("id"), "title": str(k.get("title") or "")[:100], "created_at": k.get("created_at"),
                           "age_days": age, "last_used": k.get("last_used"), "read_only": k.get("read_only"),
                           "old": age is not None and age > OLD_KEY_DAYS})
            res["ssh_keys"] = ks
            res["old_keys"] = sum(1 for k in ks if k["old"])
        else:
            res["ssh_keys"] = None
            res["old_keys"] = 0
            res["ssh_keys_note"] = "The token can't list SSH keys - classic tokens need 'read:public_key'"
        return res, scopes

    def _store_github(self, r: dict, res: dict | None, error: str | None = None) -> None:
        self.db.execute("UPDATE platform_connections SET last_sync_at=?, last_result=COALESCE(?, last_result), "
                        "last_error=? WHERE account_id=?", (_now(), json.dumps(res) if res else None, error, r["id"]))
        if not res:
            return
        self.stats["github_syncs"] += 1
        uid = r["user_id"]
        if res.get("two_factor") is False:
            self._event("github_2fa_off", "critical", f"GitHub {res.get('login')}: two-factor authentication is OFF",
                        "Anyone with your password can push code as you", {"account_id": r["id"],
                                                                            "url": cat.BY_KEY["github"]["links"][
                                                                                "security"]},
                        ref=f"gh2fa:{r['id']}:{_now()[:10]}", uid=uid, account_id=r["id"])
        if res.get("old_keys"):
            self._event("github_old_keys", "medium", f"GitHub {res.get('login')}: {res['old_keys']} SSH key(s) older "
                                                     "than a year", "Remove keys from machines you no longer use",
                        {"account_id": r["id"], "url": cat.BY_KEY["github"]["links"]["keys"]},
                        ref=f"ghkeys:{r['id']}:{_now()[:7]}", uid=uid, account_id=r["id"])

    def sync_github(self, cu, aid: int) -> dict:
        r = self._row(cu, aid)
        self._sync_conn(r)
        return self.get_account(cu, aid)

    def _sync_conn(self, r: dict) -> None:
        c = self.db.fetchone("SELECT * FROM platform_connections WHERE account_id=?", (r["id"],))
        if not c:
            raise PlatformError(404, "This account isn't connected")
        try:
            token = self.vault.unwrap_key(c["wrapped"], f"platform:github:{r['id']}").decode()
        except Exception:
            self._store_github(r, None, "The stored token can't be decrypted on this PC - connect again")
            raise PlatformError(409, "The stored token can't be decrypted on this PC - connect again")
        try:
            res, _s = self._github_fetch(token)
        except PlatformError as e:
            self._store_github(r, None, e.message)
            raise
        self._store_github(r, res)

    # ================================================================== extensions
    def extensions(self, refresh: bool = False) -> dict:
        if not refresh and self._ext_cache and time.monotonic() - self._ext_cache[0] < 60:
            res = self._ext_cache[1]
        else:
            res = ext.audit()
            self._ext_cache = (time.monotonic(), res)
            self.stats["extension_audits"] += 1
        seen = self._state("ext_seen") or {}
        base = self._state("ext_baseline_at")
        out = dict(res)
        out["items"] = [dict(i, new=bool(base) and i["key"] not in seen) for i in res["items"]]
        out["baseline_at"] = base
        return out

    def watch_extensions(self) -> int:
        res = self.extensions(refresh=True)
        seen = self._state("ext_seen") or {}
        n = 0
        if self._state("ext_baseline_at"):
            for i in res["items"]:
                if i["key"] not in seen and i["level"] in ("medium", "high"):
                    sev = "high" if i["level"] == "high" else "medium"
                    if self._event("extension_new", sev, f"New {i['level']}-risk extension in {i['app_label']}: "
                                                         f"{i['name']}",
                                   "; ".join(f["text"] for f in i["findings"][:3]),
                                   {"key": i["key"], "path": i["path"], "remove_at": i["remove_at"],
                                    "fix": {"endpoint": "POST /api/platforms/extensions/scan"}},
                                   ref=f"ext:{i['key']}:{i['version']}"):
                        n += 1
        else:
            self._state("ext_baseline_at", _now())
        self._state("ext_seen", {i["key"]: i["version"] for i in res["items"]})
        self._ext_cache = (time.monotonic(), res)
        return n

    def scan_extension(self, cu, key: str) -> dict:
        if self.scanner is None:
            raise PlatformError(501, "The antivirus engine is not available")
        it = next((i for i in self.extensions()["items"] if i["key"] == key), None)
        if not it:
            it = next((i for i in self.extensions(refresh=True)["items"] if i["key"] == key), None)
        if not it or not it["path"]:
            raise PlatformError(404, "Extension not found on this PC")
        from .scanner import ScanError
        try:
            job = self.scanner.start("custom", cu.user["username"], [it["path"]])
        except ScanError as e:
            raise PlatformError(e.status, e.message)
        return {"scan_job": job, "extension": {k: it[k] for k in ("key", "name", "app_label", "path")}}

    # ================================================================== events
    def events(self, cu, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100) -> dict:
        where, params = ["(user_id IS ? OR user_id IS NULL)", "id > ?"], [cu.user["id"], after_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if kind:
            where.append("kind=?"); params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        rows = self.db.fetchall(f"SELECT * FROM platform_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        for r in rows:
            r["data"] = json.loads(r["data"]) if r.get("data") else None
            r["acknowledged"] = bool(r["acknowledged"])
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM platform_events")["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM platform_events WHERE (user_id IS ? OR user_id IS NULL) "
                                 "AND acknowledged=0", (cu.user["id"],))["n"]
        return {"items": rows, "last_id": last, "unacknowledged": unack}

    def acknowledge(self, cu, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE platform_events SET acknowledged=1 WHERE id IN ({q}) AND (user_id IS ? OR "
                                   "user_id IS NULL)", tuple(ids) + (cu.user["id"],)).rowcount
        return self.db.execute("UPDATE platform_events SET acknowledged=1 WHERE user_id IS ? OR user_id IS NULL",
                               (cu.user["id"],)).rowcount

    def clear_events(self, cu) -> int:
        if self._is_admin(cu):
            return self.db.execute("DELETE FROM platform_events WHERE user_id IS ? OR user_id IS NULL",
                                   (cu.user["id"],)).rowcount
        return self.db.execute("DELETE FROM platform_events WHERE user_id IS ?", (cu.user["id"],)).rowcount

    # ================================================================== background
    def review_reminders(self) -> int:
        days = int(self._g("platform_review_days"))
        n = 0
        period = _now()[:7]
        for r in self.db.fetchall("SELECT * FROM platform_accounts"):
            last = r["last_reviewed_at"]
            if last and (_days_since(last) or 0) > days:
                p = self._plat(r)
                if self._event("review_due", "low", f"Time to review your {p['name']} account",
                               f"Last checked {_days_since(last)} days ago - sign-in devices, connected apps, "
                               "recovery details", {"account_id": r["id"], "url": p["links"].get("security")},
                               ref=f"review:{r['id']}:{period}", uid=r["user_id"], account_id=r["id"]):
                    n += 1
        return n

    def recovery_alerts(self) -> int:
        """An e-mail / identity account that can reset others but has no 2FA - alert once a month per account."""
        n = 0
        period = _now()[:7]
        for u in self.db.fetchall("SELECT DISTINCT user_id FROM platform_accounts"):
            info = self._analyze(u["user_id"])
            for aid, a in info.items():
                if a["recovers"] and a["two_factor"] == "not_done":
                    if self._event("recovery_weak", "critical", f"{a['platform']['name']} has no two-step "
                                                                f"verification but can reset "
                                                                f"{len(a['recovers'])} of your accounts",
                                   "Turn on 2FA there first - it protects everything linked to it",
                                   {"account_id": aid, "url": a["platform"]["links"].get("mfa") or
                                    a["platform"]["links"].get("security")}, ref=f"recov:{aid}:{period}",
                                   uid=u["user_id"], account_id=aid):
                        n += 1
        return n

    def due_emails(self) -> list[int]:
        hours = int(self._g("platform_breach_interval_hours"))
        return [r["id"] for r in self.db.fetchall(
            "SELECT id FROM platform_emails WHERE monitor=1 AND (last_checked_at IS NULL OR last_checked_at < ?) "
            "ORDER BY last_checked_at IS NOT NULL, last_checked_at LIMIT 20", (_ago(hours),))]

    def record_scores(self) -> int:
        n = 0
        for u in self.db.fetchall("SELECT DISTINCT user_id FROM platform_accounts"):
            h = self.health(u["user_id"])
            last = self.db.fetchone("SELECT ts, score FROM platform_scores WHERE user_id=? ORDER BY id DESC LIMIT 1",
                                    (u["user_id"],))
            if last and last["score"] == h["score"] and last["ts"] >= _ago(20):
                continue
            self.db.execute("INSERT INTO platform_scores(user_id, score, accounts, two_fa, details) VALUES (?,?,?,?,?)",
                            (u["user_id"], h["score"], h["accounts"], h["two_fa_coverage"],
                             json.dumps({"issues": h["issues"], "breached_emails": h["breached_emails"]})))
            n += 1
        return n

    def cleanup(self) -> int:
        cut = _ago(24 * int(self._g("platform_history_days")))
        n = self.db.execute("DELETE FROM platform_events WHERE ts < ?", (cut,)).rowcount
        n += self.db.execute("DELETE FROM platform_scores WHERE ts < ?", (_ago(24 * 730),)).rowcount
        return n

    def tick(self) -> dict:
        out: dict[str, Any] = {}
        now = time.time()
        if self._g("platform_catalog_auto_update"):
            last = _parse_ts(self._state("catalog_at"))
            if not last or datetime.now(timezone.utc) - last > timedelta(hours=int(self._g(
                    "platform_catalog_update_hours"))):
                try:
                    out["catalog"] = self.refresh_catalog()
                except PlatformError as e:
                    out["catalog"] = {"error": e.message}
        if self._g("platform_breach_check") == "auto" and not self._running_job():
            due = self.due_emails()
            if due:
                try:
                    out["breach_job"] = self.check_emails(None, due)
                except PlatformError as e:
                    out["breach_job"] = {"error": e.message}
        hours = int(self._g("platform_github_sync_hours"))
        for c in self.db.fetchall("SELECT c.account_id, c.last_sync_at FROM platform_connections c"):
            if not c["last_sync_at"] or c["last_sync_at"] < _ago(hours):
                r = self.db.fetchone("SELECT * FROM platform_accounts WHERE id=?", (c["account_id"],))
                try:
                    self._sync_conn(r)
                except PlatformError:
                    pass
        if self._g("platform_extension_audit") and now - self._last_ext_watch >= 3600 * int(
                self._g("platform_extension_watch_hours")):
            self._last_ext_watch = now
            out["extensions_new"] = self.watch_extensions()
        day = _now()[:10]
        if self._state("daily") != day:
            self._state("daily", day)
            out["reminders"] = self.review_reminders()
            out["recovery"] = self.recovery_alerts()
            out["scores"] = self.record_scores()
            out["cleanup"] = self.cleanup()
        return out

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout)

    # ================================================================== dashboard
    def health(self, user_id: int | None = None) -> dict:
        """For Part 18: account protection score, 2FA coverage, breached e-mails, risky extensions."""
        uid = user_id if user_id is not None else -1
        rows = self._rows(uid)
        info = self._analyze(uid, rows)
        ov = self._overview(uid, rows, info)
        breached = self.db.fetchone("SELECT COUNT(DISTINCT e.id) AS n FROM platform_emails e JOIN "
                                    "platform_email_breaches b ON b.email_id=e.id WHERE e.user_id=? AND "
                                    "b.acknowledged=0", (uid,))["n"]
        emails = self.db.fetchone("SELECT COUNT(*) AS n, SUM(monitor) AS m FROM platform_emails WHERE user_id=?",
                                  (uid,))
        ext_high = sum(1 for i in (self._ext_cache[1]["items"] if self._ext_cache else []) if i["level"] == "high"
                       and i["enabled"])
        score = ov["score"]
        if score is not None and breached:
            score = min(score, 84)
        return {"score": score, "grade": ov["grade"], "accounts": ov["accounts"],
                "two_fa_coverage": ov.get("two_fa_coverage"), "two_fa": ov["two_fa"],
                "critical_without_2fa": ov.get("critical_without_2fa", 0), "issues": ov["issues"],
                "emails": emails["n"], "emails_monitored": emails["m"] or 0, "breached_emails": breached,
                "breach_check": self._g("platform_breach_check"), "risky_extensions": ext_high,
                "catalog_breaches": self.catalog_status()["breaches"],
                "review_due": sum(1 for a in info.values() for i in a["issues"] if i["code"] == "review_due")}

    def summary(self, cu, days: int = 30) -> dict:
        uid = cu.user["id"]
        rows = self._rows(uid)
        info = self._analyze(uid, rows)
        by_cat: dict[str, dict] = {}
        for r in rows:
            a = info[r["id"]]
            c = by_cat.setdefault(a["platform"]["category"], {"category": a["platform"]["category"], "label":
                                  cat.CATEGORIES.get(a["platform"]["category"]), "accounts": 0, "two_fa_on": 0,
                                  "two_fa_off": 0, "two_fa_unknown": 0, "avg_score": 0})
            c["accounts"] += 1
            c["avg_score"] += a["score"]
            k = {"done": "two_fa_on", "not_done": "two_fa_off"}.get(a["two_factor"], "two_fa_unknown")
            c[k] += 1
        for c in by_cat.values():
            c["avg_score"] = round(c["avg_score"] / c["accounts"])
        completion = {}
        for a in info.values():
            for i in a["items"]:
                d = completion.setdefault(i["id"], {"item": i["id"], "label": i["label"], "done": 0, "total": 0})
                if i["status"] != "not_applicable":
                    d["total"] += 1
                    d["done"] += int(i["status"] == "done")
        since = _ago(24 * days)
        ev = self.db.fetchall("SELECT substr(ts,1,10) AS day, severity, COUNT(*) AS n FROM platform_events WHERE ts >= ? "
                              "AND (user_id IS ? OR user_id IS NULL) GROUP BY 1,2 ORDER BY 1", (since, uid))
        per_day: dict[str, dict] = {}
        for e in ev:
            d = per_day.setdefault(e["day"], {"day": e["day"], **{s: 0 for s in SEVERITIES}, "total": 0})
            d[e["severity"]] += e["n"]
            d["total"] += e["n"]
        years = self.db.fetchall("SELECT substr(c.breach_date,1,4) AS year, COUNT(DISTINCT b.name) AS n FROM "
                                 "platform_email_breaches b JOIN platform_emails e ON e.id=b.email_id LEFT JOIN "
                                 "platform_breach_catalog c ON c.name=b.name WHERE e.user_id=? GROUP BY 1 ORDER BY 1",
                                 (uid,))
        hist = self.db.fetchall("SELECT ts, score, accounts, two_fa FROM platform_scores WHERE user_id=? AND ts >= ? "
                                "ORDER BY id", (uid, _ago(24 * max(days, 90))))
        imp = {k: 0 for k in cat.IMPORTANCE}
        for a in info.values():
            imp[a["importance"]] += 1
        return {"overview": self._overview(uid, rows, info), "by_category": sorted(by_cat.values(),
                                                                                    key=lambda c: -c["accounts"]),
                "by_importance": imp, "checklist_completion": list(completion.values()),
                "breaches_by_year": [y for y in years if y["year"]], "events_per_day": list(per_day.values()),
                "score_history": hist, "recovery": self.recovery_graph(cu),
                "extensions": (self._ext_cache[1]["by_level"] if self._ext_cache else None),
                "health": self.health(uid)}

    def status(self, cu) -> dict:
        g = self._g
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM platform_events WHERE (user_id IS ? OR user_id IS NULL) "
                                 "AND acknowledged=0", (cu.user["id"],))["n"]
        return {
            "features": {"accounts": True, "checklist": True, "recovery_graph": True, "breach_monitor": True,
                         "breach_catalog": True, "link_check": True, "threat_intel": self.intel is not None,
                         "vault_link": self.passwords is not None, "github_connect": True, "extensions_audit": True,
                         "extension_scan": self.scanner is not None, "discover": True,
                         "encrypted_details": bool(self.vault is not None and self.vault.available)},
            "settings": {k: g(k) for k in ("platform_breach_check", "platform_breach_providers",
                                           "platform_breach_interval_hours", "platform_catalog_auto_update",
                                           "platform_catalog_update_hours", "platform_review_days",
                                           "platform_alert_breaches", "platform_extension_audit",
                                           "platform_extension_watch_hours", "platform_github_sync_hours",
                                           "platform_history_days")},
            "health": self.health(cu.user["id"]), "providers": self.providers(), "catalog": self.catalog_status(),
            "job": self._running_job(), "unacknowledged": unack, "platforms_known": len(cat.PLATFORMS),
            "catalog_reviewed": cat.CATALOG_REVIEWED, "stats": dict(self.stats), "attribution": bw.ATTRIBUTION,
        }


async def platform_loop(svc: PlatformService, settings, first_delay: float = 90, every: float = 60) -> None:
    """Every minute: breach list update when due, auto e-mail checks, GitHub syncs, extension watch, daily
    reminders / scores / cleanup."""
    import asyncio
    await asyncio.sleep(first_delay)
    while True:
        try:
            await asyncio.to_thread(svc.tick)
        except Exception as e:                                           # pragma: no cover
            log.warning("Platforms tick failed: %s", e)
        await asyncio.sleep(every)
