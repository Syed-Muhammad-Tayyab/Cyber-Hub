"""
Cyber Hub Backend - Password import / export formats (Part 12)
Developed by Syed Muhammad Tayyab

Import (auto-detected from the header row):
  Chrome / Edge / Brave / Opera / Safari CSV, Firefox CSV, Bitwarden CSV,
  LastPass CSV, 1Password CSV, KeePass 2 CSV, KeePassXC CSV, Proton Pass /
  NordPass / Dashlane-style CSVs and any CSV whose columns are named like
  url / username / password (generic).
Export:
  * Bitwarden-compatible CSV (plain text - for moving to another manager)
  * Cyber Hub encrypted backup (.chvault): scrypt + AES-256-GCM, protected by
    an export password of your choice, readable on any PC (not device-bound).
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import secrets
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .password_tools import ToolError, normalize

MAX_ROWS = 10000
EXPORT_MAGIC = "cyberhub-vault"
EXPORT_AAD = b"cyberhub-vault-export-v1"

# column aliases (lower-case header -> field)
ALIASES = {
    "title": ["name", "title", "account", "item name", "item"],
    "url": ["url", "login_uri", "website", "web site", "uri", "urls", "origin", "login url"],
    "username": ["username", "login_username", "login name", "login", "user", "user name", "email",
                 "e-mail", "username/email"],
    "password": ["password", "login_password", "pass"],
    "notes": ["notes", "note", "extra", "comments", "comment"],
    "totp": ["totp", "login_totp", "otpauth", "otp", "2fa", "one-time password"],
    "folder": ["folder", "grouping", "group", "vault", "category"],
    "favorite": ["favorite", "fav", "favourite"],
}
SIGNATURES = [            # (format, columns that must all be present)
    ("bitwarden", {"folder", "favorite", "type", "name", "login_uri", "login_username", "login_password"}),
    ("lastpass", {"url", "username", "password", "extra", "name", "grouping"}),
    ("firefox", {"url", "username", "password", "httprealm", "formactionorigin"}),
    ("onepassword", {"title", "url", "username", "password", "otpauth"}),
    ("keepassxc", {"group", "title", "username", "password", "url", "notes"}),
    ("keepass", {"account", "login name", "password", "web site"}),
    ("chrome", {"name", "url", "username", "password"}),
]
FORMATS = {"auto", "generic", "chvault"} | {f for f, _ in SIGNATURES}


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "x", "on"}


def _title_from_url(url: str) -> str:
    from urllib.parse import urlparse
    try:
        host = urlparse(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:
        host = ""
    return host.removeprefix("www.") or url[:60]


def detect(header: list[str]) -> str:
    cols = {h.strip().lower() for h in header}
    for fmt, need in SIGNATURES:
        if need <= cols:
            return fmt
    return "generic"


def parse_csv(text: str, fmt: str = "auto") -> tuple[str, list[dict], list[dict]]:
    """Returns (format, items, skipped). items are vault payloads {type, title, username, password, urls, notes,
    totp, folder, favorite, fields}; skipped = [{line, reason}]."""
    if fmt not in FORMATS or fmt == "chvault":
        raise ToolError(422, "Unknown CSV format")
    text = text.lstrip("﻿")
    csv.field_size_limit(1024 * 1024)
    try:
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except csv.Error as e:
        raise ToolError(422, f"Not a readable CSV file: {e}") from e
    rows = [r for r in rows if any(c.strip() for c in r)]
    if len(rows) < 2:
        raise ToolError(422, "The CSV has no rows to import (a header row plus at least one entry is needed)")
    header = [h.strip().lower() for h in rows[0]]
    found = detect(header) if fmt == "auto" else fmt
    idx: dict[str, int] = {}
    for field, names in ALIASES.items():
        for n in names:
            if n in header:
                idx[field] = header.index(n)
                break
    if "password" not in idx and found not in ("bitwarden", "lastpass"):
        raise ToolError(422, "No 'password' column found - is this a password export?")
    if len(rows) - 1 > MAX_ROWS:
        raise ToolError(413, f"Too many rows (max {MAX_ROWS})")
    col = {h: i for i, h in enumerate(header)}
    items, skipped = [], []
    for ln, r in enumerate(rows[1:], start=2):
        def g(field: str) -> str:
            i = idx.get(field)
            return r[i].strip() if i is not None and i < len(r) else ""

        def raw(name: str) -> str:
            i = col.get(name)
            return r[i] if i is not None and i < len(r) else ""
        url, user, pw, notes = g("url"), g("username"), (raw(header[idx["password"]]) if "password" in idx else ""), g("notes")
        title, totp, folder = g("title"), g("totp"), g("folder")
        kind = "login"
        fields: list[dict] = []
        if found == "bitwarden":
            t = raw("type").strip().lower()
            if t in ("note", "securenote"):
                kind = "note"
            elif t not in ("", "login"):
                skipped.append({"line": ln, "reason": f"Bitwarden '{t}' items are not imported from CSV"})
                continue
            for fl in raw("fields").splitlines():
                name, _, value = fl.partition(": ")
                if name.strip():
                    fields.append({"name": name.strip()[:60], "value": value[:2000], "hidden": False})
        if found == "lastpass" and url.strip().lower() == "http://sn":
            kind, url = "note", ""
        if found == "firefox" and url.startswith("chrome://"):
            skipped.append({"line": ln, "reason": "Firefox internal entry"})
            continue
        urls = [u.strip() for u in url.replace("\n", ",").split(",") if u.strip()] if url else []
        if kind == "login" and not pw and not user and not urls:
            skipped.append({"line": ln, "reason": "Empty entry"})
            continue
        if not title:
            title = _title_from_url(urls[0]) if urls else (user or "Imported item")
        item = {"type": kind, "title": title[:200], "notes": notes[:10000], "folder": folder[:60],
                "favorite": _truthy(g("favorite")), "fields": fields[:50]}
        if kind == "login":
            item.update(username=user[:500], password=pw[:1024], urls=[u[:2048] for u in urls[:20]],
                        totp=totp[:2048])
        items.append(item)
    return found, items, skipped


EXPORT_COLUMNS = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri",
                  "login_username", "login_password", "login_totp"]


def to_csv(items: list[dict]) -> str:
    """Bitwarden-compatible CSV (most managers import it). Cards / identities go in as notes."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(EXPORT_COLUMNS)
    for it in items:
        p = it["payload"]
        t = it["type"]
        notes = p.get("notes", "")
        if t == "card":
            extra = [f"Cardholder: {p.get('cardholder', '')}", f"Number: {p.get('number', '')}",
                     f"Expiry: {p.get('exp_month') or ''}/{p.get('exp_year') or ''}", f"CVV: {p.get('cvv', '')}"]
            notes = "\n".join(extra + ([notes] if notes else []))
        elif t == "identity":
            extra = [f"{k.replace('_', ' ').title()}: {p[k]}" for k in
                     ("full_name", "email", "phone", "address", "company", "national_id") if p.get(k)]
            notes = "\n".join(extra + ([notes] if notes else []))
        fields = "\n".join(f"{f['name']}: {f['value']}" for f in p.get("fields") or [])
        w.writerow([p.get("folder", ""), "1" if p.get("favorite") else "", "login" if t == "login" else "note",
                    p.get("title", ""), notes, fields, "0", ",".join(p.get("urls") or []) if t == "login" else "",
                    p.get("username", "") if t == "login" else "", p.get("password", "") if t == "login" else "",
                    p.get("totp", "") if t == "login" else ""])
    return out.getvalue()


# ====================================================================== encrypted backup
def _export_key(password: str, salt: bytes, kdf: dict) -> bytes:
    return hashlib.scrypt(normalize(password).encode("utf-8"), salt=salt, n=kdf["n"], r=kdf["r"], p=kdf["p"],
                          dklen=32, maxmem=1024 * 1024 * 1024)


def encrypt_backup(items: list[dict], password: str, kdf: dict, app_version: str) -> str:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    body = json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "app": f"Cyber Hub {app_version}", "count": len(items),
                       "items": [{"type": i["type"], "payload": i["payload"], "created_at": i.get("created_at"),
                                  "updated_at": i.get("updated_at")} for i in items]},
                      separators=(",", ":")).encode()
    ct = AESGCM(_export_key(password, salt, kdf)).encrypt(nonce, body, EXPORT_AAD)
    return json.dumps({"format": EXPORT_MAGIC, "version": 1, "cipher": "AES-256-GCM",
                       "kdf": {"name": "scrypt", **kdf}, "salt": base64.b64encode(salt).decode(),
                       "nonce": base64.b64encode(nonce).decode(), "data": base64.b64encode(ct).decode()}, indent=1)


def decrypt_backup(text: str, password: str) -> list[dict]:
    try:
        doc = json.loads(text)
        if doc.get("format") != EXPORT_MAGIC or doc.get("version") != 1:
            raise ValueError
        kdf = {k: int(doc["kdf"][k]) for k in ("n", "r", "p")}
        if not (2 ** 10 <= kdf["n"] <= 2 ** 20 and kdf["n"] & (kdf["n"] - 1) == 0 and 1 <= kdf["r"] <= 32
                and 1 <= kdf["p"] <= 16):
            raise ValueError
        salt, nonce, ct = (base64.b64decode(doc[k]) for k in ("salt", "nonce", "data"))
    except (ValueError, KeyError, TypeError) as e:
        raise ToolError(422, "Not a Cyber Hub vault backup (.chvault)") from e
    try:
        body = json.loads(AESGCM(_export_key(password, salt, kdf)).decrypt(nonce, ct, EXPORT_AAD))
    except InvalidTag as e:
        raise ToolError(401, "Wrong backup password (or the file was changed)") from e
    items = body.get("items")
    if not isinstance(items, list):
        raise ToolError(422, "Backup has no items")
    return items
