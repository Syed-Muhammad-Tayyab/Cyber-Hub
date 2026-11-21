"""
Cyber Hub Backend - E-mail breach monitoring helpers (Part 16)
Developed by Syed Muhammad Tayyab

Providers
  xposedornot  free, no key (https://api.xposedornot.com/v1/check-email/{email}) - breach names only, ~2 requests / s.
  hibp         Have I Been Pwned breachedaccount (paid "hibp-api-key", full breach details). Breach data from HIBP is
               CC BY 4.0 - the UI must show "Data: Have I Been Pwned" with a link (attribution below).
Breach catalog
  https://haveibeenpwned.com/api/v3/breaches - public, free, no key. Downloaded in the background (no personal data
  is sent) and used to (1) describe breaches found for an e-mail, (2) tell you when a site you use is breached.

Only the e-mail address you choose to check is sent, and only when you (or the 'auto' setting) ask.
"""
from __future__ import annotations

import html
import json
import re
import urllib.parse
from datetime import datetime, timezone

from . import ioc

XON_URL = "https://api.xposedornot.com/v1/check-email/{}"
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false"
HIBP_CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_KEY_URL = "https://haveibeenpwned.com/API/Key"
USER_AGENT = "CyberHub/0.16 (+local security app; breach monitor)"
ATTRIBUTION = {"text": "Breach data: Have I Been Pwned (CC BY 4.0) / XposedOrNot",
               "hibp": "https://haveibeenpwned.com", "xposedornot": "https://xposedornot.com"}
PROVIDERS = ("xposedornot", "hibp")
PROVIDER_LABELS = {"xposedornot": "XposedOrNot (free)", "hibp": "Have I Been Pwned (API key)"}
# data classes that make a breach serious for the account owner
SECRET_CLASSES = {"passwords", "password hints", "auth tokens", "security questions and answers",
                  "historical passwords", "partial credit card data", "credit cards", "bank account numbers",
                  "government issued ids", "browser stored credentials", "private messages"}
MAX_CATALOG_BYTES = 16 * 1024 * 1024

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}$")


class BreachError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


def normalize_email(raw: str) -> str:
    e = (raw or "").strip().strip("<>").strip()
    if e.lower().startswith("mailto:"):
        e = e[7:]
    if "@" not in e:
        raise BreachError(422, "That is not an e-mail address")
    local, _, dom = e.rpartition("@")
    try:
        dom = ioc.to_ascii_host(dom.strip().rstrip("."))
    except Exception:
        raise BreachError(422, "The e-mail's domain is not valid")
    e = f"{local}@{dom}".lower()
    if not _EMAIL.match(e) or ".." in e or not ioc.is_domain(dom):
        raise BreachError(422, "That is not a valid e-mail address")
    return e


def mask_email(e: str) -> str:
    local, _, dom = e.partition("@")
    keep = 1 if len(local) <= 3 else 2
    return local[:keep] + "•" * max(3, min(6, len(local) - keep)) + "@" + dom


def strip_html(s: str | None, limit: int = 2000) -> str:
    t = re.sub(r"<[^>]+>", "", s or "")
    t = re.sub(r"\s+", " ", html.unescape(t)).strip()
    return t[:limit]


def _flatten(v) -> list[str]:
    out: list[str] = []
    if isinstance(v, str):
        out += [x.strip() for x in v.split(",") if x.strip()]
    elif isinstance(v, (list, tuple)):
        for x in v:
            out += _flatten(x)
    return out


def parse_xon(status: int, body: bytes) -> list[str]:
    """XposedOrNot answer -> breach names ([] = not found). Raises BreachError for errors."""
    if status == 404:
        return []
    if status == 429:
        raise BreachError(429, "XposedOrNot asked us to slow down - try again in a minute", 60)
    if status != 200:
        raise BreachError(502, f"XposedOrNot answered HTTP {status}")
    try:
        d = json.loads(body.decode("utf-8", "replace") or "{}")
    except ValueError:
        raise BreachError(502, "XposedOrNot sent an answer Cyber Hub can't read")
    if isinstance(d, dict) and (d.get("Error") or d.get("error")) and not d.get("breaches"):
        msg = str(d.get("Error") or d.get("error"))
        if "not found" in msg.lower():
            return []
        raise BreachError(502, f"XposedOrNot: {msg[:120]}")
    names = _flatten(d.get("breaches") if isinstance(d, dict) else d)
    return sorted({n[:120] for n in names if re.match(r"^[\w .'&()+\-]{1,120}$", n)}, key=str.lower)


def parse_hibp_account(status: int, body: bytes, headers: dict) -> list[dict]:
    if status == 404:
        return []
    if status in (401, 403):
        raise BreachError(409, "Have I Been Pwned refused the API key (wrong key or no active subscription)")
    if status == 429:
        ra = headers.get("retry-after")
        wait = int(ra) if ra and ra.isdigit() else 10
        raise BreachError(429, f"Have I Been Pwned rate limit - next request in {wait} s", wait)
    if status != 200:
        raise BreachError(502, f"Have I Been Pwned answered HTTP {status}")
    try:
        d = json.loads(body.decode("utf-8", "replace") or "[]")
    except ValueError:
        raise BreachError(502, "Have I Been Pwned sent an answer Cyber Hub can't read")
    if not isinstance(d, list):
        raise BreachError(502, "Unexpected answer from Have I Been Pwned")
    return [catalog_row(b) for b in d if isinstance(b, dict) and b.get("Name")]


def catalog_row(b: dict) -> dict:
    dom = (b.get("Domain") or "").strip().lower()
    try:
        dom = ioc.registrable(ioc.to_ascii_host(dom)) if dom and ioc.is_domain(ioc.to_ascii_host(dom)) else ""
    except Exception:
        dom = ""
    classes = [str(x)[:80] for x in (b.get("DataClasses") or []) if isinstance(x, str)][:60]
    return {"name": str(b.get("Name"))[:120], "title": str(b.get("Title") or b.get("Name"))[:200], "domain": dom,
            "breach_date": (b.get("BreachDate") or "")[:10] or None, "added_date": (b.get("AddedDate") or "")[:19] or None,
            "pwn_count": int(b.get("PwnCount") or 0), "data_classes": classes,
            "description": strip_html(b.get("Description")),
            "verified": bool(b.get("IsVerified", True)), "sensitive": bool(b.get("IsSensitive")),
            "spam_list": bool(b.get("IsSpamList")), "malware": bool(b.get("IsMalware")),
            "stealer_log": bool(b.get("IsStealerLog")), "fabricated": bool(b.get("IsFabricated")),
            "retired": bool(b.get("IsRetired"))}


def parse_catalog(status: int, body: bytes) -> list[dict]:
    if status != 200:
        raise BreachError(502, f"Have I Been Pwned breach list answered HTTP {status}")
    if len(body) > MAX_CATALOG_BYTES:
        raise BreachError(413, "The breach list is larger than expected")
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise BreachError(502, "The breach list can't be read")
    if not isinstance(d, list) or not d:
        raise BreachError(502, "The breach list was empty - keeping the last good copy")
    rows = [catalog_row(b) for b in d if isinstance(b, dict) and b.get("Name")]
    if len(rows) < max(1, len(d) // 2):
        raise BreachError(502, "The breach list looks damaged - keeping the last good copy")
    return rows


def has_secrets(classes: list[str]) -> bool:
    return any(c.lower() in SECRET_CLASSES for c in classes or [])


def severity(classes: list[str], stealer: bool = False) -> str:
    low = {c.lower() for c in classes or []}
    if stealer or low & {"passwords", "auth tokens", "browser stored credentials", "historical passwords"}:
        return "high"
    if low & SECRET_CLASSES:
        return "medium"
    return "low"


def xon_url(email: str) -> str:
    return XON_URL.format(urllib.parse.quote(email, safe="@"))


def hibp_url(email: str) -> str:
    return HIBP_ACCOUNT_URL.format(urllib.parse.quote(email, safe=""))


def advice(classes: list[str], stealer: bool = False) -> list[str]:
    low = {c.lower() for c in classes or []}
    out = []
    if stealer:
        out.append("Your login was captured by info-stealing malware on some device - scan every PC you used "
                   "(Antivirus > Full scan) and change the passwords saved in that browser.")
    if low & {"passwords", "historical passwords", "password hints", "auth tokens", "browser stored credentials"}:
        out.append("Change the password on that site and on every site where you used the same one "
                   "(Passwords > Audit shows reuse).")
        out.append("Turn on two-step verification where you can.")
    if low & {"phone numbers"}:
        out.append("Expect SMS / WhatsApp scams that use your number - never share a code you receive.")
    if low & {"security questions and answers"}:
        out.append("Change security-question answers (use random answers stored in your vault).")
    if low & {"credit cards", "partial credit card data", "bank account numbers"}:
        out.append("Watch your bank / card statements and ask the bank for a new card if in doubt.")
    if low & {"government issued ids", "physical addresses", "dates of birth"}:
        out.append("Be careful with calls or letters that quote your details - they can be used for "
                   "identity fraud.")
    if not out:
        out.append("Be extra careful with e-mails that mention this site - phishing often follows a breach.")
    return out


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
