"""
Cyber Hub Backend - Online hash reputation (Part 8)
Developed by Syed Muhammad Tayyab

Asks VirusTotal and / or MalwareBazaar whether a file hash is known malware.
Privacy first:
  * off until you switch it on (cloud_lookup_enabled) and add your own API key(s)
  * only the SHA-256 / SHA-1 / MD5 hash ever leaves the PC - never the file
  * keys are encrypted with the quarantine vault master key (DPAPI-sealed on
    Windows) and never returned by the API, only a "....abcd" hint

Results are cached (hash_reputation) so the same hash is asked once per
cloud_cache_days. Requests are rate-limited per provider (VirusTotal's free
tier allows 4 per minute / 500 per day) and counted per day (cloud_usage).

Automatic mode (cloud_auto_lookup = executables | all): files that scans and
real-time protection found clean are queued and checked in the background;
a hash the cloud calls malicious becomes a detection (method "cloud"), goes
through the normal quarantine policy and - with cloud_add_to_signatures -
is added to the local signature database so it is caught offline next time.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timedelta, timezone

from ..database import Database
from ..logger import get_logger
from .malware_db import normalize_hash

log = get_logger("cloud")

PROVIDERS = ("virustotal", "malwarebazaar")
LABELS = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar (abuse.ch)"}
KEY_URLS = {"virustotal": "https://www.virustotal.com/gui/my-apikey",
            "malwarebazaar": "https://auth.abuse.ch/"}
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".msp", ".bat", ".cmd", ".ps1",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".docm", ".xlsm", ".pptm", ".elf",
            ".so", ".sh", ".apk", ".appimage", ".iso", ".img"}
QUEUE_MAX = 2000
USER_AGENT = "CyberHub/0.8 (+local security app)"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class CloudError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


def urllib_transport(method: str, url: str, headers: dict, data: bytes | None, timeout: float) -> tuple[int, bytes]:
    """Default HTTP client (standard library, honours the system proxy settings)."""
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:                  # nosec - fixed https URLs
            return r.status, r.read(4 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, e.read(64 * 1024) if e.fp else b""


class CloudLookup:
    def __init__(self, db: Database, settings, activity, vault=None, malware_db=None):
        self.db, self.settings, self.activity, self.vault, self.malware_db = db, settings, activity, vault, malware_db
        self.transport = urllib_transport                    # tests swap this for a fake
        self.timeout = 15.0
        self.scanner = None                                  # set in main: records cloud detections
        self.quarantine = None
        self._lock = threading.RLock()
        self._recent: dict[str, deque] = {p: deque() for p in PROVIDERS}
        self._queue: deque = deque()
        self._queued: set[str] = set()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._stop = False
        self._blocked_until: dict[str, float] = {}
        self.stats = {"queued": 0, "checked": 0, "malicious": 0, "errors": 0}

    # ============================================================ keys
    def _require_vault(self):
        if self.vault is None or not self.vault.available:
            raise CloudError(503, "The key store is unavailable (vault key missing) - can't save API keys")

    def set_key(self, provider: str, key: str | None, username: str) -> dict:
        if provider not in PROVIDERS:
            raise CloudError(422, "Unknown provider")
        if not key:
            self.db.execute("DELETE FROM cloud_api_keys WHERE provider=?", (provider,))
            self.activity.record("settings", f"{LABELS[provider]} API key removed", severity="low", source="cloud")
            return self.providers()[provider]
        key = key.strip()
        if not (16 <= len(key) <= 256) or any(c.isspace() for c in key):
            raise CloudError(422, "That doesn't look like an API key")
        self._require_vault()
        wrapped = self.vault.wrap_key(key.encode(), f"cloud:{provider}")
        self.db.execute("INSERT INTO cloud_api_keys(provider, wrapped, hint, updated_at, updated_by) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(provider) DO UPDATE SET wrapped=excluded.wrapped, hint=excluded.hint, "
                        "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                        (provider, wrapped, "…" + key[-4:], _now(), username))
        self._blocked_until.pop(provider, None)
        self.activity.record("settings", f"{LABELS[provider]} API key saved", f"by {username}", severity="low",
                             source="cloud")
        return self.providers()[provider]

    def _key(self, provider: str) -> str | None:
        r = self.db.fetchone("SELECT wrapped FROM cloud_api_keys WHERE provider=?", (provider,))
        if not r or self.vault is None or not self.vault.available:
            return None
        try:
            return self.vault.unwrap_key(r["wrapped"], f"cloud:{provider}").decode()
        except Exception:                                    # vault key changed - the stored key is unusable
            log.warning("Stored %s key can't be decrypted", provider)
            return None

    # ---- Part 15 shares these keys (one VirusTotal budget, one abuse.ch Auth-Key for all abuse.ch platforms)
    def key_for(self, provider: str) -> str | None:
        """Decrypted key for another Cyber Hub module (never returned by the API)."""
        return self._key(provider) if provider in PROVIDERS else None

    def reserve(self, provider: str) -> int | None:
        """Take one request from the shared rate limit. None = go ahead, else seconds to wait."""
        return self._take(provider) if provider in PROVIDERS else None

    def providers(self) -> dict:
        keys = {r["provider"]: r for r in self.db.fetchall("SELECT provider, hint, updated_at FROM cloud_api_keys")}
        chosen = set(self.settings.get("cloud_providers"))
        out = {}
        for p in PROVIDERS:
            k = keys.get(p)
            out[p] = {"provider": p, "label": LABELS[p], "key_set": bool(k), "key_hint": k["hint"] if k else None,
                      "key_updated_at": k["updated_at"] if k else None, "selected": p in chosen,
                      "ready": bool(k) and p in chosen, "get_key_at": KEY_URLS[p],
                      "requests_today": self._used_today(p), "daily_limit": self._limits(p)[1],
                      "per_minute": self._limits(p)[0],
                      "paused_seconds": max(0, round(self._blocked_until.get(p, 0) - time.time()))}
        return out

    def ready_providers(self) -> list[str]:
        return [p for p, v in self.providers().items() if v["ready"]]

    # ============================================================ rate limiting
    def _limits(self, p: str) -> tuple[int, int]:
        if p == "virustotal":
            return self.settings.get("cloud_vt_per_minute"), self.settings.get("cloud_vt_per_day")
        return 60, 10000

    def _used_today(self, p: str) -> int:
        r = self.db.fetchone("SELECT requests FROM cloud_usage WHERE day=? AND provider=?", (_day(), p))
        return r["requests"] if r else 0

    def _take(self, p: str) -> int | None:
        """Reserve one request. Returns None if allowed, else seconds to wait."""
        per_min, per_day = self._limits(p)
        now = time.time()
        if self._blocked_until.get(p, 0) > now:
            return int(self._blocked_until[p] - now) + 1
        if self._used_today(p) >= per_day:
            return 3600
        with self._lock:
            q = self._recent[p]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= per_min:
                return int(60 - (now - q[0])) + 1
            q.append(now)
        self.db.execute("INSERT INTO cloud_usage(day, provider, requests) VALUES (?,?,1) "
                        "ON CONFLICT(day, provider) DO UPDATE SET requests=requests+1", (_day(), p))
        return None

    # ============================================================ providers
    def _ask_virustotal(self, h: str, key: str) -> dict:
        status, body = self.transport("GET", VT_URL.format(h), {"x-apikey": key, "Accept": "application/json"},
                                      None, self.timeout)
        if status == 404:
            return {"verdict": "unknown", "found": False}
        if status in (401, 403):
            raise CloudError(401, "VirusTotal rejected the API key")
        if status == 429:
            self._blocked_until["virustotal"] = time.time() + 60
            raise CloudError(429, "VirusTotal quota reached - try again later", 60)
        if status != 200:
            raise CloudError(502, f"VirusTotal answered HTTP {status}")
        try:
            a = json.loads(body)["data"]["attributes"]
        except (ValueError, KeyError, TypeError) as e:
            raise CloudError(502, "VirusTotal sent an unexpected answer") from e
        st = a.get("last_analysis_stats") or {}
        mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
        total = sum(int(v) for k, v in st.items() if k in ("malicious", "suspicious", "undetected", "harmless"))
        label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
        first = a.get("first_submission_date")
        need = self.settings.get("cloud_vt_min_detections")
        verdict = "malicious" if mal >= need else "suspicious" if (mal or sus >= 2) else "clean"
        return {"verdict": verdict, "found": True, "malicious": mal, "suspicious": sus,
                "harmless": int(st.get("harmless", 0)), "undetected": int(st.get("undetected", 0)), "total": total,
                "threat_label": label, "name": a.get("meaningful_name"), "file_type": a.get("type_description"),
                "first_seen": datetime.fromtimestamp(first, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if isinstance(first, int) else None,
                "sha256": a.get("sha256"), "reputation": a.get("reputation"),
                "permalink": f"https://www.virustotal.com/gui/file/{a.get('sha256') or h}"}

    def _ask_malwarebazaar(self, h: str, key: str) -> dict:
        data = urllib.parse.urlencode({"query": "get_info", "hash": h}).encode()
        status, body = self.transport("POST", MB_URL, {"Auth-Key": key,
                                                       "Content-Type": "application/x-www-form-urlencoded"},
                                      data, self.timeout)
        if status in (401, 403):
            raise CloudError(401, "MalwareBazaar rejected the Auth-Key")
        if status == 429:
            self._blocked_until["malwarebazaar"] = time.time() + 60
            raise CloudError(429, "MalwareBazaar rate limit reached - try again later", 60)
        if status != 200:
            raise CloudError(502, f"MalwareBazaar answered HTTP {status}")
        try:
            j = json.loads(body)
        except ValueError as e:
            raise CloudError(502, "MalwareBazaar sent an unexpected answer") from e
        qs = j.get("query_status")
        if qs in ("hash_not_found", "no_results"):
            return {"verdict": "unknown", "found": False}
        if qs in ("no_api_key", "unknown_auth_key", "wrong_auth_key", "user_blacklisted"):
            raise CloudError(401, f"MalwareBazaar rejected the Auth-Key ({qs})")
        if qs != "ok" or not j.get("data"):
            raise CloudError(502, f"MalwareBazaar: {qs or 'unexpected answer'}")
        d = j["data"][0]
        return {"verdict": "malicious", "found": True, "malicious": 1, "total": 1,
                "threat_label": d.get("signature") or ", ".join((d.get("tags") or [])[:3]) or "known sample",
                "name": d.get("file_name"), "file_type": d.get("file_type"), "first_seen": d.get("first_seen"),
                "sha256": d.get("sha256_hash"), "tags": (d.get("tags") or [])[:10],
                "permalink": f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash')}/"}

    # ============================================================ lookups
    def _cache_get(self, h: str, p: str) -> dict | None:
        r = self.db.fetchone("SELECT * FROM hash_reputation WHERE hash=? AND provider=?", (h, p))
        if not r:
            return None
        days = self.settings.get("cloud_cache_days")
        if r["verdict"] == "malicious":
            days = max(days, 30)
        try:
            t = datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if datetime.now(timezone.utc) - t > timedelta(days=days):
            return None
        out = json.loads(r["raw"] or "{}")
        out.update(cached=True, checked_at=r["checked_at"])
        return out

    def _cache_put(self, h: str, p: str, res: dict) -> None:
        self.db.execute(
            "INSERT INTO hash_reputation(hash, provider, verdict, malicious, total, threat_label, sha256, permalink, "
            "checked_at, raw) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hash, provider) DO UPDATE SET "
            "verdict=excluded.verdict, malicious=excluded.malicious, total=excluded.total, "
            "threat_label=excluded.threat_label, sha256=excluded.sha256, permalink=excluded.permalink, "
            "checked_at=excluded.checked_at, raw=excluded.raw",
            (h, p, res["verdict"], res.get("malicious"), res.get("total"), res.get("threat_label"), res.get("sha256"),
             res.get("permalink"), _now(), json.dumps(res)))

    @staticmethod
    def combine(results: dict[str, dict]) -> str:
        vs = [r.get("verdict") for r in results.values()]
        for v in ("malicious", "suspicious", "clean", "unknown"):
            if v in vs:
                return v
        return "error"

    def lookup(self, h: str, providers: list[str] | None = None, force: bool = False,
               require_enabled: bool = True) -> dict:
        """Interactive lookup. Raises CloudError when nothing could be asked."""
        try:
            h, htype = normalize_hash(h)
        except ValueError as e:
            raise CloudError(422, str(e)) from e
        if require_enabled and not self.settings.get("cloud_lookup_enabled"):
            raise CloudError(409, "Online lookup is off - switch it on in Settings (only file hashes are sent)")
        ready = self.ready_providers()
        if providers:
            bad = [p for p in providers if p not in PROVIDERS]
            if bad:
                raise CloudError(422, f"Unknown provider: {bad[0]}")
            ready = [p for p in providers if p in ready]
        if not ready:
            raise CloudError(409, "Add a VirusTotal or MalwareBazaar API key first")
        results, errors = {}, {}
        for p in ready:
            if not force:
                c = self._cache_get(h, p)
                if c is not None:
                    results[p] = c
                    continue
            wait = self._take(p)
            if wait is not None:
                errors[p] = {"status": 429, "message": f"Rate limit - next request in {wait} s", "retry_after": wait}
                continue
            key = self._key(p)
            if not key:
                errors[p] = {"status": 409, "message": "API key can't be read - enter it again"}
                continue
            try:
                res = (self._ask_virustotal if p == "virustotal" else self._ask_malwarebazaar)(h, key)
            except CloudError as e:
                errors[p] = {"status": e.status, "message": e.message, "retry_after": e.retry_after}
                self.stats["errors"] += 1
                continue
            except (OSError, TimeoutError) as e:
                errors[p] = {"status": 503, "message": f"Can't reach {LABELS[p]}: {type(e).__name__}"}
                self.stats["errors"] += 1
                continue
            self._cache_put(h, p, res)
            results[p] = res | {"cached": False, "checked_at": _now()}
            self.stats["checked"] += 1
        if not results:
            first = next(iter(errors.values()))
            raise CloudError(first["status"], first["message"], first.get("retry_after"))
        verdict = self.combine(results)
        label = next((r.get("threat_label") for r in results.values() if r.get("threat_label")), None)
        sha = next((r.get("sha256") for r in results.values() if r.get("sha256")), None) or \
            (h if htype == "sha256" else None)
        if verdict == "malicious":
            self.stats["malicious"] += 1
            self._learn(sha, label, results)
        return {"hash": h, "hash_type": htype, "sha256": sha, "verdict": verdict, "threat_label": label,
                "providers": results, "errors": errors}

    def _learn(self, sha256: str | None, label: str | None, results: dict) -> None:
        """Malicious in the cloud -> local signature, so it is caught offline from now on."""
        if not sha256 or self.malware_db is None or not self.settings.get("cloud_add_to_signatures"):
            return
        src = "cloud:" + "+".join(sorted(p for p, r in results.items() if r.get("verdict") == "malicious"))
        try:
            if not self.malware_db.get(sha256):
                self.malware_db.add(sha256, (label or "Malware.Cloud")[:100], "high", None, source=src[:40])
        except ValueError:                                                          # pragma: no cover
            pass

    def history(self, verdict: str | None = None, limit: int = 100, offset: int = 0) -> dict:
        where, params = "", ()
        if verdict:
            where, params = "WHERE verdict=?", (verdict,)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM hash_reputation {where}", params)["n"]
        rows = self.db.fetchall(f"SELECT hash, provider, verdict, malicious, total, threat_label, sha256, permalink, "
                                f"checked_at FROM hash_reputation {where} ORDER BY checked_at DESC LIMIT ? OFFSET ?",
                                params + (limit, offset))
        return {"total": total, "items": rows}

    def clear_cache(self) -> int:
        return self.db.execute("DELETE FROM hash_reputation").rowcount

    # ============================================================ automatic (background) lookups
    def wants(self, path: str, head: bytes = b"") -> bool:
        if not self.settings.get("cloud_lookup_enabled"):
            return False
        mode = self.settings.get("cloud_auto_lookup")
        if mode == "off":
            return False
        if mode == "all":
            return True
        return os.path.splitext(path)[1].lower() in EXEC_EXT or head[:2] == b"MZ" or head[:4] == b"\x7fELF"

    def submit(self, path: str, sha256: str, head: bytes = b"", origin: str = "scan", size: int | None = None) -> bool:
        """Queue a clean file for a background check (cheap - called from scan threads)."""
        if not sha256 or not self.wants(path, head):
            return False
        with self._lock:
            if sha256 in self._queued or len(self._queue) >= QUEUE_MAX:
                return False
            if self.db.fetchone("SELECT 1 AS x FROM hash_reputation WHERE hash=? LIMIT 1", (sha256,)):
                if any(self._cache_get(sha256, p) is not None for p in PROVIDERS):
                    return False
            item = {"sha256": sha256, "path": path, "origin": origin, "size": size, "queued_at": time.time()}
            if origin == "realtime":
                self._queue.appendleft(item)                 # new arrivals first
            else:
                self._queue.append(item)
            self._queued.add(sha256)
            self.stats["queued"] += 1
        self._wake.set()
        return True

    def queue_depth(self) -> int:
        return len(self._queue)

    def process_queue_once(self, max_items: int = 50) -> int:
        """Work through the queue until it's empty, rate-limited or max_items done. Returns items done."""
        done = 0
        while done < max_items:
            with self._lock:
                if not self._queue:
                    return done
                it = self._queue.popleft()
            if not self.ready_providers() or not self.settings.get("cloud_lookup_enabled"):
                with self._lock:
                    self._queue.clear(); self._queued.clear()
                return done
            try:
                res = self.lookup(it["sha256"])
            except CloudError as e:
                if e.status == 429:                          # rate limited: put it back and stop for now
                    with self._lock:
                        self._queue.appendleft(it)
                    return done
                with self._lock:
                    self._queued.discard(it["sha256"])
                done += 1
                continue
            with self._lock:
                self._queued.discard(it["sha256"])
            done += 1
            if res["verdict"] == "malicious":
                self._on_malicious(it, res)
        return done

    def _on_malicious(self, it: dict, res: dict) -> None:
        path = it["path"]
        if self.scanner is None:
            return
        from .signatures import sha256_file
        if not os.path.isfile(path) or sha256_file(path) != it["sha256"]:   # gone or changed since it was queued
            return
        vt = res["providers"].get("virustotal") or {}
        detail = {"verdict": res["verdict"], "providers": {p: {k: r.get(k) for k in
                  ("verdict", "malicious", "total", "threat_label", "permalink")} for p, r in res["providers"].items()}}
        name = res.get("threat_label") or "Malware.Cloud"
        det = {"threat_name": f"Cloud:{name}"[:120], "severity": "high", "method": "cloud",
               "signature_source": "cloud", "archive_member": None, "sha256": it["sha256"], "md5": None,
               "size": it.get("size") or os.path.getsize(path), "details": detail}
        if self.scanner.allowlist is not None:
            entry = self.scanner.allowlist.match(it["sha256"], det["threat_name"])
            if entry is not None:
                self.scanner.allowlist.hit(entry)
                return
        rows = self.scanner._record_detections(None, {"path": path, "detections": [det]}, auto_action=True)
        self.activity.record("threat", f"Online lookup: {name}",
                             f"{path} - {vt.get('malicious', '?')}/{vt.get('total', '?')} engines"
                             if vt else f"{path} - known to MalwareBazaar", severity="high", source="cloud")
        self.scanner._emit("threat", job_id=None, detection=rows[0] if rows else None)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._loop, name="cloud-lookup", daemon=True)
        self._thread.start()

    def _loop(self) -> None:                                                     # pragma: no cover - timing
        while not self._stop:
            self._wake.wait(30)
            self._wake.clear()
            if self._stop:
                break
            try:
                self.process_queue_once()
            except Exception as e:
                log.warning("Background lookup failed: %s", e)
            if self._queue:
                time.sleep(15)                               # rate-limited: try again a bit later
                self._wake.set()

    def shutdown(self, timeout: float = 3.0) -> None:
        self._stop = True
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict:
        provs = self.providers()
        return {"enabled": bool(self.settings.get("cloud_lookup_enabled")),
                "auto_lookup": self.settings.get("cloud_auto_lookup"),
                "ready": any(p["ready"] for p in provs.values()), "providers": provs,
                "queue": self.queue_depth(), "stats": dict(self.stats),
                "cache": self.db.fetchone("SELECT COUNT(*) AS n, SUM(verdict='malicious') AS malicious "
                                          "FROM hash_reputation"),
                "privacy": "Only file hashes (SHA-256 / SHA-1 / MD5) are sent - files never leave this PC"}
