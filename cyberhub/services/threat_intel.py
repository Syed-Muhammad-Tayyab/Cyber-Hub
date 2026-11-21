"""
Cyber Hub Backend - Threat Intelligence (Part 15)
Developed by Syed Muhammad Tayyab

One service behind /api/intel.

Check anything  - IP / IP range / domain / URL / e-mail / MD5 / SHA-1 / SHA-256 (defanged forms like hxxp://evil[.]com
                  accepted). Offline first: the downloaded feeds, your own block list, Part 5's antivirus signatures,
                  Part 8's cached cloud verdicts and the phishing analyser. Optional online reputation (off by default,
                  only the indicator is sent, URL query strings stripped unless you ask): VirusTotal (Part 8's key and
                  shared rate limit), abuse.ch URLhaus + ThreatFox (the same Auth-Key as MalwareBazaar), AbuseIPDB.
                  Deep check = open the page read-only through Part 14's web_probe (redirect chain, fake login forms,
                  brand look-alikes, certificate age, domain age via RDAP).
Feeds           - built-in free feeds (abuse.ch, Spamhaus, OpenPhish, ET, Tor) + custom https feeds + your block list,
                  refreshed in the background with ETag / size caps; bad downloads never wipe the last good copy.
IOC search      - search the local intel database; "hunt" = where an indicator was seen on THIS PC (scan detections,
                  quarantine, real-time downloads + Mark of the Web, hashed files, network / firewall events,
                  web scanner targets, activity log).
Live protection - every minute this PC's internet connections (Part 10) are matched against the feeds; matches alert
                  and can be blocked in one click / automatically (intel_auto_block) through the Part 9 firewall.
                  Feed file hashes become Part 5 antivirus signatures (source intel:<feed>); new feed data is
                  retro-hunted against files already hashed and files downloaded earlier.

Feeds Part 18 through health(user_id) and Part 17 through intel_events.
"""
from __future__ import annotations

import base64
import bisect
import csv
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from ..database import Database
from ..logger import get_logger
from . import intel_feeds as feeds
from . import ioc
from . import phishing as ph
from . import web_probe as wp

log = get_logger("intel")

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV = {s: i for i, s in enumerate(SEVERITIES)}
SEV_POINTS = {"critical": 100, "high": 90, "medium": 65, "low": 40, "info": 25}
MATCH_PENALTY = {"exact": 0, "cidr": 5, "parent_domain": 10, "url_host": 25, "email_domain": 15, "signature": 0,
                 "cloud_cache": 0}
VERDICTS = ("malicious", "suspicious", "low_risk", "clean", "unknown")
ONLINE_PROVIDERS = ("virustotal", "abusech", "abuseipdb")
PROVIDER_LABELS = {"virustotal": "VirusTotal", "abusech": "abuse.ch (URLhaus + ThreatFox)", "abuseipdb": "AbuseIPDB",
                   "malwarebazaar": "MalwareBazaar", "rdap": "Domain registry (RDAP)"}
VT_BASE = "https://www.virustotal.com/api/v3"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
RDAP_URL = "https://rdap.org/domain/{}"
ABUSEIPDB_KEY_URL = "https://www.abuseipdb.com/account/api"
MAX_BULK = 500
MAX_ONLINE_BULK = 20
MAX_BLOCK_ADD = 5000
EVENT_KINDS = ("connection_match", "retro_file", "retro_download", "feed_error", "feed_needs_key", "auto_block")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s[:19].replace(" ", "T"), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _ago(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def _csv_safe(v: Any) -> Any:
    return "'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v       # CSV formula-injection guard


class IntelError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.message, self.retry_after = status, message, retry_after


class _Job:
    def __init__(self, kind: str, username: str, feed_ids: list[int] | None, force: bool):
        self.id = secrets.token_hex(8)
        self.kind, self.username, self.feed_ids, self.force = kind, username, feed_ids, force
        self.status = "running"
        self.created_at = _now()
        self.finished_at: str | None = None
        self.progress = {"done": 0, "total": 0, "current": None, "percent": 0}
        self.result: dict = {}
        self.error: str | None = None

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "by": self.username,
                "created_at": self.created_at, "finished_at": self.finished_at, "progress": dict(self.progress),
                "result": self.result, "error": self.error}


class ThreatIntelService:
    def __init__(self, db: Database, settings, activity, vault=None, cloud=None, malware_db=None, network=None,
                 firewall=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.vault, self.cloud, self.malware_db = vault, cloud, malware_db
        self.network, self.firewall = network, firewall
        self.transport = feeds.urllib_transport           # tests swap this for a fake
        self.timeout = 30.0
        self._lock = threading.RLock()
        self._jobs: dict[str, _Job] = {}
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._gen = 0
        self._cidr_cache: tuple[int, dict] | None = None
        self._allow_cache: tuple[int, list] | None = None
        self._recent: dict[str, deque] = {p: deque() for p in ("abusech", "abuseipdb", "rdap")}
        self._last_watch = 0.0
        self.stats = {"watch_runs": 0, "connections_checked": 0, "matches": 0, "auto_blocked": 0}
        self._seed()

    # ================================================================== setup
    def _seed(self) -> None:
        with self.db.tx() as c:
            for f in feeds.CATALOG:
                c.execute("INSERT OR IGNORE INTO intel_feeds(key, name, provider, url, format, category, severity, "
                          "builtin, enabled, created_by) VALUES (?,?,?,?,?,?,?,1,?, 'builtin')",
                          (f["key"], f["name"], f["provider"], f["url"], f["format"], f["category"], f["severity"],
                           int(f["enabled"])))
                c.execute("UPDATE intel_feeds SET name=?, provider=?, url=?, format=?, category=?, severity=? "
                          "WHERE key=? AND builtin=1", (f["name"], f["provider"], f["url"], f["format"],
                                                        f["category"], f["severity"], f["key"]))
            c.execute("INSERT OR IGNORE INTO intel_feeds(key, name, provider, url, format, category, severity, builtin, "
                      "enabled, status, created_by) VALUES ('local', 'Your block list', 'You', NULL, 'auto', "
                      "'blocklist', 'high', 1, 1, 'manual', 'builtin')")

    def _g(self, key: str):
        return self.settings.get(key)

    def _state(self, key: str, value: Any = ...) -> Any:
        if value is ...:
            r = self.db.fetchone("SELECT value FROM intel_state WHERE key=?", (key,))
            return json.loads(r["value"]) if r else None
        self.db.execute("INSERT INTO intel_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))
        return value

    def _changed(self) -> None:
        with self._lock:
            self._gen += 1

    def _event(self, kind: str, severity: str, title: str, detail: str | None = None, data: dict | None = None,
               ref: str | None = None, uid: int | None = None) -> int:
        cur = self.db.execute("INSERT INTO intel_events(user_id, kind, severity, title, detail, ref, data) "
                              "VALUES (?,?,?,?,?,?,?)", (uid, kind, severity, title, detail, ref,
                                                         json.dumps(data) if data else None))
        try:
            self.activity.record("intel", title, detail, severity=severity, source="intel")
        except ValueError:                                              # pragma: no cover
            pass
        return cur.lastrowid

    def _has_event(self, ref: str) -> bool:
        return self.db.fetchone("SELECT 1 FROM intel_events WHERE ref=? LIMIT 1", (ref,)) is not None

    @staticmethod
    def _is_admin(cu) -> bool:
        return cu is None or cu.user.get("role") == "admin"

    def _need_admin(self, cu, what: str) -> None:
        if not self._is_admin(cu):
            raise IntelError(403, f"Administrator rights required to {what}")

    # ================================================================== feeds
    def _feed_row(self, fid: int | str) -> dict:
        r = self.db.fetchone("SELECT * FROM intel_feeds WHERE " + ("id=?" if isinstance(fid, int) else "key=?"), (fid,))
        if not r:
            raise IntelError(404, "Feed not found")
        return r

    def _abusech_key(self) -> str | None:
        return self.cloud.key_for("malwarebazaar") if self.cloud is not None else None

    def _hours(self, f: dict) -> int:
        cat = feeds.CATALOG_BY_KEY.get(f["key"]) if f["builtin"] else None
        h = int(f["refresh_hours"] or self._g("intel_update_hours"))
        return max(h, int(cat.get("min_hours", 1)) if cat else 1)

    def _feed_public(self, f: dict) -> dict:
        cat = feeds.CATALOG_BY_KEY.get(f["key"]) if f["builtin"] else None
        out = {k: f[k] for k in ("id", "key", "name", "provider", "format", "category", "severity", "status",
                                 "last_fetch_at", "last_ok_at", "last_error", "ioc_count", "skipped", "created_at",
                                 "refresh_hours")}
        out["url"] = (f["url"] or "").replace("{key}", "<your-abuse.ch-key>") or None
        out["builtin"], out["enabled"] = bool(f["builtin"]), bool(f["enabled"])
        out["local"] = f["key"] == "local"
        out["category_label"] = feeds.CATEGORIES.get(f["category"], f["category"])
        out["types"] = cat["types"] if cat else None
        out["description"] = cat.get("description") if cat else None
        out["homepage"] = cat.get("homepage") if cat else None
        out["license"] = cat.get("license") if cat else None
        need = cat.get("auth") if cat else None
        out["needs_key"] = need
        out["key_required"] = bool(need and not cat.get("auth_optional"))
        out["key_ready"] = bool(self._abusech_key()) if need == "abusech" else None
        if need == "abusech":
            out["key_help"] = ("Free abuse.ch Auth-Key from https://auth.abuse.ch/ - save it once under Online "
                               "lookup (/api/lookup/keys, provider malwarebazaar); it works for every abuse.ch feed")
        out["effective_hours"] = self._hours(f) if f["url"] else None
        last = _parse_ts(f["last_fetch_at"])
        out["next_due"] = ((last + timedelta(hours=self._hours(f))).strftime("%Y-%m-%dT%H:%M:%SZ")
                           if last and f["url"] and f["enabled"] else None)
        ok = _parse_ts(f["last_ok_at"])
        out["stale"] = bool(f["url"] and f["enabled"] and (not ok or datetime.now(timezone.utc) - ok >
                                                           timedelta(hours=max(24, 3 * self._hours(f)))))
        return out

    def feeds(self) -> dict:
        rows = self.db.fetchall("SELECT * FROM intel_feeds ORDER BY builtin DESC, key='local' DESC, id")
        items = [self._feed_public(r) for r in rows]
        return {"items": items, "total_iocs": sum(f["ioc_count"] for f in items if f["enabled"]),
                "abusech_key": bool(self._abusech_key()), "categories": feeds.CATEGORIES,
                "formats": list(feeds.CUSTOM_FORMATS)}

    def feed(self, fid: int) -> dict:
        f = self._feed_public(self._feed_row(fid))
        f["by_type"] = {r["type"]: r["n"] for r in self.db.fetchall(
            "SELECT type, COUNT(*) AS n FROM intel_iocs WHERE feed_id=? GROUP BY type", (fid,))}
        f["top_threats"] = self.db.fetchall("SELECT threat, COUNT(*) AS n FROM intel_iocs WHERE feed_id=? AND threat "
                                            "IS NOT NULL GROUP BY threat ORDER BY n DESC LIMIT 15", (fid,))
        return f

    def add_feed(self, cu, name: str, url: str, fmt: str = "auto", column: str | None = None,
                 category: str = "custom", severity: str = "high", refresh_hours: int | None = None,
                 enabled: bool = True) -> dict:
        self._need_admin(cu, "add threat feeds")
        name = (name or "").strip()[:80]
        if not name:
            raise IntelError(422, "Give the feed a name")
        if fmt not in feeds.CUSTOM_FORMATS:
            raise IntelError(422, f"format must be one of {', '.join(feeds.CUSTOM_FORMATS)}")
        if category not in feeds.CATEGORIES or category in ("blocklist",):
            raise IntelError(422, "Unknown category")
        if severity not in SEVERITIES:
            raise IntelError(422, "Unknown severity")
        try:
            url = feeds.check_custom_url(url, resolve=False)
        except feeds.FeedError as e:
            raise IntelError(e.status, e.message)
        if self.db.fetchone("SELECT 1 FROM intel_feeds WHERE url=?", (url,)):
            raise IntelError(409, "That feed is already in the list")
        key = "custom_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:30] + "_" + secrets.token_hex(3)
        cur = self.db.execute("INSERT INTO intel_feeds(key, name, provider, url, format, column_spec, category, "
                              "severity, builtin, enabled, refresh_hours, created_by) VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
                              (key, name, urllib.parse.urlsplit(url).hostname, url, fmt, column, category, severity,
                               int(enabled), refresh_hours, cu.user["username"] if cu else "system"))
        self.activity.record("intel", f"Threat feed added: {name}", url, severity="low", source="intel")
        return self.feed(cur.lastrowid)

    def update_feed(self, cu, fid: int, enabled: bool | None = None, refresh_hours: int | None = ...,
                    severity: str | None = None, name: str | None = None) -> dict:
        f = self._feed_row(fid)
        lowering = enabled is False or severity is not None or name is not None or refresh_hours is not ...
        if lowering:
            self._need_admin(cu, "change or switch off threat feeds")
        sets, params = [], []
        if enabled is not None:
            if f["key"] == "local" and not enabled:
                raise IntelError(409, "Your block list can't be switched off - remove entries instead")
            sets.append("enabled=?"); params.append(int(enabled))
        if refresh_hours is not ...:
            if refresh_hours is not None and not 1 <= int(refresh_hours) <= 720:
                raise IntelError(422, "refresh_hours must be 1-720")
            sets.append("refresh_hours=?"); params.append(refresh_hours)
        if severity is not None:
            if severity not in SEVERITIES:
                raise IntelError(422, "Unknown severity")
            sets.append("severity=?"); params.append(severity)
        if name is not None:
            if f["builtin"]:
                raise IntelError(409, "Built-in feeds keep their name")
            sets.append("name=?"); params.append(name.strip()[:80] or f["name"])
        if sets:
            self.db.execute(f"UPDATE intel_feeds SET {', '.join(sets)} WHERE id=?", tuple(params) + (fid,))
            self._changed()
        if enabled is not None and bool(enabled) != bool(f["enabled"]):
            self.activity.record("intel", f"Threat feed {'on' if enabled else 'OFF'}: {f['name']}",
                                 f"by {cu.user['username'] if cu else 'system'}",
                                 severity="info" if enabled else "medium", source="intel")
            if not enabled:
                self._remove_signatures(f["key"])
            else:
                self._sync_signatures(self._feed_row(fid))
        return self.feed(fid)

    def delete_feed(self, cu, fid: int) -> dict:
        self._need_admin(cu, "remove threat feeds")
        f = self._feed_row(fid)
        if f["builtin"]:
            raise IntelError(409, "Built-in feeds can't be removed - switch them off instead")
        self._remove_signatures(f["key"])
        self.db.execute("DELETE FROM intel_feeds WHERE id=?", (fid,))
        self._changed()
        self.activity.record("intel", f"Threat feed removed: {f['name']}", severity="low", source="intel")
        return {"deleted": fid, "iocs_removed": f["ioc_count"]}

    # ------------------------------------------------------------------ refresh jobs
    def due_feeds(self) -> list[dict]:
        out = []
        for f in self.db.fetchall("SELECT * FROM intel_feeds WHERE enabled=1 AND url IS NOT NULL"):
            last = _parse_ts(f["last_fetch_at"])
            if not last or datetime.now(timezone.utc) - last >= timedelta(hours=self._hours(f)):
                out.append(f)
        return out

    def refresh(self, cu=None, feed_ids: list[int] | None = None, force: bool = False, wait: bool = False) -> dict:
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
            if running:
                raise IntelError(409, "Feeds are already being updated", )
            if feed_ids:
                for fid in feed_ids:
                    f = self._feed_row(fid)
                    if not f["url"]:
                        raise IntelError(409, f"'{f['name']}' has no download address")
            job = _Job("refresh", cu.user["username"] if cu else "system", feed_ids, force)
            self._jobs[job.id] = job
            for old in sorted(self._jobs.values(), key=lambda j: j.created_at)[:-20]:
                if old.status != "running":
                    self._jobs.pop(old.id, None)
        t = threading.Thread(target=self._run_refresh, args=(job,), name="intel-refresh", daemon=True)
        self._thread = t
        t.start()
        if wait:
            t.join(600)
        return job.public()

    def job(self, job_id: str) -> dict:
        j = self._jobs.get(job_id)
        if not j:
            raise IntelError(404, "Job not found")
        return j.public()

    def jobs(self) -> dict:
        items = sorted((j.public() for j in self._jobs.values()), key=lambda j: j["created_at"], reverse=True)
        return {"items": items, "running": [j for j in items if j["status"] == "running"]}

    def wait(self, job_id: str, timeout: float = 120) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            j = self._jobs.get(job_id)
            if j and j.status != "running":
                return j.public()
            time.sleep(0.05)
        return self.job(job_id)

    def _run_refresh(self, job: _Job) -> None:
        try:
            if job.feed_ids:
                rows = [self._feed_row(i) for i in job.feed_ids]
            elif job.force:
                rows = self.db.fetchall("SELECT * FROM intel_feeds WHERE enabled=1 AND url IS NOT NULL ORDER BY id")
            else:
                rows = self.due_feeds()
            job.progress["total"] = len(rows)
            results = []
            for i, f in enumerate(rows):
                if self._stopping.is_set():
                    job.status = "cancelled"
                    break
                job.progress.update(current=f["name"], done=i, percent=int(100 * i / max(1, len(rows))))
                results.append(self._refresh_feed(f, force=job.force))
            job.progress.update(done=len(results), current=None, percent=100)
            changed = [r for r in results if r.get("changed")]
            retro = self.retro_hunt() if changed and self._g("intel_retro_hunt") else {"files": 0, "downloads": 0}
            job.result = {"feeds": results, "updated": len(changed),
                          "errors": sum(1 for r in results if r["status"] == "error"),
                          "needs_key": [r["key"] for r in results if r["status"] == "needs_key"],
                          "total_iocs": self.db.fetchone("SELECT COUNT(*) AS n FROM intel_iocs i JOIN intel_feeds f "
                                                         "ON f.id=i.feed_id WHERE f.enabled=1")["n"],
                          "retro_hunt": retro}
            if job.status == "running":
                job.status = "done"
        except Exception as e:                                              # pragma: no cover - safety net
            log.exception("Feed refresh failed")
            job.status, job.error = "error", str(e)
        finally:
            job.finished_at = _now()

    def _refresh_feed(self, f: dict, force: bool = False) -> dict:
        cat = feeds.CATALOG_BY_KEY.get(f["key"]) if f["builtin"] else None
        out = {"id": f["id"], "key": f["key"], "name": f["name"], "status": "ok", "changed": False}
        url, headers = f["url"], {"Accept": "*/*"}
        need = cat.get("auth") if cat else None
        if need == "abusech":
            key = self._abusech_key()
            if not key and not cat.get("auth_optional"):
                self.db.execute("UPDATE intel_feeds SET status='needs_key', last_error=?, last_fetch_at=? WHERE id=?",
                                ("Needs a free abuse.ch Auth-Key (https://auth.abuse.ch/)", _now(), f["id"]))
                out.update(status="needs_key", message="abuse.ch Auth-Key needed")
                return out
            if key:
                if cat.get("auth_in") == "path":
                    url = url.replace("{key}", urllib.parse.quote(key, safe=""))
                else:
                    headers["Auth-Key"] = key
        if not force:
            if f["etag"]:
                headers["If-None-Match"] = f["etag"]
            if f["last_modified"]:
                headers["If-Modified-Since"] = f["last_modified"]
        max_bytes = int(self._g("intel_max_feed_mb")) * 1024 * 1024
        now = _now()

        def fail(msg: str, status: str = "error") -> dict:
            self.db.execute("UPDATE intel_feeds SET status=?, last_error=?, last_fetch_at=? WHERE id=?",
                            (status, msg[:300], now, f["id"]))
            ref = f"feed_error:{f['key']}:{now[:10]}"
            if status == "error" and f["status"] == "ok" and not self._has_event(ref):
                self._event("feed_error", "low", f"Threat feed update failed: {f['name']}", msg[:300],
                            {"feed": f["key"]}, ref=ref)
            out.update(status=status, message=msg)
            return out
        try:
            if self.transport is feeds.urllib_transport:
                status, body, rh = feeds.urllib_transport("GET", url, headers, None, self.timeout, max_bytes,
                                                          strict=not f["builtin"])
            else:
                status, body, rh = self.transport("GET", url, headers, None, self.timeout)
        except feeds.FeedError as e:
            return fail(e.message)
        except Exception as e:
            return fail(f"Download failed: {type(e).__name__}: {str(e)[:150]}".replace(
                self._abusech_key() or "\0", "<key>"))
        if status == 304:
            self.db.execute("UPDATE intel_feeds SET status='ok', last_error=NULL, last_fetch_at=?, last_ok_at=? "
                            "WHERE id=?", (now, now, f["id"]))
            out["message"] = "Not changed since the last download"
            return out
        if status in (401, 403):
            if need == "abusech" and not self._abusech_key():
                return fail("abuse.ch now asks for a free Auth-Key - add one (https://auth.abuse.ch/)", "needs_key")
            return fail(f"Access denied by the feed server ({status})" +
                        (" - abuse.ch rejected the Auth-Key; create a new one at https://auth.abuse.ch/"
                         if need == "abusech" else ""))
        if status == 429:
            return fail("The feed server says we're asking too often (429) - will retry later")
        if status != 200:
            return fail(f"Feed server answered HTTP {status}")
        if len(body) > max_bytes:
            return fail(f"Feed larger than intel_max_feed_mb ({self._g('intel_max_feed_mb')} MB)")
        import hashlib
        digest = hashlib.sha256(body).hexdigest()
        if digest == f["sha256"] and not force and f["ioc_count"]:
            self.db.execute("UPDATE intel_feeds SET status='ok', last_error=NULL, last_fetch_at=?, last_ok_at=?, "
                            "etag=?, last_modified=? WHERE id=?", (now, now, rh.get("etag"), rh.get("last-modified"),
                                                                   f["id"]))
            out["message"] = "Same content as last time"
            return out
        try:
            text = feeds.decode(feeds.unpack(body, max_bytes))
            items, bad = feeds.parse(f["format"], text, cat.get("types") if cat else None, f["column_spec"])
        except feeds.FeedError as e:
            return fail(e.message)
        if not items:
            msg = "The download contained no usable indicators"
            if f["ioc_count"]:
                msg += " - keeping the previous copy"
            return fail(msg)
        n = self._store(f, items)
        self.db.execute("UPDATE intel_feeds SET status='ok', last_error=NULL, last_fetch_at=?, last_ok_at=?, etag=?, "
                        "last_modified=?, sha256=?, ioc_count=?, skipped=? WHERE id=?",
                        (now, now, rh.get("etag"), rh.get("last-modified"), digest, n, bad, f["id"]))
        self._changed()
        self._sync_signatures(self._feed_row(f["id"]))
        out.update(changed=True, iocs=n, skipped=bad, previous=f["ioc_count"])
        log.info("Feed %s updated: %d indicators (%d skipped)", f["key"], n, bad)
        return out

    def _rows(self, feed_id: int, items: list[dict], added_by: str | None = None, note: str | None = None,
              severity: str | None = None):
        for it in items:
            ver = lo = hi = None
            if it["type"] == "cidr":
                ver, lo, hi = ioc.net_range(it["value"])
            yield (feed_id, it["type"], it["value"], it.get("host"), it.get("port"), ver, lo, hi,
                   (it.get("threat") or None) and str(it["threat"])[:120], it.get("category"),
                   severity or it.get("severity"), it.get("confidence"), (it.get("tags") or None) and
                   str(it["tags"])[:200], it.get("first_seen"), (it.get("ref") or None) and str(it["ref"])[:300],
                   note, added_by)

    def _store(self, f: dict, items: list[dict]) -> int:
        """Replace a feed's indicators in one transaction (readers never see a half-loaded feed)."""
        with self.db.tx() as c:
            c.execute("DELETE FROM intel_iocs WHERE feed_id=?", (f["id"],))
            c.executemany("INSERT OR IGNORE INTO intel_iocs(feed_id, type, value, host, port, ver, net_lo, net_hi, "
                          "threat, category, severity, confidence, tags, first_seen, ref, note, added_by) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self._rows(f["id"], items))
            n = c.execute("SELECT COUNT(*) FROM intel_iocs WHERE feed_id=?", (f["id"],)).fetchone()[0]
        return n

    # ------------------------------------------------------------------ Part 5 signatures
    def _remove_signatures(self, feed_key: str) -> int:
        if self.malware_db is None:
            return 0
        return self.malware_db.delete_source(f"intel:{feed_key}")

    def _sync_signatures(self, f: dict) -> int:
        """Feed hashes -> Part 5 antivirus signatures (source intel:<feed>). Never touches other sources."""
        if self.malware_db is None:
            return 0
        src = f"intel:{f['key']}"
        if not (self._g("intel_hashes_to_signatures") and f["enabled"]):
            self._remove_signatures(f["key"])
            return 0
        rows = self.db.fetchall("SELECT type, value, threat, COALESCE(severity, ?) AS sev FROM intel_iocs "
                                "WHERE feed_id=? AND type IN ('md5','sha1','sha256')", (f["severity"], f["id"]))
        short = f["name"].split(" - ")[0][:30]
        sev = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        with self.db.tx() as c:
            c.execute("DELETE FROM malware_signatures WHERE source=?", (src,))
            c.executemany("INSERT INTO malware_signatures(hash, hash_type, name, family, severity, source) "
                          "VALUES (?,?,?,?,?,?) ON CONFLICT(hash) DO NOTHING",
                          [(r["value"], r["type"], f"{r['threat'] or 'Malware.Generic'} [{short}]"[:120],
                            r["threat"], sev.get(r["sev"], "high"), src) for r in rows])
        return len(rows)

    def resync_signatures(self) -> int:
        n = 0
        for f in self.db.fetchall("SELECT * FROM intel_feeds"):
            n += self._sync_signatures(f)
        return n

    # ================================================================== allow list
    def _allow_entries(self) -> list[dict]:
        with self._lock:
            if self._allow_cache and self._allow_cache[0] == self._gen:
                return self._allow_cache[1]
        rows = self.db.fetchall("SELECT * FROM intel_allow")
        with self._lock:
            self._allow_cache = (self._gen, rows)
        return rows

    def allowed(self, c: dict) -> dict | None:
        """The allow-list entry covering this indicator (domain entries cover sub-domains and URLs on them)."""
        entries = self._allow_entries()
        if not entries:
            return None
        t, v = c["type"], c["value"]
        hosts: list[str] = []
        if t in ("domain",):
            hosts = ioc.parent_domains(v)
        elif t == "url" and not c.get("ip"):
            hosts = ioc.parent_domains(c["host"])
        elif t == "email":
            hosts = ioc.parent_domains(c["domain"])
        ip = v if t == "ip" else c.get("ip") if t == "url" else None
        for e in entries:
            if e["type"] == t and e["value"] == v:
                return e
            if e["type"] == "domain" and e["value"] in hosts:
                return e
            if ip and e["type"] == "ip" and e["value"] == ip:
                return e
            if ip and e["type"] == "cidr":
                try:
                    import ipaddress
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(e["value"]):
                        return e
                except ValueError:
                    pass
        return None

    def allow_list(self) -> dict:
        return {"items": self.db.fetchall("SELECT * FROM intel_allow ORDER BY created_at DESC")}

    def allow_add(self, cu, value: str, note: str | None = None) -> dict:
        self._need_admin(cu, "add allow-list entries (they switch protection off for that address)")
        c = self._classify(value)
        if c["type"] == "cidr" and c["size"] > 65536:
            raise IntelError(422, "Allow-listing a network bigger than /16 is not allowed")
        if c["type"] == "domain" and ioc.registrable(c["value"]) != c["value"] and "." not in c["value"]:
            raise IntelError(422, "Too broad")
        self.db.execute("INSERT INTO intel_allow(type, value, note, created_by) VALUES (?,?,?,?) ON CONFLICT(type, value) "
                        "DO UPDATE SET note=excluded.note", (c["type"], c["value"], (note or "")[:200] or None,
                                                             cu.user["username"] if cu else "system"))
        self._changed()
        self.activity.record("intel", f"Allowed by threat intel: {c['value']}", note, severity="medium", source="intel")
        return self.db.fetchone("SELECT * FROM intel_allow WHERE type=? AND value=?", (c["type"], c["value"]))

    def allow_remove(self, cu, aid: int) -> dict:
        n = self.db.execute("DELETE FROM intel_allow WHERE id=?", (aid,)).rowcount
        if not n:
            raise IntelError(404, "Allow-list entry not found")
        self._changed()
        return {"deleted": aid}

    # ================================================================== block list (feed 'local')
    def _local(self) -> dict:
        return self._feed_row("local")

    def blocklist(self, q: str | None = None, limit: int = 100, offset: int = 0) -> dict:
        f = self._local()
        where, params = ["feed_id=?"], [f["id"]]
        if q:
            where.append("(value LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')")
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params += [like, like]
        w = " AND ".join(where)
        rows = self.db.fetchall(f"SELECT id, type, value, severity, note, added_by, added_at FROM intel_iocs WHERE {w} "
                                "ORDER BY id DESC LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM intel_iocs WHERE {w}", tuple(params))["n"]
        for r in rows:
            r["defanged"] = ioc.defang(r["value"], r["type"])
        return {"items": rows, "total": total, "limit": limit, "offset": offset}

    def block_add(self, cu, values: list[str] | None = None, text: str | None = None, severity: str = "high",
                  note: str | None = None) -> dict:
        if severity not in SEVERITIES:
            raise IntelError(422, "Unknown severity")
        items, invalid = [], []
        for v in values or []:
            try:
                items.append(self._classify(v))
            except IntelError:
                invalid.append(v[:100])
        if text:
            got, bad = ioc.extract(text, limit=MAX_BLOCK_ADD)
            items += got
            if bad:
                invalid.append(f"{bad} unreadable item(s) in the text")
        if not items:
            raise IntelError(422, "Nothing to add - enter IPs, domains, URLs, e-mails or hashes")
        if len(items) > MAX_BLOCK_ADD:
            raise IntelError(422, f"At most {MAX_BLOCK_ADD} entries at once")
        refused = []
        keep = []
        for c in items:
            if c["type"] == "ip" and c.get("scope") in ("loopback",):
                refused.append({"value": c["value"], "reason": "This PC's own address"})
            elif c["type"] == "cidr" and c.get("size", 0) > 2 ** 24:
                refused.append({"value": c["value"], "reason": "Networks bigger than /8 are refused"})
            elif c["type"] == "domain" and c.get("local"):
                refused.append({"value": c["value"], "reason": "Local network name"})
            else:
                keep.append(c)
        f = self._local()
        before = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_iocs WHERE feed_id=?", (f["id"],))["n"]
        by = cu.user["username"] if cu else "system"
        with self.db.tx() as con:
            con.executemany(
                "INSERT INTO intel_iocs(feed_id, type, value, host, port, ver, net_lo, net_hi, threat, category, "
                "severity, confidence, tags, first_seen, ref, note, added_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(feed_id, type, value) DO UPDATE SET severity=excluded.severity, "
                "note=COALESCE(excluded.note, intel_iocs.note)",
                list(self._rows(f["id"], [dict(c, host=c.get("host") if c["type"] == "url" else None,
                                               port=None, threat=None) for c in keep],
                                added_by=by, note=(note or "")[:200] or None, severity=severity)))
        n = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_iocs WHERE feed_id=?", (f["id"],))["n"]
        self.db.execute("UPDATE intel_feeds SET ioc_count=?, last_ok_at=? WHERE id=?", (n, _now(), f["id"]))
        self._changed()
        self._sync_signatures(self._feed_row(f["id"]))
        retro = None
        if keep:
            self.activity.record("intel", f"Block list: {n - before} added, {len(keep) - (n - before)} updated",
                                 f"by {by}", source="intel")
            if self._g("intel_retro_hunt"):
                retro = self.retro_hunt()                   # was something you just blocked already on this PC?
        return {"added": n - before, "updated": len(keep) - (n - before), "refused": refused, "invalid": invalid,
                "total": n, "retro_hunt": retro}

    def block_remove(self, cu, ids: list[int] | None = None, value: str | None = None) -> dict:
        self._need_admin(cu, "remove block-list entries")
        f = self._local()
        if value:
            c = self._classify(value)
            n = self.db.execute("DELETE FROM intel_iocs WHERE feed_id=? AND type=? AND value=?",
                                (f["id"], c["type"], c["value"])).rowcount
        elif ids:
            q = ",".join("?" * len(ids))
            n = self.db.execute(f"DELETE FROM intel_iocs WHERE feed_id=? AND id IN ({q})", (f["id"], *ids)).rowcount
        else:
            raise IntelError(422, "Give ids or value")
        if not n:
            raise IntelError(404, "Not on your block list")
        total = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_iocs WHERE feed_id=?", (f["id"],))["n"]
        self.db.execute("UPDATE intel_feeds SET ioc_count=? WHERE id=?", (total, f["id"]))
        self._changed()
        self._sync_signatures(self._feed_row(f["id"]))
        return {"deleted": n, "total": total}

    def import_iocs(self, cu, text: str | None = None, path: str | None = None, fmt: str = "auto",
                    column: str | None = None, severity: str = "high", note: str | None = None) -> dict:
        """Import a list / CSV / STIX bundle into your block list."""
        if bool(text) == bool(path):
            raise IntelError(422, "Send either text or path")
        if fmt not in feeds.CUSTOM_FORMATS:
            raise IntelError(422, f"format must be one of {', '.join(feeds.CUSTOM_FORMATS)}")
        max_bytes = int(self._g("intel_max_feed_mb")) * 1024 * 1024
        if path:
            p = os.path.abspath(os.path.expanduser(path))
            if not os.path.isfile(p):
                raise IntelError(404, "File not found")
            if os.path.getsize(p) > max_bytes:
                raise IntelError(413, "File larger than intel_max_feed_mb")
            with open(p, "rb") as fh:
                raw = fh.read(max_bytes + 1)
            try:
                text = feeds.decode(feeds.unpack(raw, max_bytes))
            except feeds.FeedError as e:
                raise IntelError(e.status, e.message)
        try:
            items, bad = feeds.parse(fmt, text or "", None, column)
        except feeds.FeedError as e:
            raise IntelError(e.status, e.message)
        if not items:
            raise IntelError(422, "No indicators found in that list")
        if len(items) > 200_000:
            raise IntelError(413, "More than 200,000 indicators - add it as a feed instead")
        values = [i["value"] for i in items]
        res = self._block_many(cu, values, severity, note)
        res["skipped"] = bad
        return res

    def _block_many(self, cu, values: list[str], severity: str, note: str | None) -> dict:
        out = {"added": 0, "updated": 0, "refused": [], "invalid": [], "total": 0}
        for i in range(0, len(values), MAX_BLOCK_ADD):
            r = self.block_add(cu, values=values[i:i + MAX_BLOCK_ADD], severity=severity, note=note)
            for k in ("added", "updated"):
                out[k] += r[k]
            out["refused"] += r["refused"][:50]
            out["invalid"] += r["invalid"][:50]
            out["total"] = r["total"]
        return out

    def export(self, fmt: str = "csv", what: str = "blocklist") -> tuple[bytes, str, str]:
        if what == "blocklist":
            rows = self.db.fetchall("SELECT i.type, i.value, i.severity, i.note, i.added_by, i.added_at FROM intel_iocs i "
                                    "JOIN intel_feeds f ON f.id=i.feed_id WHERE f.key='local' ORDER BY i.id")
        elif what == "matches":
            rows = []
            for e in self.db.fetchall("SELECT * FROM intel_events WHERE kind IN ('connection_match','retro_file',"
                                      "'retro_download','auto_block') ORDER BY id"):
                d = json.loads(e["data"]) if e["data"] else {}
                rows.append({"type": d.get("type") or ("ip" if d.get("ip") else "sha256" if d.get("sha256") else "domain"),
                             "value": d.get("ip") or d.get("sha256") or d.get("host") or "", "severity": e["severity"],
                             "note": e["title"], "added_by": "cyberhub", "added_at": e["ts"]})
        else:
            raise IntelError(422, "what must be blocklist or matches")
        day = _now()[:10]
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["type", "value", "severity", "note", "added_by", "added_at"])
            for r in rows:
                w.writerow([_csv_safe(r[k]) for k in ("type", "value", "severity", "note", "added_by", "added_at")])
            return buf.getvalue().encode("utf-8-sig"), "text/csv", f"cyberhub-{what}-{day}.csv"
        if fmt == "txt":
            body = "# Cyber Hub - Developed by Syed Muhammad Tayyab\n# " + what + " exported " + day + "\n" + \
                   "\n".join(r["value"] for r in rows) + "\n"
            return body.encode(), "text/plain", f"cyberhub-{what}-{day}.txt"
        if fmt == "stix":
            return (json.dumps(ioc.to_stix([dict(r, threat=r.get("note")) for r in rows]), indent=1).encode(),
                    "application/json", f"cyberhub-{what}-{day}.stix.json")
        if fmt == "json":
            return json.dumps({"exported": day, "what": what, "items": rows}, indent=1).encode(), "application/json", \
                f"cyberhub-{what}-{day}.json"
        raise IntelError(422, "format must be csv, txt, stix or json")

    # ================================================================== matching
    def _classify(self, value: str) -> dict:
        try:
            return ioc.classify(value)
        except ioc.IOCError as e:
            raise IntelError(422, str(e))

    _HIT_SQL = ("SELECT i.id, i.type, i.value, i.host, i.port, i.threat, i.category, i.severity, i.confidence, i.tags, "
                "i.first_seen, i.ref, i.note, f.key AS feed_key, f.name AS feed_name, f.category AS feed_category, "
                "f.severity AS feed_severity, f.provider FROM intel_iocs i JOIN intel_feeds f ON f.id=i.feed_id "
                "WHERE f.enabled=1 AND ")

    @staticmethod
    def _hit(r: dict, on: str) -> dict:
        sev = r.get("severity") or r.get("feed_severity") or "high"
        cat = r.get("category") or r.get("feed_category") or "custom"
        if on == "url_host" and SEV[sev] > SEV["medium"]:
            sev = "medium"
        return {"feed": r.get("feed_key"), "feed_name": r.get("feed_name"), "provider": r.get("provider"),
                "type": r["type"], "value": r["value"], "defanged": ioc.defang(r["value"], r["type"]), "matched_on": on,
                "threat": r.get("threat"), "category": cat, "category_label": feeds.CATEGORIES.get(cat, cat),
                "severity": sev, "confidence": r.get("confidence"), "first_seen": r.get("first_seen"),
                "ref": r.get("ref"), "tags": r.get("tags"), "note": r.get("note"), "port": r.get("port"),
                "points": max(0, SEV_POINTS[sev] - MATCH_PENALTY.get(on, 0))}

    def _cidrs(self) -> dict:
        """{4: (los, his, prefmax, rows), 6: ...} - IP ranges of enabled feeds, rebuilt after changes."""
        with self._lock:
            if self._cidr_cache and self._cidr_cache[0] == self._gen:
                return self._cidr_cache[1]
        rows = self.db.fetchall(self._HIT_SQL.replace("SELECT i.id,", "SELECT i.ver, i.net_lo, i.net_hi, i.id,") +
                                "i.type='cidr' AND i.net_lo IS NOT NULL ORDER BY i.ver, i.net_lo")
        out: dict[int, tuple] = {}
        for ver in (4, 6):
            rs = [r for r in rows if r["ver"] == ver]
            los = [int(r["net_lo"], 16) for r in rs]
            his = [int(r["net_hi"], 16) for r in rs]
            pref, m = [], -1
            for h in his:
                m = max(m, h)
                pref.append(m)
            out[ver] = (los, his, pref, rs)
        with self._lock:
            self._cidr_cache = (self._gen, out)
        return out

    def _cidr_hits(self, ip: str) -> list[dict]:
        try:
            ver, hx = ioc.ip_hex(ip)
        except ValueError:
            return []
        los, his, pref, rs = self._cidrs().get(ver, ([], [], [], []))
        x = int(hx, 16)
        j = bisect.bisect_right(los, x) - 1
        hits = []
        while j >= 0 and pref[j] >= x:
            if his[j] >= x:
                hits.append(self._hit(rs[j], "cidr"))
            j -= 1
        return hits

    def match(self, c: dict) -> list[dict]:
        """All local intel hits for a classified indicator, strongest first."""
        t, v = c["type"], c["value"]
        hits: list[dict] = []
        q = self.db.fetchall

        def exact(typ: str, vals: list[str], on: str = "exact") -> None:
            if not vals:
                return
            ph_ = ",".join("?" * len(vals))
            for r in q(self._HIT_SQL + f"i.type=? AND i.value IN ({ph_})", (typ, *vals)):
                hits.append(self._hit(r, on))

        def domains(host: str, first_on: str = "exact") -> None:
            ps = ioc.parent_domains(host)
            if not ps:
                return
            ph_ = ",".join("?" * len(ps))
            for r in q(self._HIT_SQL + f"i.type='domain' AND i.value IN ({ph_})", tuple(ps)):
                hits.append(self._hit(r, first_on if r["value"] == host else "parent_domain"))

        def url_host(host: str) -> None:
            if host in ph.SHARED_HOSTS or ioc.registrable(host) in ph.SHARED_HOSTS:
                return
            for r in q(self._HIT_SQL + "i.type='url' AND i.host=? LIMIT 25", (host,)):
                hits.append(self._hit(r, "url_host"))

        if t == "ip":
            exact("ip", [v])
            hits.extend(self._cidr_hits(v))
            url_host(v)
        elif t == "cidr":
            exact("cidr", [v])
            try:
                net = ioc.classify(v)
                first = str(__import__("ipaddress").ip_network(v).network_address)
                if net["size"] <= 65536:
                    hits.extend(h for h in self._cidr_hits(first) if h["value"] != v)
            except ValueError:
                pass
        elif t == "domain":
            domains(v)
            url_host(v)
        elif t == "url":
            exact("url", ioc.url_key_variants(v))
            if c.get("ip"):
                exact("ip", [c["ip"]], on="url_ip")
                for h in self._cidr_hits(c["ip"]):
                    hits.append(h)
            else:
                domains(c["host"], first_on="url_domain")
            urls = {h["value"] for h in hits if h["type"] == "url"}
            if not urls:
                url_host(c["host"])
        elif t == "email":
            exact("email", [v])
            for h in self._domain_only(c["domain"]):
                hits.append(h)
        elif t in ioc.HASH_TYPES:
            exact(t, [v])
            hits.extend(self._hash_extra(t, v))
        # one hit per (feed, value): keep the strongest
        best: dict[tuple, dict] = {}
        for h in hits:
            if h["matched_on"] == "url_domain":
                h["matched_on"] = "exact" if h["type"] == "domain" and h["value"] == c.get("host") else "parent_domain"
                h["points"] = max(0, SEV_POINTS[h["severity"]] - MATCH_PENALTY[h["matched_on"]])
            if h["matched_on"] == "url_ip":
                h["matched_on"] = "exact"
            k = (h["feed"], h["type"], h["value"])
            if k not in best or h["points"] > best[k]["points"]:
                best[k] = h
        return sorted(best.values(), key=lambda h: (-h["points"], h["feed"] or ""))

    def _domain_only(self, host: str) -> list[dict]:
        ps = ioc.parent_domains(host)
        ph_ = ",".join("?" * len(ps))
        return [dict(self._hit(r, "email_domain")) for r in
                self.db.fetchall(self._HIT_SQL + f"i.type='domain' AND i.value IN ({ph_})", tuple(ps))]

    def _hash_extra(self, t: str, v: str) -> list[dict]:
        """Part 5 signatures (not from intel feeds) + Part 8 cached cloud verdicts."""
        out = []
        if self.malware_db is not None:
            sig = self.malware_db.lookup(**{t: v})
            if sig and not str(sig.get("source", "")).startswith("intel:") and sig.get("enabled", True):
                sev = sig["severity"] if sig["severity"] in SEV else "high"
                out.append({"feed": "signatures", "feed_name": "Cyber Hub antivirus signatures (Part 5)",
                            "provider": "Cyber Hub", "type": t, "value": v, "defanged": v, "matched_on": "signature",
                            "threat": sig["name"], "category": "malware", "category_label": "Known malware",
                            "severity": sev, "confidence": None, "first_seen": sig.get("added_at"), "ref": None,
                            "tags": sig.get("source"), "note": None, "port": None, "points": SEV_POINTS[sev]})
        for r in self.db.fetchall("SELECT * FROM hash_reputation WHERE (hash=? OR sha256=?) AND verdict IN "
                                  "('malicious','suspicious')", (v, v)):
            sev = "critical" if r["verdict"] == "malicious" else "medium"
            out.append({"feed": f"cloud:{r['provider']}", "feed_name": f"{PROVIDER_LABELS.get(r['provider'], r['provider'])}"
                                                                    f" (cached by Part 8)",
                        "provider": r["provider"], "type": t, "value": v, "defanged": v, "matched_on": "cloud_cache",
                        "threat": r["threat_label"], "category": "malware", "category_label": "Known malware",
                        "severity": sev, "confidence": None, "first_seen": r["checked_at"], "ref": r["permalink"],
                        "tags": None, "note": f"{r['malicious']}/{r['total']} engines" if r["total"] else None,
                        "port": None, "points": 90 if sev == "critical" else 55})
        return out

    def match_ips(self, ips: list[str]) -> dict[str, list[dict]]:
        """Bulk matching for the connection watch: exact IPs, IP ranges, malware URLs hosted on the IP."""
        out: dict[str, list[dict]] = {}
        ips = list(dict.fromkeys(ips))
        for i in range(0, len(ips), 500):
            chunk = ips[i:i + 500]
            ph_ = ",".join("?" * len(chunk))
            for r in self.db.fetchall(self._HIT_SQL + f"i.type='ip' AND i.value IN ({ph_})", tuple(chunk)):
                out.setdefault(r["value"], []).append(self._hit(r, "exact"))
            for r in self.db.fetchall(self._HIT_SQL + f"i.type='url' AND i.host IN ({ph_})", tuple(chunk)):
                out.setdefault(r["host"], []).append(self._hit(r, "url_host"))
        for ip in ips:
            h = self._cidr_hits(ip)
            if h:
                out.setdefault(ip, []).extend(h)
        for ip in list(out):
            best: dict[tuple, dict] = {}
            for h in out[ip]:
                k = (h["feed"], h["type"], h["value"])
                if k not in best or h["points"] > best[k]["points"]:
                    best[k] = h
            out[ip] = sorted(best.values(), key=lambda h: -h["points"])
        return out

    # ================================================================== online reputation
    def _cache_get(self, provider: str, t: str, v: str) -> dict | None:
        r = self.db.fetchone("SELECT * FROM intel_lookups WHERE key=?", (f"{provider}|{t}|{v}",))
        hours = 24 * 7 if provider == "rdap" else int(self._g("intel_cache_hours"))
        if r and r["fetched_at"] >= _ago(hours):
            return dict(json.loads(r["result"]), cached=True, checked_at=r["fetched_at"])
        return None

    def _cache_put(self, provider: str, t: str, v: str, res: dict) -> None:
        self.db.execute("INSERT INTO intel_lookups(key, provider, verdict, result, fetched_at) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET verdict=excluded.verdict, result=excluded.result, "
                        "fetched_at=excluded.fetched_at", (f"{provider}|{t}|{v}", provider, res.get("verdict", "unknown"),
                                                           json.dumps(res), _now()))

    def _limit(self, provider: str, per_min: int, per_day: int) -> int | None:
        now = time.time()
        day = _now()[:10]
        used = self._state(f"usage:{provider}:{day}") or 0
        if used >= per_day:
            return 3600
        with self._lock:
            dq = self._recent.setdefault(provider, deque())
            while dq and now - dq[0] > 60:
                dq.popleft()
            if len(dq) >= per_min:
                return int(60 - (now - dq[0])) + 1
            dq.append(now)
        self._state(f"usage:{provider}:{day}", used + 1)
        return None

    def _http(self, method: str, url: str, headers: dict, data: bytes | None = None) -> tuple[int, bytes]:
        if self.transport is feeds.urllib_transport:
            st, body, _h = feeds.urllib_transport(method, url, headers, data, 20.0, 8 * 1024 * 1024)
        else:
            st, body, _h = self.transport(method, url, headers, data, 20.0)
        return st, body

    def _json(self, body: bytes) -> dict:
        try:
            return json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            raise IntelError(502, "The service sent an answer Cyber Hub can't read")

    # ---- VirusTotal (Part 8 key + shared limiter)
    def _vt(self, t: str, v: str) -> dict:
        key = self.cloud.key_for("virustotal") if self.cloud else None
        if not key:
            raise IntelError(409, "Add a VirusTotal API key (Online lookup settings)")
        wait = self.cloud.reserve("virustotal")
        if wait is not None:
            raise IntelError(429, f"VirusTotal rate limit - next request in {wait} s", wait)
        path = {"ip": f"/ip_addresses/{v}", "domain": f"/domains/{v}",
                "url": "/urls/" + base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")}[t]
        st, body = self._http("GET", VT_BASE + path, {"x-apikey": key, "Accept": "application/json"})
        if st == 404:
            return {"verdict": "unknown", "found": False, "text": "Not in VirusTotal yet"}
        if st in (401, 403):
            raise IntelError(409, "VirusTotal refused the API key")
        if st == 429:
            raise IntelError(429, "VirusTotal quota used up for now", 60)
        if st != 200:
            raise IntelError(502, f"VirusTotal answered HTTP {st}")
        a = (self._json(body).get("data") or {}).get("attributes") or {}
        s = a.get("last_analysis_stats") or {}
        mal, sus, harmless = int(s.get("malicious", 0)), int(s.get("suspicious", 0)), int(s.get("harmless", 0))
        total = sum(int(x) for x in s.values() if isinstance(x, int))
        need = int(self._g("cloud_vt_min_detections"))
        verdict = "malicious" if mal >= need else "suspicious" if mal >= 1 or sus >= 2 else \
            "clean" if harmless > 0 else "unknown"
        gui = {"ip": f"https://www.virustotal.com/gui/ip-address/{v}", "domain": f"https://www.virustotal.com/gui/domain/{v}",
               "url": "https://www.virustotal.com/gui/url/" + __import__("hashlib").sha256(v.encode()).hexdigest()}[t]
        cats = a.get("categories") or {}
        return {"verdict": verdict, "found": True, "malicious": mal, "suspicious": sus, "harmless": harmless,
                "total": total, "reputation": a.get("reputation"), "country": a.get("country"),
                "as_owner": a.get("as_owner"), "categories": sorted(set(cats.values()))[:6] if isinstance(cats, dict) else [],
                "permalink": gui, "text": f"{mal} of {total} security vendors flag it" if total else "No verdicts yet",
                "points": 90 if verdict == "malicious" else 55 if verdict == "suspicious" else 0}

    # ---- abuse.ch: URLhaus + ThreatFox (Part 8's abuse.ch Auth-Key)
    def _abusech(self, t: str, v: str, c: dict) -> dict:
        key = self._abusech_key()
        if not key:
            raise IntelError(409, "Add the free abuse.ch Auth-Key (it's the MalwareBazaar key in Online lookup)")
        wait = self._limit("abusech", 30, 20000)
        if wait is not None:
            raise IntelError(429, f"abuse.ch rate limit - next request in {wait} s", wait)
        hdr = {"Auth-Key": key, "Accept": "application/json"}
        res: dict = {"verdict": "unknown", "found": False, "urlhaus": None, "threatfox": None, "points": 0}
        if t in ("url", "domain", "ip"):
            if t == "url":
                st, body = self._http("POST", URLHAUS_API + "/url/", dict(hdr, **{
                    "Content-Type": "application/x-www-form-urlencoded"}), urllib.parse.urlencode({"url": v}).encode())
            else:
                st, body = self._http("POST", URLHAUS_API + "/host/", dict(hdr, **{
                    "Content-Type": "application/x-www-form-urlencoded"}), urllib.parse.urlencode({"host": v}).encode())
            if st in (401, 403):
                raise IntelError(409, "abuse.ch refused the Auth-Key")
            if st == 200:
                j = self._json(body)
                if j.get("query_status") == "ok":
                    if t == "url":
                        online = j.get("url_status") == "online"
                        res["urlhaus"] = {"status": j.get("url_status"), "threat": j.get("threat"),
                                          "tags": j.get("tags"), "date_added": j.get("date_added"),
                                          "ref": j.get("urlhaus_reference")}
                        res["points"] = max(res["points"], 95 if online else 65)
                    else:
                        urls = j.get("urls") or []
                        on = sum(1 for u in urls if u.get("url_status") == "online")
                        res["urlhaus"] = {"urls": int(j.get("url_count") or len(urls)), "online": on,
                                          "first_seen": j.get("firstseen"), "ref": j.get("urlhaus_reference"),
                                          "threats": sorted({u.get("threat") for u in urls if u.get("threat")})[:5]}
                        res["points"] = max(res["points"], 80 if on else 45 if urls else 0)
                    res["found"] = True
        if t in ("url", "domain", "ip") or t in ioc.HASH_TYPES:
            body_json = ({"query": "search_hash", "hash": v} if t in ioc.HASH_TYPES else
                         {"query": "search_ioc", "search_term": v, "exact_match": True})
            st, body = self._http("POST", THREATFOX_API, dict(hdr, **{"Content-Type": "application/json"}),
                                  json.dumps(body_json).encode())
            if st == 200:
                j = self._json(body)
                data = j.get("data") if j.get("query_status") == "ok" else None
                if isinstance(data, list) and data:
                    best = max(data, key=lambda d: int(d.get("confidence_level") or 0))
                    conf = int(best.get("confidence_level") or 0)
                    res["threatfox"] = {"matches": len(data), "malware": best.get("malware_printable"),
                                        "threat_type": best.get("threat_type_desc") or best.get("threat_type"),
                                        "confidence": conf, "first_seen": best.get("first_seen")}
                    res["points"] = max(res["points"], 90 if conf >= 75 else 65)
                    res["found"] = True
        res["verdict"] = "malicious" if res["points"] >= 80 else "suspicious" if res["points"] >= 50 else \
            "low_risk" if res["points"] >= 25 else "unknown"
        parts = []
        if res["urlhaus"]:
            u = res["urlhaus"]
            parts.append(f"URLhaus: {u.get('threat') or ''} {u.get('status') or ''}".strip() if t == "url" else
                         f"URLhaus: {u['urls']} malware link(s), {u['online']} online")
        if res["threatfox"]:
            parts.append(f"ThreatFox: {res['threatfox']['malware'] or 'malware'} ({res['threatfox']['confidence']}% "
                         f"confidence)")
        res["text"] = "; ".join(parts) or "Not listed by abuse.ch"
        return res

    # ---- AbuseIPDB (own key)
    def _abuseipdb_key(self) -> str | None:
        r = self.db.fetchone("SELECT wrapped FROM intel_api_keys WHERE provider='abuseipdb'")
        if not r or self.vault is None or not self.vault.available:
            return None
        try:
            return self.vault.unwrap_key(r["wrapped"], "intel:abuseipdb").decode()
        except Exception:
            log.warning("Stored AbuseIPDB key can't be decrypted")
            return None

    def _abuseipdb(self, ip: str) -> dict:
        key = self._abuseipdb_key()
        if not key:
            raise IntelError(409, "Add an AbuseIPDB API key")
        wait = self._limit("abuseipdb", 60, 1000)
        if wait is not None:
            raise IntelError(429, f"AbuseIPDB daily / minute limit reached - next request in {wait} s", wait)
        st, body = self._http("GET", ABUSEIPDB_API + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
                              {"Key": key, "Accept": "application/json"})
        if st in (401, 403):
            raise IntelError(409, "AbuseIPDB refused the API key")
        if st == 429:
            raise IntelError(429, "AbuseIPDB quota used up", 3600)
        if st != 200:
            raise IntelError(502, f"AbuseIPDB answered HTTP {st}")
        d = self._json(body).get("data") or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        need = int(self._g("intel_abuseipdb_min_score"))
        if d.get("isWhitelisted"):
            verdict, pts = "clean", 0
        elif score >= 75:
            verdict, pts = "malicious", 85
        elif score >= need:
            verdict, pts = "suspicious", 55
        elif reports:
            verdict, pts = "low_risk", 30
        else:
            verdict, pts = "clean", 0
        return {"verdict": verdict, "found": reports > 0, "score": score, "reports": reports,
                "country": d.get("countryCode"), "isp": d.get("isp"), "usage": d.get("usageType"),
                "domain": d.get("domain"), "tor": d.get("isTor"), "last_reported": d.get("lastReportedAt"),
                "permalink": f"https://www.abuseipdb.com/check/{ip}", "points": pts,
                "text": f"{score}% abuse confidence, {reports} report(s)"}

    def set_key(self, cu, provider: str, key: str | None) -> dict:
        self._need_admin(cu, "change API keys")
        if provider != "abuseipdb":
            raise IntelError(422, "VirusTotal and abuse.ch keys are saved under Online lookup (/api/lookup/keys) and "
                                  "shared with the antivirus")
        if not key:
            self.db.execute("DELETE FROM intel_api_keys WHERE provider=?", (provider,))
            self.activity.record("settings", "AbuseIPDB API key removed", severity="low", source="intel")
            return self.providers()
        key = key.strip()
        if not 16 <= len(key) <= 256 or any(ch.isspace() for ch in key):
            raise IntelError(422, "That doesn't look like an API key")
        if self.vault is None or not self.vault.available:
            raise IntelError(503, "The key store is unavailable (vault key missing)")
        wrapped = self.vault.wrap_key(key.encode(), "intel:abuseipdb")
        self.db.execute("INSERT INTO intel_api_keys(provider, wrapped, hint, updated_at, updated_by) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(provider) DO UPDATE SET wrapped=excluded.wrapped, hint=excluded.hint, "
                        "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                        (provider, wrapped, "…" + key[-4:], _now(), cu.user["username"] if cu else "system"))
        self.activity.record("settings", "AbuseIPDB API key saved", severity="low", source="intel")
        return self.providers()

    def providers(self) -> dict:
        cloud = self.cloud.providers() if self.cloud else {}
        r = self.db.fetchone("SELECT hint, updated_at FROM intel_api_keys WHERE provider='abuseipdb'")
        day = _now()[:10]
        return {
            "virustotal": {"label": PROVIDER_LABELS["virustotal"], "ready": bool(cloud.get("virustotal", {}).get("ready")),
                           "key_hint": cloud.get("virustotal", {}).get("key_hint"), "shared_with": "Part 8 hash lookup",
                           "types": ["ip", "domain", "url", "hashes"], "key_saved_at": "/api/lookup/keys"},
            "abusech": {"label": PROVIDER_LABELS["abusech"], "ready": bool(self._abusech_key()),
                        "key_hint": cloud.get("malwarebazaar", {}).get("key_hint"), "shared_with":
                        "MalwareBazaar (Part 8) + URLhaus / ThreatFox feeds", "types": ["ip", "domain", "url", "hashes"],
                        "key_saved_at": "/api/lookup/keys (provider malwarebazaar)", "get_key": feeds.ABUSECH_KEY_URL,
                        "used_today": self._state(f"usage:abusech:{day}") or 0},
            "abuseipdb": {"label": PROVIDER_LABELS["abuseipdb"], "ready": bool(r) and self._abuseipdb_key() is not None,
                          "key_hint": r["hint"] if r else None, "updated_at": r["updated_at"] if r else None,
                          "types": ["ip"], "get_key": ABUSEIPDB_KEY_URL, "daily_limit": 1000,
                          "used_today": self._state(f"usage:abuseipdb:{day}") or 0},
            "enabled": bool(self._g("intel_online_lookup")), "selected": list(self._g("intel_online_providers")),
        }

    def _online(self, c: dict, full_url: bool = False) -> tuple[dict, dict, str | None]:
        """Ask the online services. Returns (results, errors, value_sent)."""
        t, v = c["type"], c["value"]
        if t == "ip" and c.get("scope") != "public":
            return {}, {"all": "Private / local addresses are never sent online"}, None
        if t in ("domain",) and c.get("local"):
            return {}, {"all": "Local network names are never sent online"}, None
        if t == "url":
            if c.get("ip") and ioc.ip_kind(c["ip"]) != "public" or ioc.is_local_name(c["host"]) and not c.get("ip"):
                return {}, {"all": "Addresses on your own network are never sent online"}, None
            if not full_url:
                v = v.split("?", 1)[0]
        if t in ("cidr", "email"):
            return {}, {"all": "Online services can't check this kind of indicator"}, None
        chosen = [p for p in self._g("intel_online_providers") if p in ONLINE_PROVIDERS]
        results, errors = {}, {}
        if t in ioc.HASH_TYPES:
            if self.cloud is not None and ("virustotal" in chosen or "abusech" in chosen):
                provs = [p for p, want in (("virustotal", "virustotal"), ("malwarebazaar", "abusech")) if want in chosen]
                try:
                    r = self.cloud.lookup(v, provs, require_enabled=False)
                    for p, pr in r["providers"].items():
                        pr = dict(pr)
                        pr["points"] = 90 if pr.get("verdict") == "malicious" else 55 if pr.get("verdict") == \
                            "suspicious" else 0
                        pr["text"] = pr.get("threat_label") or pr.get("verdict")
                        results[p] = pr
                    for p, e in r["errors"].items():
                        errors[p] = e["message"]
                except Exception as e:                                              # CloudError
                    errors["cloud"] = getattr(e, "message", str(e))
            if "abusech" in chosen and self._abusech_key():
                try:
                    cached = self._cache_get("abusech", t, v)
                    results["threatfox"] = cached or self._abusech(t, v, c)
                    if not cached:
                        self._cache_put("abusech", t, v, results["threatfox"])
                except IntelError as e:
                    errors["abusech"] = e.message
            return results, errors, v
        for p in chosen:
            if p == "abuseipdb" and t != "ip":
                continue
            cached = self._cache_get(p, t, v)
            if cached:
                results[p] = cached
                continue
            try:
                if p == "virustotal":
                    res = self._vt(t, v)
                elif p == "abusech":
                    res = self._abusech(t, v, c)
                else:
                    res = self._abuseipdb(v)
            except IntelError as e:
                errors[p] = e.message
                continue
            except (OSError, TimeoutError) as e:
                errors[p] = f"Can't reach {PROVIDER_LABELS[p]}: {type(e).__name__}"
                continue
            self._cache_put(p, t, v, res)
            results[p] = dict(res, cached=False, checked_at=_now())
        return results, errors, v

    # ---- RDAP domain age (deep check)
    def domain_age(self, domain: str) -> dict | None:
        reg = ioc.registrable(domain)
        cached = self._cache_get("rdap", "domain", reg)
        if cached:
            return cached
        if self._limit("rdap", 20, 2000) is not None:
            return None
        try:
            st, body = self._http("GET", RDAP_URL.format(reg), {"Accept": "application/rdap+json"})
        except (OSError, TimeoutError, feeds.FeedError):
            return None
        if st != 200:
            res = {"verdict": "unknown", "registered": None, "age_days": None}
        else:
            try:
                j = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                return None
            reg_at = next((e.get("eventDate") for e in j.get("events", []) if e.get("eventAction") == "registration"),
                          None)
            d = _parse_ts(reg_at)
            res = {"verdict": "unknown", "registered": reg_at,
                   "age_days": (datetime.now(timezone.utc) - d).days if d else None,
                   "registrar": next((e.get("vcardArray", [None, []])[1][1][3] for e in j.get("entities", [])
                                      if "registrar" in (e.get("roles") or []) and len(e.get("vcardArray", [None, []])[1]) > 1
                                      and len(e.get("vcardArray", [None, []])[1][1]) > 3), None)}
        self._cache_put("rdap", "domain", reg, res)
        return res

    # ================================================================== check
    def check(self, cu, value: str, online: bool | None = None, deep: bool = False, full_url: bool = False,
              save: bool = True) -> dict:
        c = self._classify(value)
        t = c["type"]
        report: dict[str, Any] = {
            "indicator": {k: c.get(k) for k in ("type", "value", "display", "host", "ip", "scope", "port", "domain")
                          if c.get(k) is not None},
            "checked_at": _now(), "matches": [], "phishing": None, "page": None, "online": {}, "online_errors": {},
            "online_used": False, "allowed": None, "private": False, "reasons": [], "actions": []}
        report["indicator"]["defanged"] = ioc.defang(c["value"], t)
        if t == "url" and c.get("userinfo"):
            report["indicator"]["userinfo_removed"] = True
        if t == "ip" and c.get("scope") != "public":
            report["private"] = True
        if t == "domain" and c.get("local"):
            report["private"] = True
        if t == "url" and c["host"] not in wp._public_override() and (
                (c.get("ip") and ioc.ip_kind(c["ip"]) != "public") or (not c.get("ip") and ioc.is_local_name(c["host"]))):
            report["private"] = True
        allow = self.allowed(c)
        report["allowed"] = allow
        hits = self.match(c)
        report["matches"] = hits
        points = [h["points"] for h in hits]
        # phishing analysis (url / domain / email / ip-in-url)
        if t in ("url", "domain", "email"):
            try:
                pa = ph.analyze_url(c["value"] if t != "email" else c["domain"])
            except ioc.IOCError:
                pa = None
            if pa and t == "url" and c.get("userinfo"):
                pa["findings"].insert(0, ph._f("at_sign", "high", 40, "The link hides a fake site name before an '@'"))
                pa["score"] = min(100, pa["score"] + 40)
                pa["level"] = ph.level(pa["score"])
            report["phishing"] = pa
        # deep check: open the page read-only
        if deep and t in ("url", "domain") and not report["private"]:
            report["page"] = self._deep(c)
        phish_pts = 0
        if report["phishing"]:
            pg = report["page"] or {}
            page_score = pg.get("score", 0)
            crit = any(f["severity"] == "critical" for f in (pg.get("findings") or []))
            phish_pts = min(95 if crit else 79, report["phishing"]["score"] + page_score)
            for hop in pg.get("redirect_hits", []):
                points.append(hop["points"])
        # online
        want_online = self._g("intel_online_lookup") if online is None else online
        if want_online and not allow:
            res, errs, sent = self._online(c, full_url)
            report["online"], report["online_errors"] = res, errs
            report["online_used"] = bool(res)
            report["online_sent"] = sent
            points += [r.get("points", 0) for r in res.values()]
        elif online and allow:
            report["online_errors"] = {"all": "On your allow list - not sent online"}
        score = max(points + [phish_pts]) if (points or phish_pts) else 0
        # two independent signals agreeing (a feed, the phishing analyser, an online service) count for more
        signals = sum(1 for x in (max([h["points"] for h in hits], default=0), phish_pts,
                                  max([r.get("points", 0) for r in report["online"].values()], default=0)) if x >= 25)
        if signals >= 2 and score < 100:
            score = min(100, score + 10)
            report["corroborated"] = True
        if allow:
            verdict, score = "clean", 0
        else:
            verdict = ("malicious" if score >= 80 else "suspicious" if score >= 50 else "low_risk" if score >= 25 else
                       "clean" if self._covered(c, report) else "unknown")
        report["verdict"], report["score"] = verdict, int(score)
        report["reasons"] = self._reasons(report, allow)
        report["summary"] = report["reasons"][0] if report["reasons"] else (
            "No threat intelligence matches" if verdict == "clean" else "Nothing known about this indicator")
        report["actions"] = self._actions(c, report)
        if save and cu is not None:
            stored = c["value"].split("?", 1)[0] if t == "url" else c["value"]
            self.db.execute("INSERT INTO intel_checks(user_id, type, value, verdict, score, summary) VALUES (?,?,?,?,?,?)",
                            (cu.user["id"], t, stored, verdict, int(score),
                             json.dumps({"summary": report["summary"], "matches": len(hits),
                                         "feeds": sorted({h["feed_name"] for h in hits})[:5],
                                         "online": sorted(report["online"]), "deep": bool(report["page"])})))
        return report

    def _covered(self, c: dict, report: dict) -> bool:
        t = c["type"]
        if report["online"]:
            return True
        if t in ("url", "domain", "email"):
            return True                                          # the phishing analyser always has an opinion
        if t in ("ip", "cidr"):
            if report["private"]:
                return True
            return self.db.fetchone("SELECT 1 FROM intel_iocs i JOIN intel_feeds f ON f.id=i.feed_id WHERE f.enabled=1 "
                                    "AND i.type IN ('ip','cidr') LIMIT 1") is not None
        return False                                             # hashes: absence from lists proves nothing

    def _reasons(self, report: dict, allow: dict | None) -> list[str]:
        out = []
        if allow:
            out.append(f"On your allow list ({allow['value']}" + (f": {allow['note']}" if allow.get("note") else "") + ")")
        for h in report["matches"][:5]:
            what = {"exact": "Listed", "cidr": "Inside a listed network", "parent_domain": "Its parent domain is listed",
                    "url_host": "Malicious links are hosted on it", "email_domain": "The e-mail domain is listed",
                    "signature": "Known malware", "cloud_cache": "Flagged by the cloud"}.get(h["matched_on"], "Listed")
            out.append(f"{what} in {h['feed_name']}" + (f" - {h['threat']}" if h.get("threat") else "") +
                       f" ({h['category_label'].lower()})")
        for p, r in report["online"].items():
            if r.get("points", 0) >= 25:
                out.append(f"{PROVIDER_LABELS.get(p, p)}: {r.get('text')}")
        pg = report.get("page") or {}
        for hop in pg.get("redirect_hits", [])[:3]:
            out.append(f"Redirects through {hop['host']}, listed in {hop['feed_name']}")
        for f in ((report.get("phishing") or {}).get("findings") or [])[:3] + (pg.get("findings") or [])[:3]:
            if f["points"] >= 15:
                out.append(f["text"])
        if report["private"]:
            out.append("This is an address on your own PC / network")
        return list(dict.fromkeys(out))

    def _actions(self, c: dict, report: dict) -> list[dict]:
        acts = []
        t, bad = c["type"], report["verdict"] in ("malicious", "suspicious")
        on_local = any(h["feed"] == "local" for h in report["matches"])
        if bad and not report["allowed"]:
            ip = c["value"] if t == "ip" else c.get("ip") if t == "url" else None
            if ip and ioc.ip_kind(ip) == "public" and self.firewall is not None:
                acts.append({"action": "block_ip", "ip": ip, "label": "Block this address in the firewall",
                             "endpoint": "POST /api/intel/block-ip"})
            if not on_local:
                acts.append({"action": "add_blocklist", "label": "Add to your block list",
                             "endpoint": "POST /api/intel/blocklist"})
            if t in ("url", "domain"):
                acts.append({"action": "dont_open", "label": "Don't open it or type any password there"})
            if t in ioc.HASH_TYPES:
                acts.append({"action": "hunt", "label": "Look for this file on the PC",
                             "endpoint": "GET /api/intel/hunt"})
            acts.append({"action": "allow", "label": "It's safe (false positive) - allow it", "admin": True,
                         "endpoint": "POST /api/intel/allowlist"})
        elif not bad and not on_local and t not in ("cidr",) and not report["private"]:
            acts.append({"action": "add_blocklist", "label": "Block it anyway (add to your block list)",
                         "endpoint": "POST /api/intel/blocklist"})
        if report["verdict"] in ("clean", "unknown", "low_risk") and t in ("url", "domain") and not report["page"] \
                and not report["private"]:
            acts.append({"action": "deep_check", "label": "Open the page safely and look closer (deep check)",
                         "endpoint": "POST /api/intel/check deep=true"})
        return acts

    def _deep(self, c: dict) -> dict:
        url = c["value"] if c["type"] == "url" else f"https://{c['value']}/"
        out: dict[str, Any] = {"url": url, "fetched": False, "error": None, "redirects": [], "redirect_hits": [],
                               "findings": [], "score": 0}
        if c["type"] == "url" and c["scheme"] not in ("http", "https"):
            out["error"] = "Only web pages can be opened"
            return out
        fetcher = wp.Fetcher(timeout=10.0, max_requests=10, start_scope="public")
        try:
            r = fetcher.fetch(url, max_body=1024 * 1024)
        except wp.ProbeError as e:
            if c["type"] == "domain" and e.code in ("refused", "timeout", "tls", "network", "reset"):
                try:
                    url = f"http://{c['value']}/"
                    r = fetcher.fetch(url, max_body=1024 * 1024)
                    out["url"] = url
                except wp.ProbeError as e2:
                    out["error"] = e2.message
                    return out
            else:
                out["error"] = e.message if e.code != "redirect_local" else \
                    "The link redirects to an address on your own network - stopped there (that alone is suspicious)"
                if e.code == "redirect_local":
                    out["findings"].append(ph._f("redirect_local", "high", 35, out["error"]))
                    out["score"] = 35
                return out
        out["fetched"] = True
        out["status"] = r["status"]
        out["final_url"] = r["final_url"]
        out["redirects"] = [h["url"] for h in r["chain"]]
        final_host = wp.parse_target(r["final_url"])["host"]
        out["final_host"] = final_host
        seen_hosts = []
        for hop in r["chain"]:
            try:
                h = wp.parse_target(hop["url"])["host"]
            except wp.ProbeError:
                continue
            if h in seen_hosts:
                continue
            seen_hosts.append(h)
            try:
                hc = ioc.classify(h)
            except ioc.IOCError:
                continue
            for hit in self.match(hc):
                out["redirect_hits"].append(dict(hit, host=h))
        if len(seen_hosts) > 1:
            first_reg = ioc.registrable(seen_hosts[0])
            if ioc.registrable(final_host) != first_reg:
                out["findings"].append(ph._f("cross_site_redirect", "low", 8, f"The link sends you on to a different "
                                                                             f"site: {final_host}"))
                fa = ph.analyze_host(final_host)
                out["findings"] += [dict(f, text=f"Destination {final_host}: {f['text']}") for f in fa if f["points"] >= 15]
        ctype = ",".join(r["h"].get("content-type", [])).lower()
        if "html" in ctype or (not ctype and r["body"][:200].lstrip().startswith(b"<")):
            page = ph.analyze_page(r["body"], r["final_url"], final_host)
            out["title"] = page["title"]
            out["forms"], out["password_fields"] = page["forms"], page["password_fields"]
            out["findings"] += page["findings"]
        elif any(x in ctype for x in ("application/x-msdownload", "application/octet-stream", "application/x-dosexec",
                                       "application/vnd.android.package-archive", "application/java-archive")):
            out["findings"].append(ph._f("serves_file", "high", 35, f"The link downloads a program / file "
                                                                   f"({ctype.split(';')[0]}) instead of showing a page"))
        if r["final_url"].startswith("https://"):
            try:
                ti = wp.tls_info(final_host, r["ip"], wp.parse_target(r["final_url"])["port"], timeout=8.0,
                                 test_versions=False)
                cert = ti.get("cert") or {}
                out["certificate"] = {"trusted": ti.get("trusted"), "issuer": cert.get("issuer_org") or cert.get("issuer"),
                                      "not_before": cert.get("not_before"), "not_after": cert.get("not_after")}
                nb = _parse_ts(cert.get("not_before"))
                if ti.get("trusted") is False:
                    out["findings"].append(ph._f("untrusted_cert", "medium", 20, "The site's certificate is not "
                                                                                 "trusted"))
                elif nb and (datetime.now(timezone.utc) - nb).days < 7:
                    out["findings"].append(ph._f("new_cert", "low", 10, f"The site's certificate was issued "
                                                                       f"{(datetime.now(timezone.utc) - nb).days} day(s) ago"))
            except Exception as e:                                      # pragma: no cover - TLS oddities
                out["certificate"] = {"error": str(e)[:120]}
        if not ioc.is_local_name(final_host):
            try:
                ioc.norm_ip(final_host)
            except ValueError:
                age = self.domain_age(final_host)
                if age:
                    out["domain"] = {"registrable": ioc.registrable(final_host), **age}
                    ad = age.get("age_days")
                    if ad is not None and ad < 30:
                        out["findings"].append(ph._f("new_domain", "high", 30, f"The domain was registered only {ad} "
                                                                              f"day(s) ago"))
                    elif ad is not None and ad < 180:
                        out["findings"].append(ph._f("young_domain", "low", 10, f"The domain is only {ad} days old"))
        out["findings"].sort(key=lambda f: -f["points"])
        out["score"] = min(100, sum(f["points"] for f in out["findings"]))
        return out

    def check_bulk(self, cu, text: str, online: bool = False) -> dict:
        items, bad = ioc.extract(text, limit=MAX_BULK + 1)
        if not items:
            raise IntelError(422, "No IP addresses, domains, URLs, e-mails or hashes found in that text")
        if len(items) > MAX_BULK:
            raise IntelError(422, f"At most {MAX_BULK} indicators at once")
        use_online = bool(online) and len(items) <= MAX_ONLINE_BULK
        out = []
        counts = {v: 0 for v in VERDICTS}
        for c in items:
            r = self.check(cu, c["value"], online=use_online, save=False)
            counts[r["verdict"]] += 1
            out.append({"type": c["type"], "value": c["value"], "defanged": r["indicator"]["defanged"],
                        "verdict": r["verdict"], "score": r["score"], "summary": r["summary"],
                        "matches": [{"feed": h["feed_name"], "threat": h["threat"], "severity": h["severity"]}
                                    for h in r["matches"][:3]], "private": r["private"]})
        out.sort(key=lambda x: (-x["score"], x["type"]))
        if counts["malicious"] or counts["suspicious"]:
            self.activity.record("intel", f"Bulk check: {counts['malicious']} malicious, {counts['suspicious']} "
                                          f"suspicious of {len(items)}", severity="medium" if counts["malicious"] else "low",
                                 source="intel")
        return {"total": len(items), "unreadable": bad, "counts": counts, "online_used": use_online,
                "online_skipped": bool(online) and not use_online, "items": out}

    def checks(self, cu, limit: int = 50, verdict: str | None = None) -> dict:
        where, params = ["user_id=?"], [cu.user["id"]]
        if verdict:
            where.append("verdict=?"); params.append(verdict)
        rows = self.db.fetchall(f"SELECT * FROM intel_checks WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        for r in rows:
            r["summary"] = json.loads(r["summary"]) if r["summary"] else None
            r["defanged"] = ioc.defang(r["value"], r["type"])
        return {"items": rows}

    def clear_checks(self, cu) -> int:
        return self.db.execute("DELETE FROM intel_checks WHERE user_id=?", (cu.user["id"],)).rowcount

    # ================================================================== IOC search + hunt
    def search(self, q: str | None = None, type_: str | None = None, feed: str | None = None,
               threat: str | None = None, category: str | None = None, limit: int = 100, offset: int = 0) -> dict:
        where, params = ["f.enabled=1"], []
        exact = None
        if q:
            try:
                exact = ioc.classify(q)
            except ioc.IOCError:
                exact = None
            if exact and exact.get("local"):
                exact = None                                     # a single word: text search
            if exact and not type_:
                if exact["type"] == "url":
                    vs = ioc.url_key_variants(exact["value"])
                    where.append(f"((i.type='url' AND i.value IN ({','.join('?' * len(vs))})) OR i.host=?)")
                    params += vs + [exact["host"]]
                elif exact["type"] == "domain":
                    ps = ioc.parent_domains(exact["value"])
                    where.append(f"((i.type='domain' AND i.value IN ({','.join('?' * len(ps))})) OR i.host=?)")
                    params += ps + [exact["value"]]
                elif exact["type"] == "ip":
                    where.append("((i.type='ip' AND i.value=?) OR i.host=?)")
                    params += [exact["value"], exact["value"]]
                else:
                    where.append("i.type=? AND i.value=?")
                    params += [exact["type"], exact["value"]]
            else:
                like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                where.append("(i.value LIKE ? ESCAPE '\\' OR lower(i.threat) LIKE ? ESCAPE '\\' OR lower(i.tags) "
                             "LIKE ? ESCAPE '\\')")
                params += [like, like, like]
        if type_:
            where.append("i.type=?"); params.append(type_)
        if feed:
            where.append("f.key=?"); params.append(feed)
        if threat:
            where.append("lower(i.threat)=?"); params.append(threat.lower())
        if category:
            where.append("COALESCE(i.category, f.category)=?"); params.append(category)
        w = " AND ".join(where)
        rows = self.db.fetchall("SELECT i.id, i.type, i.value, i.host, i.port, i.threat, COALESCE(i.category, f.category) "
                                "AS category, COALESCE(i.severity, f.severity) AS severity, i.confidence, i.tags, "
                                "i.first_seen, i.ref, i.note, f.key AS feed, f.name AS feed_name FROM intel_iocs i "
                                f"JOIN intel_feeds f ON f.id=i.feed_id WHERE {w} ORDER BY i.id DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM intel_iocs i JOIN intel_feeds f ON "
                                 f"f.id=i.feed_id WHERE {w} LIMIT 100001)", tuple(params))["n"]
        if exact and exact["type"] == "ip" and not type_:
            for h in self._cidr_hits(exact["value"]):
                rows.append({"id": None, "type": "cidr", "value": h["value"], "host": None, "port": None,
                             "threat": h["threat"], "category": h["category"], "severity": h["severity"],
                             "confidence": None, "tags": None, "first_seen": None, "ref": h["ref"], "note": None,
                             "feed": h["feed"], "feed_name": h["feed_name"]})
                total += 1
        for r in rows:
            r["defanged"] = ioc.defang(r["value"], r["type"])
            r["category_label"] = feeds.CATEGORIES.get(r["category"], r["category"])
        return {"items": rows, "total": total, "total_capped": total > 100000, "limit": limit, "offset": offset,
                "query_type": exact["type"] if exact else None}

    def _table(self, name: str) -> bool:
        return self.db.fetchone("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None

    def hunt(self, value: str, limit: int = 50) -> dict:
        """Where has this indicator shown up on THIS PC? (read-only search through every module's history)"""
        c = self._classify(value)
        t, v = c["type"], c["value"]
        found: list[dict] = []
        esc = lambda s: "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"   # noqa: E731

        def add(source: str, label: str, rows: list[dict], fmt) -> None:
            for r in rows[:limit]:
                item = fmt(r)
                if item:
                    found.append({"source": source, "source_label": label, **item})

        if t in ioc.HASH_TYPES:
            col = {"sha256": "sha256", "md5": "md5", "sha1": "sha1"}[t]
            if self._table("file_hash_cache"):
                add("files", "Files hashed on this PC (antivirus cache)",
                    self.db.fetchall(f"SELECT path, size, hashed_at FROM file_hash_cache WHERE {col}=? LIMIT ?", (v, limit)),
                    lambda r: {"ts": r["hashed_at"], "title": r["path"], "detail": f"{r['size']} bytes",
                               "exists": os.path.exists(r["path"]), "path": r["path"]})
            if col != "sha1" and self._table("scan_detections"):
                add("detections", "Antivirus detections (Part 5)",
                    self.db.fetchall(f"SELECT id, detected_at, path, threat_name, status FROM scan_detections WHERE {col}=? "
                                     "ORDER BY id DESC LIMIT ?", (v, limit)),
                    lambda r: {"ts": r["detected_at"], "title": f"{r['threat_name']} - {r['path']}",
                               "detail": f"status {r['status']}", "ref": r["id"]})
            if col != "sha1" and self._table("quarantine_items"):
                add("quarantine", "Quarantine (Part 6)",
                    self.db.fetchall(f"SELECT id, quarantined_at, original_path, threat_name, status FROM quarantine_items "
                                     f"WHERE {col}=? LIMIT ?", (v, limit)) if self._has_col("quarantine_items",
                                                                                          "quarantined_at") else
                    self.db.fetchall(f"SELECT id, original_path, threat_name, status FROM quarantine_items WHERE {col}=? "
                                     "LIMIT ?", (v, limit)),
                    lambda r: {"ts": r.get("quarantined_at"), "title": f"{r['threat_name']} - {r['original_path']}",
                               "detail": f"status {r['status']}", "ref": r["id"]})
            if col == "sha256" and self._table("realtime_events"):
                add("realtime", "Real-time protection (Part 7)",
                    self.db.fetchall("SELECT ts, path, status, downloaded_from FROM realtime_events WHERE sha256=? "
                                     "ORDER BY id DESC LIMIT ?", (v, limit)),
                    lambda r: {"ts": r["ts"], "title": r["path"], "detail": f"{r['status']}" + (
                        f", downloaded from {r['downloaded_from']}" if r["downloaded_from"] else "")})
        if t in ("ip", "domain", "url", "email", "cidr"):
            needle = c.get("host") if t == "url" else c.get("domain") if t == "email" else v.split("/")[0] \
                if t == "cidr" else v
            like = esc(needle)
            if self._table("realtime_events"):
                add("downloads", "Downloaded files (Mark of the Web, Part 7)",
                    self.db.fetchall("SELECT ts, path, status, downloaded_from FROM realtime_events WHERE downloaded_from "
                                     "LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?", (like, limit)),
                    lambda r: {"ts": r["ts"], "title": r["path"], "detail": f"from {r['downloaded_from']} ({r['status']})",
                               "exists": os.path.exists(r["path"])})
            if self._table("quarantine_items"):
                add("quarantine", "Quarantine - downloaded from (Part 6)",
                    self.db.fetchall("SELECT id, original_path, threat_name, zone_identifier FROM quarantine_items "
                                     "WHERE zone_identifier LIKE ? ESCAPE '\\' LIMIT ?", (like, limit)),
                    lambda r: {"ts": None, "title": f"{r['threat_name']} - {r['original_path']}",
                               "detail": "Mark of the Web points to it", "ref": r["id"]})
            for tbl, label in (("network_events", "Network monitor events (Part 10)"),
                               ("firewall_events", "Firewall events (Part 9)"),
                               ("intel_events", "Threat-intel alerts (Part 15)"),
                               ("web_events", "Website scanner alerts (Part 14)")):
                if self._table(tbl):
                    cols = [x for x in ("title", "detail", "data") if self._has_col(tbl, x)]
                    conds = " OR ".join(f"{x} LIKE ? ESCAPE '\\'" for x in cols)
                    add(tbl.split("_")[0] + "_events", label,
                        self.db.fetchall(f"SELECT id, ts, severity, title, detail FROM {tbl} WHERE {conds} ORDER BY id DESC "
                                         "LIMIT ?", tuple([like] * len(cols)) + (limit,)),
                        lambda r: {"ts": r["ts"], "title": r["title"], "detail": r["detail"], "severity": r["severity"],
                                   "ref": r["id"]})
            if self._table("firewall_blocks"):
                add("firewall", "Firewall blocks (Part 9)",
                    self.db.fetchall("SELECT id, created_at, kind, target, status, reason FROM firewall_blocks WHERE "
                                     "target LIKE ? ESCAPE '\\' LIMIT ?", (like, limit)),
                    lambda r: {"ts": r["created_at"], "title": f"{r['kind']} block {r['target']}",
                               "detail": f"{r['status']}" + (f" - {r['reason']}" if r["reason"] else ""), "ref": r["id"]})
            if self._table("web_targets"):
                add("web", "Website scanner targets (Part 14)",
                    self.db.fetchall("SELECT id, created_at, target, last_grade FROM web_targets WHERE kind='site' AND "
                                     "target LIKE ? ESCAPE '\\' LIMIT ?", (like, limit)),
                    lambda r: {"ts": r["created_at"], "title": r["target"], "detail": f"grade {r['last_grade'] or '-'}",
                               "ref": r["id"]})
            if t in ("ip",) and self._table("lan_devices"):
                add("lan", "Devices on your network (Part 10)",
                    self.db.fetchall("SELECT id, ip, mac, hostname, vendor, last_seen FROM lan_devices WHERE ip=? LIMIT ?",
                                     (v, limit)) if self._has_col("lan_devices", "last_seen") else [],
                    lambda r: {"ts": r.get("last_seen"), "title": f"{r['ip']} ({r['vendor'] or r['mac']})",
                               "detail": r["hostname"], "ref": r["id"]})
        if self._table("activity_log"):
            needle = c.get("host") if t == "url" else v
            add("activity", "Activity log",
                self.db.fetchall("SELECT id, ts, category, severity, title, detail FROM activity_log WHERE (title LIKE ? "
                                 "ESCAPE '\\' OR detail LIKE ? ESCAPE '\\') AND source != 'intel' ORDER BY id DESC "
                                 "LIMIT ?", (esc(needle), esc(needle), limit)),
                lambda r: {"ts": r["ts"], "title": r["title"], "detail": r["detail"], "severity": r["severity"],
                           "ref": r["id"]})
        if t == "ip" and self.network is not None:
            try:
                live = self.network.connections(search=v, limit=50, resolve=False)["items"]
                add("live", "Live connections right now (Part 10)", [r for r in live if r.get("remote_ip") == v],
                    lambda r: {"ts": _now(), "title": f"{r.get('process') or '?'} (pid {r.get('pid')}) -> {v}:"
                                                      f"{r.get('remote_port')}", "detail": r.get("status"),
                               "pid": r.get("pid"), "exe": r.get("exe")})
            except Exception:                                                     # network unavailable
                pass
        counts: dict[str, int] = {}
        for f in found:
            counts[f["source"]] = counts.get(f["source"], 0) + 1
        return {"indicator": {"type": t, "value": v, "defanged": ioc.defang(v, t)}, "total": len(found),
                "counts": counts, "items": found, "intel": self.match(c)[:10]}

    def _has_col(self, table: str, col: str) -> bool:
        return any(r["name"] == col for r in self.db.fetchall(f"PRAGMA table_info({table})"))

    # ================================================================== retro hunt
    def retro_hunt(self) -> dict:
        """New feed data vs. what this PC already has: hashed files and downloads (Mark of the Web)."""
        out = {"files": 0, "downloads": 0}
        if self._table("file_hash_cache"):
            for col in ("sha256", "md5", "sha1"):
                rows = self.db.fetchall(
                    f"SELECT c.path, c.sha256, i.value, i.type, i.threat, COALESCE(i.severity, f.severity) AS sev, "
                    f"f.name AS feed_name, f.key AS feed_key FROM file_hash_cache c JOIN intel_iocs i ON i.type=? AND "
                    f"i.value=c.{col} JOIN intel_feeds f ON f.id=i.feed_id WHERE f.enabled=1 LIMIT 500", (col,))
                for r in rows:
                    if self.allowed({"type": col, "value": r["value"]}):
                        continue
                    ref = f"retro_file:{r['sha256']}:{r['path']}"
                    if self._has_event(ref):
                        continue
                    exists = os.path.exists(r["path"])
                    sev = "high" if exists else "medium"
                    self._event("retro_file", sev, f"A file on this PC is now known malware: {os.path.basename(r['path'])}",
                                f"{r['threat'] or 'Malware'} - listed by {r['feed_name']}. "
                                + ("Scan it now - it will be detected." if exists else "The file is no longer there."),
                                {"type": "sha256", "sha256": r["sha256"], "path": r["path"], "threat": r["threat"],
                                 "feed": r["feed_key"], "exists": exists,
                                 "fix": {"action": "scan_file", "endpoint": "POST /api/scan/file", "path": r["path"]}
                                 if exists else None}, ref=ref)
                    out["files"] += 1
        if self._table("realtime_events"):
            since = _ago(24 * 90)
            rows = self.db.fetchall("SELECT id, ts, path, downloaded_from FROM realtime_events WHERE downloaded_from IS "
                                    "NOT NULL AND ts >= ? ORDER BY id DESC LIMIT 5000", (since,))
            for r in rows:
                src = (r["downloaded_from"] or "").split()[0]
                try:
                    c = ioc.classify(src)
                except ioc.IOCError:
                    continue
                if c["type"] not in ("url", "domain", "ip") or self.allowed(c):
                    continue
                hits = [h for h in self.match(c) if h["points"] >= 50]
                if not hits:
                    continue
                host = c.get("host") or c["value"]
                ref = f"retro_download:{host}:{r['path']}"
                if self._has_event(ref):
                    continue
                h = hits[0]
                exists = os.path.exists(r["path"])
                self._event("retro_download", "high" if exists else "medium",
                            f"Downloaded from a site now known as {h['category_label'].lower()}: "
                            f"{os.path.basename(r['path'])}",
                            f"{host} is listed by {h['feed_name']}" + (f" ({h['threat']})" if h.get("threat") else ""),
                            {"type": c["type"], "host": host, "path": r["path"], "url": src[:300], "feed": h["feed"],
                             "threat": h.get("threat"), "exists": exists,
                             "fix": {"action": "scan_file", "endpoint": "POST /api/scan/file", "path": r["path"]}
                             if exists else None}, ref=ref)
                out["downloads"] += 1
        return out

    # ================================================================== live connection watch
    def watch_once(self) -> dict:
        out = {"checked": 0, "matches": 0, "alerts": 0, "blocked": 0, "skipped": None}
        if not self._g("intel_watch_connections"):
            out["skipped"] = "off"
            return out
        if self.network is None:
            out["skipped"] = "no network module"
            return out
        try:
            rows = self.network.connections(include_listening=False, limit=5000, resolve=False)["items"]
        except Exception as e:
            out["skipped"] = f"connections unavailable: {getattr(e, 'message', e)}"
            return out
        rows = [r for r in rows if r.get("remote_ip") and r.get("scope") == "internet" and not r.get("cyberhub")]
        self.stats["watch_runs"] += 1
        self.stats["connections_checked"] += len(rows)
        out["checked"] = len(rows)
        if not rows:
            return out
        hits = self.match_ips([r["remote_ip"] for r in rows])
        mode = self._g("intel_auto_block")
        for r in rows:
            hs = hits.get(r["remote_ip"])
            if not hs:
                continue
            if self.allowed({"type": "ip", "value": r["remote_ip"]}):
                continue
            out["matches"] += 1
            self.stats["matches"] += 1
            best = hs[0]
            prog = r.get("exe") or r.get("process") or "?"
            ref = f"conn:{r['remote_ip']}|{prog}"
            last = self._state(ref)
            if last and _parse_ts(last) and datetime.now(timezone.utc) - _parse_ts(last) < timedelta(hours=24):
                continue
            self._state(ref, _now())
            sev = best["severity"] if best["severity"] != "info" else "low"
            block = None
            if (mode == "c2" and best["category"] == "c2" and best["matched_on"] == "exact") or \
                    (mode == "high" and SEV[best["severity"]] >= SEV["high"] and best["matched_on"] in ("exact", "cidr")):
                block = self._auto_block(r["remote_ip"], best)
                if block and block.get("id"):
                    out["blocked"] += 1
            who = r.get("process") or "A program"
            what = best["threat"] or best["category_label"].lower()
            self._event("connection_match", sev,
                        f"{who} is talking to a known {best['category_label'].lower()}: {r['remote_ip']}",
                        f"{best['feed_name']}" + (f" - {best['threat']}" if best.get("threat") else "") +
                        f" (port {r.get('remote_port')}, pid {r.get('pid')})" +
                        (" - blocked in the firewall" if block and block.get("id") else ""),
                        {"type": "ip", "ip": r["remote_ip"], "port": r.get("remote_port"), "pid": r.get("pid"),
                         "process": r.get("process"), "exe": r.get("exe"), "create_time": r.get("create_time"),
                         "feeds": sorted({h["feed_name"] for h in hs}), "threat": best.get("threat"),
                         "category": best["category"], "what": what, "matched_on": best["matched_on"],
                         "blocked": block,
                         "fix": None if block and block.get("id") else
                         {"action": "block_ip", "endpoint": "POST /api/intel/events/{id}/block", "ip": r["remote_ip"]}},
                        ref=ref)
            out["alerts"] += 1
        return out

    def _auto_block(self, ip: str, hit: dict) -> dict | None:
        if self.firewall is None or ioc.ip_kind(ip) != "public":
            return None
        try:
            res = self.firewall.block_ip([ip], "Cyber Hub (threat intel)", direction="both",
                                         reason=f"Threat intel: {hit['feed_name']}" +
                                                (f" - {hit['threat']}" if hit.get("threat") else ""))
            b = res.get("block") if isinstance(res, dict) and "block" in res else res
            self.stats["auto_blocked"] += 1
            self._event("auto_block", "medium", f"Blocked {ip} automatically (threat intel)",
                        f"{hit['feed_name']} - {hit.get('threat') or hit['category_label']}",
                        {"type": "ip", "ip": ip, "block_id": (b or {}).get("id")}, ref=f"auto_block:{ip}:{_now()[:10]}")
            return {"id": (b or {}).get("id"), "status": (b or {}).get("status")}
        except Exception as e:
            st = getattr(e, "status", None)
            return {"id": None, "error": getattr(e, "message", str(e))[:200], "status": st}

    def block_ip(self, cu, ip: str, minutes: int | None = None, reason: str | None = None) -> dict:
        """One-click: block an address in the Part 9 firewall (in + out)."""
        if self.firewall is None:
            raise IntelError(501, "The firewall module is not available")
        c = self._classify(ip)
        if c["type"] != "ip":
            raise IntelError(422, "Give a single IP address")
        if c["scope"] != "public":
            raise IntelError(422, "Only internet addresses can be blocked from here (use the firewall page for "
                                  "your own network)")
        if self.allowed(c):
            raise IntelError(409, "That address is on your threat-intel allow list")
        hits = self.match(c)
        why = reason or (f"Threat intel: {hits[0]['feed_name']}" + (f" - {hits[0]['threat']}" if hits[0].get("threat")
                                                                     else "") if hits else "Blocked from Threat Intelligence")
        from .firewall import FirewallError
        try:
            res = self.firewall.block_ip([c["value"]], cu.user["username"] if cu else "system", direction="both",
                                         minutes=minutes, reason=why[:200])
        except FirewallError as e:
            raise IntelError(e.status, e.message)
        self.activity.record("intel", f"Blocked {c['value']} (threat intel)", why, severity="medium", source="intel")
        return {"ip": c["value"], "firewall": res, "matches": hits[:5]}

    def block_event(self, cu, eid: int, minutes: int | None = None) -> dict:
        e = self.db.fetchone("SELECT * FROM intel_events WHERE id=?", (eid,))
        if not e or (e["user_id"] is not None and e["user_id"] != cu.user["id"]):
            raise IntelError(404, "Alert not found")
        d = json.loads(e["data"]) if e["data"] else {}
        if not d.get("ip"):
            raise IntelError(409, "This alert has no address to block")
        res = self.block_ip(cu, d["ip"], minutes)
        d["blocked"] = {"id": (res.get("firewall") or {}).get("id") if isinstance(res.get("firewall"), dict) else None}
        d["fix"] = None
        self.db.execute("UPDATE intel_events SET data=?, acknowledged=1 WHERE id=?", (json.dumps(d), eid))
        return res

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
        rows = self.db.fetchall(f"SELECT * FROM intel_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        for r in rows:
            r["data"] = json.loads(r["data"]) if r.get("data") else None
            r["acknowledged"] = bool(r["acknowledged"])
            if r["data"] and r["data"].get("fix") and "{id}" in str(r["data"]["fix"].get("endpoint", "")):
                r["data"]["fix"]["endpoint"] = r["data"]["fix"]["endpoint"].replace("{id}", str(r["id"]))
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM intel_events")["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_events WHERE (user_id IS ? OR user_id IS NULL) AND "
                                 "acknowledged=0", (cu.user["id"],))["n"]
        return {"items": rows, "last_id": last, "unacknowledged": unack}

    def acknowledge(self, cu, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE intel_events SET acknowledged=1 WHERE id IN ({q}) AND (user_id IS ? OR "
                                   "user_id IS NULL)", tuple(ids) + (cu.user["id"],)).rowcount
        return self.db.execute("UPDATE intel_events SET acknowledged=1 WHERE user_id IS ? OR user_id IS NULL",
                               (cu.user["id"],)).rowcount

    def clear_events(self, cu) -> int:
        if self._is_admin(cu):
            return self.db.execute("DELETE FROM intel_events WHERE user_id IS ? OR user_id IS NULL",
                                   (cu.user["id"],)).rowcount
        return self.db.execute("DELETE FROM intel_events WHERE user_id IS ?", (cu.user["id"],)).rowcount

    # ================================================================== housekeeping
    def cleanup(self) -> int:
        cut = _ago(24 * int(self._g("intel_history_days")))
        n = self.db.execute("DELETE FROM intel_events WHERE ts < ?", (cut,)).rowcount
        n += self.db.execute("DELETE FROM intel_checks WHERE ts < ?", (cut,)).rowcount
        self.db.execute("DELETE FROM intel_lookups WHERE fetched_at < ?", (_ago(24 * 30),))
        old = _ago(48)
        for r in self.db.fetchall("SELECT key, value FROM intel_state WHERE key LIKE 'conn:%' OR key LIKE 'usage:%'"):
            v = json.loads(r["value"])
            if (r["key"].startswith("conn:") and isinstance(v, str) and v < old) or \
                    (r["key"].startswith("usage:") and r["key"].rsplit(":", 1)[-1] < old[:10]):
                self.db.execute("DELETE FROM intel_state WHERE key=?", (r["key"],))
        return n

    def tick(self) -> dict:
        """Called by the background loop: auto-update due feeds, watch connections, daily cleanup."""
        out = {}
        now = time.time()
        if now - self._last_watch >= int(self._g("intel_watch_interval_seconds")):
            self._last_watch = now
            out["watch"] = self.watch_once()
        if self._g("intel_auto_update") and self.due_feeds() and not self.jobs()["running"]:
            try:
                out["refresh"] = self.refresh(None)
            except IntelError:
                pass
        day = _now()[:10]
        if self._state("cleanup_day") != day:
            self._state("cleanup_day", day)
            out["cleanup"] = self.cleanup()
        return out

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout)

    # ================================================================== dashboard
    def health(self, user_id: int | None = None) -> dict:
        """For Part 18: is threat intelligence working, and did it catch anything?"""
        fs = [self._feed_public(f) for f in self.db.fetchall("SELECT * FROM intel_feeds WHERE url IS NOT NULL")]
        enabled = [f for f in fs if f["enabled"]]
        ok = [f for f in enabled if f["status"] == "ok" and not f["stale"]]
        stale = [f for f in enabled if f["stale"] and f["status"] != "needs_key"]
        needs_key = [f["key"] for f in enabled if f["status"] == "needs_key"]
        since = _ago(24 * 7)
        uid = user_id if user_id is not None else -1
        by = {s: 0 for s in SEVERITIES}
        for r in self.db.fetchall("SELECT severity, COUNT(*) AS n FROM intel_events WHERE ts >= ? AND acknowledged=0 AND "
                                  "kind IN ('connection_match','retro_file','retro_download') AND (user_id IS ? OR "
                                  "user_id IS NULL) GROUP BY severity", (since, uid)):
            by[r["severity"]] = r["n"]
        iocs = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_iocs i JOIN intel_feeds f ON f.id=i.feed_id "
                                "WHERE f.enabled=1")["n"]
        penalty = 0
        if not iocs:
            penalty += 40
        penalty += 8 * len(stale)
        if not self._g("intel_watch_connections"):
            penalty += 20
        if not self._g("intel_auto_update"):
            penalty += 15
        penalty += 10 * by["medium"] + 3 * by["low"]
        score = round(100 * 100 / (100 + penalty))
        if by["critical"]:
            score = min(score, 49)
        elif by["high"]:
            score = min(score, 84)
        last = max((f["last_ok_at"] for f in enabled if f["last_ok_at"]), default=None)
        return {"score": score, "iocs": iocs, "feeds_enabled": len(enabled), "feeds_ok": len(ok),
                "feeds_stale": [f["key"] for f in stale], "feeds_need_key": needs_key, "last_update": last,
                "open_alerts": by, "watch_connections": bool(self._g("intel_watch_connections")),
                "auto_update": bool(self._g("intel_auto_update")), "auto_block": self._g("intel_auto_block"),
                "online_lookup": bool(self._g("intel_online_lookup")),
                "signatures_from_feeds": self.db.fetchone("SELECT COUNT(*) AS n FROM malware_signatures WHERE source "
                                                          "LIKE 'intel:%'")["n"] if self._table("malware_signatures") else 0}

    def summary(self, cu, days: int = 30) -> dict:
        since = _ago(24 * days)
        by_type = {r["type"]: r["n"] for r in self.db.fetchall(
            "SELECT i.type, COUNT(*) AS n FROM intel_iocs i JOIN intel_feeds f ON f.id=i.feed_id WHERE f.enabled=1 "
            "GROUP BY i.type")}
        by_cat = [{"category": r["c"], "label": feeds.CATEGORIES.get(r["c"], r["c"]), "count": r["n"]} for r in
                  self.db.fetchall("SELECT COALESCE(i.category, f.category) AS c, COUNT(*) AS n FROM intel_iocs i JOIN "
                                   "intel_feeds f ON f.id=i.feed_id WHERE f.enabled=1 GROUP BY 1 ORDER BY n DESC")]
        by_feed = [{"feed": f["key"], "name": f["name"], "count": f["ioc_count"], "status": f["status"],
                    "last_ok_at": f["last_ok_at"], "enabled": bool(f["enabled"])}
                   for f in self.db.fetchall("SELECT * FROM intel_feeds ORDER BY ioc_count DESC")]
        threats = self.db.fetchall("SELECT i.threat AS name, COUNT(*) AS count FROM intel_iocs i JOIN intel_feeds f ON "
                                   "f.id=i.feed_id WHERE f.enabled=1 AND i.threat IS NOT NULL AND i.type != 'cidr' "
                                   "GROUP BY i.threat ORDER BY count DESC LIMIT 15")
        alerts = self.db.fetchall("SELECT substr(ts,1,10) AS day, kind, severity, COUNT(*) AS n FROM intel_events WHERE "
                                  "ts >= ? AND (user_id IS ? OR user_id IS NULL) AND kind IN ('connection_match',"
                                  "'retro_file','retro_download','auto_block') GROUP BY 1,2,3 ORDER BY 1",
                                  (since, cu.user["id"]))
        per_day: dict[str, dict] = {}
        for a in alerts:
            d = per_day.setdefault(a["day"], {"day": a["day"], **{s: 0 for s in SEVERITIES}, "total": 0})
            d[a["severity"]] += a["n"]
            d["total"] += a["n"]
        checks = self.db.fetchall("SELECT substr(ts,1,10) AS day, verdict, COUNT(*) AS n FROM intel_checks WHERE "
                                  "user_id=? AND ts >= ? GROUP BY 1,2 ORDER BY 1", (cu.user["id"], since))
        cpd: dict[str, dict] = {}
        for c in checks:
            d = cpd.setdefault(c["day"], {"day": c["day"], **{v: 0 for v in VERDICTS}})
            d[c["verdict"]] += c["n"]
        top_ips = self.db.fetchall("SELECT json_extract(data,'$.ip') AS ip, json_extract(data,'$.process') AS process, "
                                   "COUNT(*) AS n, MAX(severity) AS severity FROM intel_events WHERE kind="
                                   "'connection_match' AND ts >= ? GROUP BY 1,2 ORDER BY n DESC LIMIT 10", (since,))
        return {"iocs_by_type": by_type, "iocs_by_category": by_cat, "feeds": by_feed, "top_threats": threats,
                "alerts_per_day": list(per_day.values()), "checks_per_day": list(cpd.values()),
                "top_matched_addresses": top_ips, "health": self.health(cu.user["id"]),
                "watch": dict(self.stats)}

    def status(self, cu) -> dict:
        g = self._g
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM intel_events WHERE (user_id IS ? OR user_id IS NULL) AND "
                                 "acknowledged=0", (cu.user["id"],))["n"]
        return {
            "features": {"check": True, "bulk_check": True, "phishing": True, "deep_check": True, "feeds": True,
                         "custom_feeds": True, "blocklist": True, "allowlist": True, "ioc_search": True, "hunt": True,
                         "connection_watch": self.network is not None, "firewall_block": self.firewall is not None,
                         "signatures": self.malware_db is not None, "retro_hunt": True, "stix": True,
                         "online": ONLINE_PROVIDERS},
            "settings": {k: g(k) for k in ("intel_auto_update", "intel_update_hours", "intel_watch_connections",
                                           "intel_watch_interval_seconds", "intel_auto_block",
                                           "intel_hashes_to_signatures", "intel_retro_hunt", "intel_online_lookup",
                                           "intel_online_providers", "intel_cache_hours", "intel_abuseipdb_min_score",
                                           "intel_max_feed_mb", "intel_history_days")},
            "health": self.health(cu.user["id"]), "providers": self.providers(), "jobs_running": self.jobs()["running"],
            "unacknowledged": unack, "types": list(ioc.TYPES), "verdicts": list(VERDICTS),
            "brands_known": len(ph.BRANDS), "watch": dict(self.stats), "catalog_reviewed": "2026-11-13",
        }


async def intel_loop(svc: ThreatIntelService, settings, first_delay: float = 60, every: float = 15) -> None:
    """Every 15 s: watch connections when due, start due feed downloads, daily cleanup."""
    import asyncio
    await asyncio.sleep(first_delay)
    while True:
        try:
            await asyncio.to_thread(svc.tick)
        except Exception as e:                                           # pragma: no cover
            log.warning("Threat intel tick failed: %s", e)
        await asyncio.sleep(every)
