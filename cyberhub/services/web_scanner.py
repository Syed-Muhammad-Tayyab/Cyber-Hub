"""
Cyber Hub Backend - Website / Developer Scanner (Part 14)
Developed by Syed Muhammad Tayyab

One service behind /api/web. Everything heavy runs as a background job with live progress and Cancel.

Website scan  (web_probe + web_checks)
  * passive checks (any site): HTTPS + certificate + TLS versions, security headers, cookies, CORS, mixed
    content / insecure forms / scripts without integrity / hijacked CDNs, debug pages and stack traces,
    technology fingerprint (CMS, framework, server, JS libraries) with known-vulnerable / end-of-life versions.
  * active checks (exposed files like /.git/ and /.env, directory listing, open ports) only run on this PC,
    your own network, or sites you confirm you own / manage (owner_confirmed) - 428 otherwise.
Project scan  (dep_audit + Part 13's sensitive_finder)
  * every npm / PyPI / Packagist package from lockfiles checked against OSV (online and / or an imported
    offline copy), secrets in the code (keys, tokens, passwords), risky settings (.env not git-ignored,
    debug on in production, tokens in .npmrc).
Saved targets + monitoring: re-scan on a schedule, alert on new problems, worse grade, certificate expiry,
unreachable site, new vulnerable packages. Dev servers: listening ports from Part 10 + the real Part 9
firewall verdict -> warns when e.g. a Vite / React / Django dev server or the Node debugger can be reached
from the network, one-click fix = Part 9 inbound port block.

Feeds Part 18 through health(user_id) and Part 17 through web_events.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from ..database import Database
from ..logger import get_logger
from . import dep_audit as da
from . import sensitive_finder as sf
from . import web_checks as wc
from . import web_probe as wp

log = get_logger("webscan")

SEVERITIES = wc.SEVERITIES
SEV = wc.SEV
MAX_RUNNING = 3
SITE_CHECKS = ("https", "headers", "content", "tech", "exposure", "ports")
ACTIVE_CHECKS = {"exposure", "ports"}
SECRET_TYPES = {"private_key", "api_key", "password"}
SECRET_SKIP = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
               "Pipfile.lock", "composer.lock"}
MAX_SECRET_FILES = 5000
CODE_EXT = {".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".kt", ".kts", ".swift", ".dart", ".tf", ".tfvars",
            ".gradle", ".scala", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".pl", ".lua", ".r", ".ipynb",
            ".erb", ".ejs", ".hbs", ".twig", ".tpl", ".graphql", ".prisma", ".pem", ".tfstate"}
MAX_DETAIL_FETCH = 400
CDN_HOSTS = ("code.jquery.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
             "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "ajax.aspnetcdn.com")
DEV_PORTS = {3000: "React / Next.js / Express", 3001: "Node dev server", 4000: "Jekyll / Phoenix / Gatsby",
             4200: "Angular", 4321: "Astro", 5000: "Flask / ASP.NET", 5001: "ASP.NET (HTTPS)", 5173: "Vite",
             5174: "Vite", 5500: "Live Server", 6006: "Storybook", 7860: "Gradio", 8000: "Django / Laravel / uvicorn",
             8001: "dev server", 8080: "dev server / Tomcat", 8081: "dev server", 8501: "Streamlit",
             8888: "Jupyter Notebook", 9000: "PHP / dev server", 1313: "Hugo", 19000: "Expo",
             9229: "Node.js debugger", 9222: "Chrome DevTools debugger", 24678: "Vite HMR"}
DEBUG_PORTS = {9229, 9222}
DEV_PROGRAMS = {"node", "python", "pythonw", "python3", "php", "ruby", "java", "dotnet", "deno", "bun", "hugo",
                "jupyter", "uvicorn", "gunicorn", "flask", "rails", "go", "air", "php-cgi"}
OSV_ECOSYSTEMS = da.ECOSYSTEMS
ENV_TEMPLATE = re.compile(r"(example|sample|template|dist|defaults?)")
EXAMPLE_FILE = re.compile(r"[/._-](example|examples|sample|samples|template|templates|fixture|fixtures|mock|mocks|"
                          r"dummy|demo)([/._-]|$)|/tests?/|/__tests__/|/spec/|[/_]test_|_test\.|\.test\.|\.spec\.")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _secret_candidate(path: str) -> bool:
    name = os.path.basename(path).lower()
    return name.startswith(".env") or os.path.splitext(name)[1] in CODE_EXT or sf.candidate(path)


def _project_text(path: str, max_bytes: int) -> tuple[str | None, str]:
    """Part 13's text extraction + source-code files and .env.* variants it doesn't know."""
    name = os.path.basename(path).lower()
    if name.startswith(".env") or os.path.splitext(name)[1] in CODE_EXT:
        try:
            with open(path, "rb") as f:
                return sf._decode_text(f.read(max_bytes)), "text"
        except OSError as e:
            return None, "error:" + type(e).__name__
    return sf.extract_text(path, max_bytes)


class WebError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class _Cancelled(Exception):
    pass


class _User:
    """What the service needs from a signed-in session (also built for monitor scans)."""
    def __init__(self, user: dict):
        self.user = user


class Job:
    def __init__(self, kind: str, cu, target: str, params: dict, target_id: int | None = None,
                 trigger: str = "manual", key: str | None = None):
        self.id = secrets.token_hex(8)
        self.kind = kind
        self.user_id = cu.user["id"] if cu else None
        self.username = cu.user["username"] if cu else "system"
        self.role = cu.user.get("role") if cu else "admin"
        self.target, self.target_id, self.trigger, self.key = target, target_id, trigger, key or target
        self.params = params
        self.status = "running"
        self.created_at = _now()
        self.finished_at: str | None = None
        self.progress = {"phase": "starting", "percent": 0, "step": 0, "steps": 1, "current": None}
        self.result: dict = {}
        self.error: str | None = None
        self.cancel = threading.Event()
        self.thread: threading.Thread | None = None

    def check(self) -> None:
        if self.cancel.is_set():
            raise _Cancelled()

    def tick(self, phase: str | None = None, step: int | None = None, current: str | None = None,
             percent: int | None = None) -> None:
        p = self.progress
        if phase:
            p["phase"] = phase
        if step is not None:
            p["step"] = step
            p["percent"] = min(99, int(step * 100 / max(1, p["steps"])))
        if percent is not None:
            p["percent"] = min(99, max(p["percent"], percent))
        if current is not None:
            p["current"] = current[:200]
        self.check()

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "target": self.target,
                "target_id": self.target_id, "trigger": self.trigger, "username": self.username,
                "created_at": self.created_at, "finished_at": self.finished_at, "progress": dict(self.progress),
                "summary": self._summary(), "error": self.error}

    def _summary(self) -> dict | None:
        r = self.result
        if not r or "score" not in r:
            return None
        return {"score": r["score"]["score"], "grade": r["score"]["grade"], "by_severity": r["score"]["by_severity"]}


# ====================================================================== service
class WebScannerService:
    DEV_TTL = 10.0

    def __init__(self, db: Database, settings, activity, network=None, firewall=None, data_dir: Path | None = None):
        self.db, self.settings, self.activity = db, settings, activity
        self.network, self.firewall = network, firewall
        self.data_dir = Path(data_dir) if data_dir else None
        self.osv = da.OSVClient()
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._dev_cache: tuple[float, dict] | None = None
        self._stopping = threading.Event()
        self._recover()

    def _recover(self) -> None:
        n = self.db.execute("UPDATE web_scans SET status='interrupted', finished_at=?, error=? WHERE status='running'",
                            (_now(), "Cyber Hub stopped while this scan was running")).rowcount
        if n:
            log.info("Marked %d interrupted web scan(s)", n)

    # ------------------------------------------------------------------ helpers
    def _g(self, key: str):
        return self.settings.get(key)

    def _state(self, key: str, value: Any = ...) -> Any:
        if value is ...:
            r = self.db.fetchone("SELECT value FROM web_state WHERE key=?", (key,))
            return json.loads(r["value"]) if r else None
        self.db.execute("INSERT INTO web_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))
        return value

    def _event(self, uid: int | None, kind: str, severity: str, title: str, detail: str | None = None,
               data: dict | None = None, target_id: int | None = None) -> None:
        self.db.execute("INSERT INTO web_events(user_id, target_id, kind, severity, title, detail, data) "
                        "VALUES (?,?,?,?,?,?,?)", (uid, target_id, kind, severity, title, detail,
                                                   json.dumps(data) if data else None))
        try:
            self.activity.record("web", title, detail, severity=severity, source="webscan")
        except ValueError:                                              # pragma: no cover
            pass

    @staticmethod
    def _can(cu, uid: int | None) -> bool:
        return cu.user.get("role") == "admin" or uid == cu.user["id"]

    # ================================================================== targets
    def _normalize(self, kind: str, target: str) -> tuple[str, dict]:
        if kind == "site":
            try:
                t = wp.parse_target(target)
            except wp.ProbeError as e:
                raise WebError(422, e.message)
            return t["url"] if t["explicit_scheme"] else t["origin"].split("://", 1)[1] + (
                "" if t["path"] == "/" else t["path"]), t
        if kind == "project":
            p = os.path.abspath(os.path.expanduser(target or ""))
            if not target or not os.path.isdir(p):
                raise WebError(404 if target else 422, "Pick an existing project folder")
            return p, {"path": p}
        raise WebError(422, "kind must be site or project")

    @staticmethod
    def _target_public(r: dict) -> dict:
        out = {k: r[k] for k in ("id", "kind", "target", "label", "created_at", "last_scan_id", "last_scan_at",
                                 "last_score", "last_grade", "last_error", "cert_not_after")}
        out["owner_confirmed"] = bool(r["owner_confirmed"])
        out["monitor"] = bool(r["monitor"])
        na = _parse_ts(r.get("cert_not_after"))
        out["cert_days_left"] = int((na - datetime.now(timezone.utc)).total_seconds() // 86400) if na else None
        return out

    def targets(self, cu, kind: str | None = None) -> list[dict]:
        where, params = ["user_id=?"], [cu.user["id"]]
        if kind:
            where.append("kind=?"); params.append(kind)
        rows = self.db.fetchall(f"SELECT * FROM web_targets WHERE {' AND '.join(where)} ORDER BY kind, target",
                                tuple(params))
        return [self._target_public(r) for r in rows]

    def _target_row(self, cu, tid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM web_targets WHERE id=?", (tid,))
        if not r or r["user_id"] != cu.user["id"]:
            raise WebError(404, "Saved target not found")
        return r

    def get_target(self, cu, tid: int) -> dict:
        return self._target_public(self._target_row(cu, tid))

    def save_target(self, cu, kind: str, target: str, label: str | None = None, monitor: bool | None = None,
                    owner_confirmed: bool | None = None) -> dict:
        norm, _ = self._normalize(kind, target)
        r = self.db.fetchone("SELECT * FROM web_targets WHERE user_id=? AND kind=? AND target=?",
                             (cu.user["id"], kind, norm))
        if r is None:
            n = self.db.fetchone("SELECT COUNT(*) AS n FROM web_targets WHERE user_id=?", (cu.user["id"],))["n"]
            if n >= 200:
                raise WebError(429, "You have 200 saved targets - remove some first")
            cur = self.db.execute("INSERT INTO web_targets(user_id, kind, target, label, monitor, owner_confirmed) "
                                  "VALUES (?,?,?,?,?,?)", (cu.user["id"], kind, norm, (label or None),
                                                           int(bool(monitor)), int(bool(owner_confirmed))))
            tid = cur.lastrowid
        else:
            tid = r["id"]
            self.update_target(cu, tid, label, monitor, owner_confirmed)
        return self.get_target(cu, tid)

    def update_target(self, cu, tid: int, label: str | None = None, monitor: bool | None = None,
                      owner_confirmed: bool | None = None) -> dict:
        r = self._target_row(cu, tid)
        sets, params = [], []
        if label is not None:
            sets.append("label=?"); params.append(label.strip()[:80] or None)
        if monitor is not None:
            sets.append("monitor=?"); params.append(int(monitor))
        if owner_confirmed is not None:
            if r["kind"] != "site":
                raise WebError(422, "Ownership only applies to websites")
            sets.append("owner_confirmed=?"); params.append(int(owner_confirmed))
        if sets:
            self.db.execute(f"UPDATE web_targets SET {', '.join(sets)} WHERE id=?", tuple(params) + (tid,))
        return self.get_target(cu, tid)

    def delete_target(self, cu, tid: int, delete_scans: bool = False) -> dict:
        self._target_row(cu, tid)
        n = 0
        if delete_scans:
            n = self.db.execute("DELETE FROM web_scans WHERE target_id=? AND status!='running'", (tid,)).rowcount
        self.db.execute("DELETE FROM web_targets WHERE id=?", (tid,))
        return {"deleted": tid, "scans_deleted": n}

    def target_history(self, cu, tid: int, limit: int = 50) -> dict:
        t = self.get_target(cu, tid)
        rows = self.db.fetchall("SELECT id, created_at, finished_at, status, score, grade, critical, high, medium, low "
                                "FROM web_scans WHERE target_id=? AND status='done' ORDER BY created_at DESC LIMIT ?",
                                (tid, limit))
        return {"target": t, "points": list(reversed(rows))}

    # ================================================================== jobs
    def _spawn(self, job: Job, steps: int, fn: Callable[[Job], dict]) -> dict:
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
            if len(running) >= MAX_RUNNING:
                raise WebError(429, f"{MAX_RUNNING} scans are already running - wait for one to finish")
            dup = next((j for j in running if j.key == job.key and j.user_id == job.user_id), None)
            if dup:
                raise WebError(409, f"This target is already being scanned (job {dup.id})")
            job.progress["steps"] = steps
            self._jobs[job.id] = job
        self.db.execute("INSERT INTO web_scans(id, user_id, username, target_id, kind, target, trigger, status, "
                        "created_at, params, progress) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (job.id, job.user_id, job.username, job.target_id, job.kind, job.target, job.trigger,
                         "running", job.created_at, json.dumps(job.params), json.dumps(job.progress)))

        def run():
            try:
                job.result = fn(job)
                job.status = "done"
            except _Cancelled:
                job.status = "cancelled"
            except (WebError, wp.ProbeError, da.DepError) as e:
                job.status, job.error = "failed", e.message
            except Exception as e:                                       # pragma: no cover
                log.exception("Web scan %s failed", job.id)
                job.status, job.error = "failed", f"Unexpected error: {e}"
            finally:
                job.finished_at = _now()
                job.progress["percent"] = 100 if job.status == "done" else job.progress["percent"]
                job.progress["phase"] = job.status
                sc = (job.result or {}).get("score") or {}
                by = sc.get("by_severity") or {}
                self.db.execute("UPDATE web_scans SET status=?, finished_at=?, progress=?, result=?, score=?, grade=?, "
                                "critical=?, high=?, medium=?, low=?, error=? WHERE id=?",
                                (job.status, job.finished_at, json.dumps(job.progress),
                                 json.dumps(job.result)[:4_000_000] if job.result else None, sc.get("score"),
                                 sc.get("grade"), by.get("critical", 0), by.get("high", 0), by.get("medium", 0),
                                 by.get("low", 0), job.error, job.id))
                try:
                    self._after(job)
                except Exception:                                        # pragma: no cover
                    log.exception("After-scan handling failed for %s", job.id)
        job.thread = threading.Thread(target=run, name=f"web-{job.kind}-{job.id}", daemon=True)
        job.thread.start()
        return job.public()

    def jobs_for(self, cu, limit: int = 30, kind: str | None = None) -> dict:
        with self._lock:
            live = [j.public() for j in self._jobs.values() if j.status == "running" and self._can(cu, j.user_id)]
        where, params = ["status!='running'"], []
        if cu.user.get("role") != "admin":
            where.append("user_id=?"); params.append(cu.user["id"])
        if kind:
            where.append("kind=?"); params.append(kind)
        rows = self.db.fetchall(f"SELECT id, kind, target, target_id, trigger, username, status, created_at, "
                                f"finished_at, score, grade, critical, high, medium, low, error FROM web_scans WHERE "
                                f"{' AND '.join(where)} ORDER BY created_at DESC LIMIT ?", tuple(params) + (limit,))
        return {"running": live, "history": rows}

    def job(self, cu, job_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if j and self._can(cu, j.user_id):
            return j.public()
        r = self.db.fetchone("SELECT * FROM web_scans WHERE id=?", (job_id,))
        if not r or not self._can(cu, r["user_id"]):
            raise WebError(404, "Scan not found")
        return {"id": r["id"], "kind": r["kind"], "status": r["status"], "target": r["target"],
                "target_id": r["target_id"], "trigger": r["trigger"], "username": r["username"],
                "created_at": r["created_at"], "finished_at": r["finished_at"],
                "progress": json.loads(r["progress"]) if r["progress"] else None,
                "summary": {"score": r["score"], "grade": r["grade"],
                            "by_severity": {k: r[k] for k in ("critical", "high", "medium", "low")}}
                if r["score"] is not None else None, "error": r["error"]}

    def cancel(self, cu, job_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if not j or not self._can(cu, j.user_id):
            raise WebError(404, "Scan not found")
        if j.status != "running":
            raise WebError(409, f"Scan is already {j.status}")
        j.cancel.set()
        return {"id": j.id, "cancelling": True}

    def wait(self, job_id: str, timeout: float = 60) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if j and j.thread:
            j.thread.join(timeout)
        return j.public() if j else {}

    def shutdown(self) -> None:
        self._stopping.set()
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.status == "running"]
        for j in jobs:
            j.cancel.set()
        for j in jobs:
            if j.thread:
                j.thread.join(15)

    # ================================================================== scans (stored)
    def scans(self, cu, kind: str | None = None, target_id: int | None = None, limit: int = 50,
              offset: int = 0) -> dict:
        where, params = ["user_id=?"], [cu.user["id"]]
        if kind:
            where.append("kind=?"); params.append(kind)
        if target_id:
            where.append("target_id=?"); params.append(target_id)
        w = " AND ".join(where)
        rows = self.db.fetchall(f"SELECT id, kind, target, target_id, trigger, status, created_at, finished_at, score, "
                                f"grade, critical, high, medium, low, error FROM web_scans WHERE {w} "
                                f"ORDER BY created_at DESC LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM web_scans WHERE {w}", tuple(params))["n"]
        return {"total": total, "items": rows}

    def scan(self, cu, scan_id: str) -> dict:
        r = self.db.fetchone("SELECT * FROM web_scans WHERE id=?", (scan_id,))
        if not r or not self._can(cu, r["user_id"]):
            raise WebError(404, "Scan not found")
        r = dict(r)
        for k in ("params", "progress", "result"):
            r[k] = json.loads(r[k]) if r.get(k) else None
        return r

    def delete_scan(self, cu, scan_id: str) -> dict:
        r = self.db.fetchone("SELECT user_id, status FROM web_scans WHERE id=?", (scan_id,))
        if not r or not self._can(cu, r["user_id"]):
            raise WebError(404, "Scan not found")
        if r["status"] == "running":
            raise WebError(409, "Cancel the scan first")
        self.db.execute("DELETE FROM web_scans WHERE id=?", (scan_id,))
        return {"deleted": scan_id}

    def _previous(self, uid: int | None, kind: str, target: str, before: str) -> dict | None:
        r = self.db.fetchone("SELECT id, result, grade, score FROM web_scans WHERE user_id IS ? AND kind=? AND target=? "
                             "AND status='done' AND created_at < ? ORDER BY created_at DESC LIMIT 1",
                             (uid, kind, target, before))
        if r and r.get("result"):
            r["result"] = json.loads(r["result"])
            return r
        return None

    # ================================================================== website scan
    def start_site_scan(self, cu, target: str, checks: list[str] | None = None, confirm_owner: bool = False,
                        save: bool = False, monitor: bool | None = None, label: str | None = None,
                        trigger: str = "manual") -> dict:
        norm, t = self._normalize("site", target)
        if checks is not None:
            bad = sorted(set(checks) - set(SITE_CHECKS))
            if bad:
                raise WebError(422, f"Unknown check(s): {', '.join(bad)}. Use: {', '.join(SITE_CHECKS)}")
        try:
            ips = wp.resolve(t["host"], t["port"], 5.0)
        except wp.ProbeError as e:
            raise WebError(422, e.message)
        scope, why = wp.scope_of(t["host"], ips)
        if scope == "refused":
            raise WebError(403, why or "This address can't be scanned")
        trow = self.db.fetchone("SELECT * FROM web_targets WHERE user_id=? AND kind='site' AND target=?",
                                (cu.user["id"], norm))
        owner = bool(confirm_owner) or bool(trow and trow["owner_confirmed"]) or scope != "public"
        wanted = list(dict.fromkeys(checks or SITE_CHECKS))
        skipped: list[dict] = []
        active = [c for c in wanted if c in ACTIVE_CHECKS]
        if active and not owner:
            if checks is not None:
                raise WebError(428, f"{' and '.join(active)} checks touch {t['host']} more than a normal visit (they "
                                    "look for leaked files and open ports). Only run them on sites you own or manage "
                                    "- send confirm_owner=true to confirm that you do")
            for c in active:
                skipped.append({"check": c, "reason": "Only on sites you own - tick 'I own / manage this site'"})
            wanted = [c for c in wanted if c not in ACTIVE_CHECKS]
        if "exposure" in wanted and not self._g("web_check_exposed_files"):
            wanted.remove("exposure")
            skipped.append({"check": "exposure", "reason": "Turned off in settings (web_check_exposed_files)"})
        tid = None
        confirmed_now = bool(confirm_owner) and scope == "public"       # remembered with the target (no re-asking)
        if save or monitor is not None or trow is not None or confirmed_now:
            tid = self.save_target(cu, "site", norm, label, monitor, True if confirmed_now else None)["id"]
        params = {"checks": wanted, "skipped": skipped, "scope": scope, "owner_confirmed": owner}
        job = Job("site", cu, norm, params, tid, trigger, key=f"site:{norm}")
        steps = 3 + len(wanted)
        return self._spawn(job, steps, lambda j: self._run_site(j, t, ips, scope, wanted, skipped))

    def _run_site(self, job: Job, t: dict, ips: list[str], scope: str, checks: list[str],
                  skipped: list[dict]) -> dict:
        timeout = float(self._g("web_scan_timeout_seconds"))
        fx = wp.Fetcher(timeout=timeout, max_requests=90, start_scope=scope, cancel=job.check)
        findings: list[dict] = []
        passed: list[dict] = []
        step = 0
        job.tick("connecting", step, t["host"])
        # ---- 1. load the page (https first unless http:// was typed)
        page = None
        first_err = None
        tries = [t["url"]] if t["explicit_scheme"] else [t["url"], "http://" + t["url"].split("://", 1)[1]]
        if not t["explicit_scheme"] and t["port"] == 443:
            tries[1] = f"http://{t['origin'].split('://', 1)[1]}{t['path']}"
        for u in tries:
            try:
                page = fx.fetch(u)
                break
            except wp.ProbeError as e:
                if e.code in ("redirect_local", "refused_scope", "budget"):
                    raise WebError(422, e.message)
                first_err = first_err or e
                job.check()
        if page is None:
            raise WebError(502, f"Could not reach {t['host']}: {first_err.message if first_err else 'no answer'}")
        final = wp.parse_target(page["final_url"])
        is_https = final["scheme"] == "https"
        h = page["h"]
        html = wc.page_text(page["body"], h)
        ctype = (wc.first(h, "content-type") or "").lower()
        is_html = "html" in ctype or (not ctype and "<html" in html[:2000].lower())
        cookie_values = []
        step += 1
        job.tick("reading the page", step)
        facts: dict[str, Any] = {}
        # ---- 2. headers, cookies, CORS, page content, debug pages
        if "headers" in checks:
            f, ok, facts["headers"] = wc.analyze_headers(h, is_https, is_html)
            findings += f
            passed += ok
            evil = "https://cyberhub-cors-check.invalid"
            try:
                cr = fx.fetch(page["final_url"], headers={"Origin": evil}, follow=False, max_body=1024)
                findings += wc.analyze_cors(cr["h"], evil)
            except wp.ProbeError:
                pass
        cookie_values = list(h.get("set-cookie", []))
        f, ok, cookies = wc.analyze_cookies(cookie_values, is_https)
        if "headers" in checks:
            findings += f
            passed += ok
        content: dict = {"scripts": [], "generator": None}
        if "content" in checks and is_html:
            f, ok, content = wc.analyze_html(html, page["final_url"], is_https)
            findings += f
            passed += ok
        elif is_html:
            _f, _ok, content = wc.analyze_html(html, page["final_url"], is_https)
        findings += wc.find_debug_leaks(html, "the home page")
        baseline = None
        try:
            rnd = f"/cyberhub-check-{secrets.token_hex(6)}.html"
            b = fx.fetch(final["origin"] + rnd, follow=False, max_body=262144)
            baseline = wc.soft404_signature(b["status"], b["body"])
            facts["not_found_status"] = b["status"]
            for x in wc.find_debug_leaks(wc.page_text(b["body"], b["h"]), "a missing page (404)"):
                if not any(y["id"] == x["id"] for y in findings):
                    findings.append(x)
            if b["status"] == 200:
                findings.append(wc.F("soft_404", "content", "info", "Missing pages answer 200 OK",
                                     "Pages that don't exist still return status 200, which confuses search engines "
                                     "and security tools.", "Return a real 404 status for unknown addresses"))
        except wp.ProbeError:
            pass
        step += 1
        # ---- 3. HTTPS / certificate
        tls_summary = None
        if "https" in checks:
            job.tick("checking HTTPS and the certificate", step, final["host"])
            redirects = None
            if is_https:
                if final["port"] == 443:
                    try:
                        r80 = fx.fetch(f"http://{final['origin'].split('://', 1)[1]}{final['path']}", follow=False,
                                       max_body=1024, timeout=min(timeout, 6))
                        loc = (wc.first(r80["h"], "location") or "")
                        redirects = r80["status"] in (301, 302, 307, 308) and loc.lower().startswith("https://")
                    except wp.ProbeError:
                        redirects = None                       # port 80 closed is fine
                tls = wp.tls_info(final["host"], page["ip"], final["port"], timeout)
                f, ok = wc.evaluate_tls(tls, scope, int(self._g("web_cert_warn_days")), redirects)
            else:
                tls = None
                https_port = 443 if t["port"] in (80, 443) else None
                tls_try = wp.tls_info(final["host"], page["ip"], https_port, min(timeout, 6), test_versions=False) \
                    if https_port else {"available": False, "error": "site uses plain HTTP"}
                if tls_try.get("available"):
                    f = [wc.F("https_not_default", "https", "low" if scope != "public" else "medium",
                              "Site opens on plain HTTP although HTTPS works",
                              "The site answers on https:// but doesn't send visitors there.",
                              "Redirect every http:// request to https:// and add HSTS")]
                    ok = []
                    tls = tls_try
                else:
                    f, ok = wc.evaluate_tls(tls_try, scope, int(self._g("web_cert_warn_days")), None)
            findings += f
            passed += ok
            if tls:
                c = tls.get("cert") or {}
                tls_summary = {k: tls.get(k) for k in ("available", "trusted", "verify_error", "hostname_ok", "protocol",
                                                       "cipher", "cipher_bits", "versions", "chain_length")}
                tls_summary["cert"] = c or None
            step += 1
        # ---- 4. technology fingerprint (+ banners of up to 5 JS files)
        technologies: list[dict] = []
        if "tech" in checks:
            job.tick("identifying software and libraries", step)
            banners: dict[str, str] = {}
            from urllib.parse import urlsplit
            own_host = final["host"]
            js = [s for s in content.get("scripts", []) if s.split("?")[0].endswith(".js") and
                  (urlsplit(s).hostname in (own_host,) + CDN_HOSTS)]
            for s in js[:5]:
                try:
                    r = fx.fetch(s, max_body=3072, timeout=min(timeout, 6))
                    if r["status"] == 200:
                        banners[s] = r["body"][:3072].decode("utf-8", "replace")
                except wp.ProbeError:
                    continue
            names = [wc.parse_set_cookie(v)["name"] for v in cookie_values]
            technologies, f = wc.fingerprint(h, names, html, content.get("generator"), content.get("scripts", []),
                                             banners)
            findings += f
            if not f:
                passed.append(wc.P("tech", "tech", "No outdated software recognised"))
            step += 1
        # ---- 5. exposed files (active)
        exposure = None
        if "exposure" in checks:
            job.tick("looking for exposed files", step)
            probes = list(wc.EXPOSURE_PROBES)
            if any(x["name"] == "WordPress" for x in technologies) or "/wp-content/" in html:
                probes += wc.WP_PROBES
            found_groups: set[str] = set()
            probed = 0
            for i, pr in enumerate(probes):
                if pr["group"] in found_groups:
                    continue
                job.tick(current=pr["path"], percent=int((step + i / len(probes)) * 100 / job.progress["steps"]))
                try:
                    r = fx.fetch(final["origin"] + pr["path"], follow=False, max_body=65536,
                                 headers={"Range": "bytes=0-65535"}, timeout=min(timeout, 8))
                    probed += 1
                except wp.ProbeError as e:
                    if e.code == "budget":
                        break
                    continue
                if wc.check_exposure(pr, r["status"], r["body"], r["h"], baseline):
                    found_groups.add(pr["group"])
                    findings.append(wc.F(f"exposed_{pr['group']}", "exposure", pr["severity"], pr["title"],
                                         pr["detail"], pr["advice"], final["origin"] + pr["path"], path=pr["path"]))
            listing = []
            for d in wc.DIR_PROBES:
                try:
                    r = fx.fetch(final["origin"] + d, follow=False, max_body=32768, timeout=min(timeout, 6))
                    probed += 1
                except wp.ProbeError:
                    continue
                if r["status"] == 200 and wc.DIR_LISTING.search(wc.page_text(r["body"], r["h"])):
                    listing.append(d)
            if wc.DIR_LISTING.search(html[:5000]):
                listing.insert(0, final["path"])
            if listing:
                findings.append(wc.F("dir_listing", "exposure", "medium", "Directory listing is on",
                                     f"Anyone can browse the files in {', '.join(listing[:5])} - backups and private "
                                     "uploads are easy to find.",
                                     "Turn it off: Apache Options -Indexes; nginx autoindex off; IIS directoryBrowse "
                                     "off", ", ".join(listing[:10])))
            try:
                r = fx.fetch(final["origin"] + "/robots.txt", follow=False, max_body=65536, timeout=min(timeout, 6))
                if r["status"] == 200 and not wc._is_html(r["body"]):
                    juicy = wc.robots_paths(wc.page_text(r["body"], r["h"]))
                    if juicy:
                        findings.append(wc.F("robots_hints", "exposure", "info", "robots.txt points to private areas",
                                             "robots.txt is public; listing admin / backup paths there tells "
                                             "attackers where to look.", "Protect those paths with a login instead",
                                             ", ".join(juicy)))
            except wp.ProbeError:
                pass
            try:
                r = fx.fetch(final["origin"] + "/.well-known/security.txt", follow=False, max_body=16384,
                             timeout=min(timeout, 6))
                if r["status"] == 200 and b"contact:" in r["body"].lower() and not wc._is_html(r["body"]):
                    passed.append(wc.P("security_txt", "exposure", "security.txt tells researchers how to reach you"))
                else:
                    findings.append(wc.F("security_txt_missing", "exposure", "info", "No security.txt",
                                         "security.txt (RFC 9116) tells people who find a bug how to report it.",
                                         "Add /.well-known/security.txt with Contact: and Expires: lines"))
            except wp.ProbeError:
                pass
            if not any(f["category"] == "exposure" and SEV[f["severity"]] >= SEV["low"] for f in findings):
                passed.append(wc.P("exposure", "exposure", f"No exposed files found ({probed} addresses checked)"))
            exposure = {"probed": probed, "found": sorted(found_groups), "directory_listing": listing}
            step += 1
        # ---- 6. open ports (active)
        ports = None
        if "ports" in checks:
            job.tick("checking open ports", step, page["ip"])
            res = wp.port_scan(page["ip"], timeout=1.5, cancel=job.check)
            f, ok, software = wc.evaluate_ports(res, scope, final["port"])
            findings += f
            passed += ok
            ports = {"ip": page["ip"], "checked": len(res), "open": [r for r in res if r["state"] == "open"],
                     "software": software}
            step += 1
        job.tick("scoring", step)
        findings = wc.sort_findings(wc.dedupe(findings))
        sc = wc.score(findings)
        prev = self._previous(job.user_id, "site", job.target, job.created_at)
        changes = wc.diff(prev["result"].get("findings", []), findings) if prev else None
        security_headers = {k: wc.first(h, k) for k in (
            "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy", "server", "x-powered-by") if wc.first(h, k)}
        return {
            "kind": "site",
            "target": {"input": job.target, "url": page["url"], "final_url": page["final_url"], "host": final["host"],
                       "ip": page["ip"], "scope": scope, "scheme": final["scheme"]},
            "checks": checks, "skipped": skipped,
            "response": {"status": page["status"], "elapsed_ms": page["elapsed_ms"], "http_version": page["version"],
                         "content_type": ctype or None, "redirects": page["chain"][:-1], "truncated": page["truncated"],
                         "security_headers": security_headers},
            "tls": tls_summary, "cookies": cookies, "technologies": technologies, "exposure": exposure,
            "ports": ports, "findings": findings, "passed": passed, "score": sc,
            "changes": {k: [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in v]
                        for k, v in changes.items()} if changes else None,
            "previous": {"id": prev["id"], "grade": prev["grade"], "score": prev["score"]} if prev else None,
            "requests": fx.requests, "tables_reviewed": wc.TABLES_REVIEWED,
        }

    # ================================================================== project scan
    def start_project_scan(self, cu, path: str, online: bool | None = None, secrets_scan: bool | None = None,
                           save: bool = False, monitor: bool | None = None, label: str | None = None,
                           trigger: str = "manual") -> dict:
        norm, _ = self._normalize("project", path)
        if norm in (os.path.abspath(os.sep), os.path.abspath(str(Path.home()))) or len(norm) <= 3:
            raise WebError(403, "Pick a project folder, not a whole drive or your home folder")
        online = bool(self._g("web_dep_online")) if online is None else bool(online)
        secrets_scan = bool(self._g("web_secret_scan")) if secrets_scan is None else bool(secrets_scan)
        trow = self.db.fetchone("SELECT id FROM web_targets WHERE user_id=? AND kind='project' AND target=?",
                                (cu.user["id"], norm))
        tid = None
        if save or monitor is not None or trow is not None:
            tid = self.save_target(cu, "project", norm, label, monitor)["id"]
        params = {"online": online, "secrets": secrets_scan}
        job = Job("project", cu, norm, params, tid, trigger, key=f"project:{os.path.normcase(norm)}")
        return self._spawn(job, 5, lambda j: self._run_project(j, norm, online, secrets_scan))

    def _run_project(self, job: Job, root: str, online: bool, secrets_scan: bool) -> dict:
        job.tick("finding package files", 0, root)
        col = da.collect(root)
        deps = col["deps"]
        job.tick("checking packages", 1, f"{len(deps)} packages")
        vulns, online_info = self.lookup(deps, online, job)
        findings: list[dict] = []
        passed: list[dict] = []
        packages = []
        for d in deps:
            hits = vulns.get((d["ecosystem"], da.norm_name(d["ecosystem"], d["name"]), d["version"])) or []
            if not hits:
                continue
            sev = max((v["severity"] for v in hits), key=lambda s: SEV[s])
            malicious = any(str(v["id"]).startswith("MAL-") for v in hits)
            if d["dev"] and not malicious:
                sev = wc.LOWER[sev] if sev != "critical" else "high"
            fixes = [v["fixed"] for v in hits if v.get("fixed")]
            fixed = None
            for fv in fixes:
                if fixed is None or (da.vcmp(d["ecosystem"], fv, fixed) or 0) > 0:
                    fixed = fv
            advisories = [{"id": v["id"], "aliases": v.get("aliases", [])[:5], "summary": v.get("summary"),
                           "severity": v["severity"], "cvss": v.get("cvss"), "fixed": v.get("fixed"),
                           "url": v.get("url")} for v in sorted(hits, key=lambda v: -SEV[v["severity"]])]
            title = (f"Malicious package {d['name']} {d['version']}" if malicious else
                     f"{d['name']} {d['version']} has {len(hits)} known vulnerabilit{'y' if len(hits) == 1 else 'ies'}")
            detail = "; ".join(f"{a['id']}: {a['summary'] or 'see advisory'}" for a in advisories[:4])
            if d["dev"] and not malicious:
                detail += " (development dependency - lower risk for the live site)"
            if d["approx"]:
                detail += " (version guessed from the range in " + d["file"] + " - add a lockfile for exact results)"
            advice = ("Remove it immediately, delete node_modules / the virtual env and rotate any secret the "
                      "machine had access to" if malicious else
                      (f"Upgrade {d['name']} to {fixed} or later" if fixed else
                       f"No fixed version yet - check the advisory for workarounds or replace {d['name']}"))
            fid = f"dep:{d['ecosystem']}:{da.norm_name(d['ecosystem'], d['name'])}@{d['version']}"
            findings.append(wc.F(fid, "deps", sev, title, detail, advice, ", ".join(d["files"][:5]),
                                 package={"ecosystem": d["ecosystem"], "name": d["name"], "version": d["version"],
                                          "dev": d["dev"], "direct": d["direct"], "approx": d["approx"],
                                          "fixed": fixed, "files": d["files"][:10]}, advisories=advisories[:20]))
            packages.append({"ecosystem": d["ecosystem"], "name": d["name"], "version": d["version"], "dev": d["dev"],
                             "direct": d["direct"], "severity": sev, "vulns": len(hits), "fixed": fixed})
        if deps and not packages and (online_info["ok"] or online_info["offline_records"]):
            passed.append(wc.P("deps", "deps", f"No known vulnerabilities in {len(deps)} packages"))
        if col["no_lockfile"]:
            findings.append(wc.F("no_lockfile", "config", "low", "No lockfile - versions are not pinned",
                                 f"{', '.join(col['no_lockfile'][:5])} without package-lock.json / yarn.lock / "
                                 "composer.lock: every install can pull different (possibly hijacked) versions, and "
                                 "this check can only guess the versions.",
                                 "Commit the lockfile (npm install creates package-lock.json) and use npm ci / "
                                 "composer install in deployments", ", ".join(col["no_lockfile"][:10])))
        if col["unpinned"]:
            findings.append(wc.F("unpinned_requirements", "config", "low",
                                 f"{len(col['unpinned'])} Python package(s) without an exact version",
                                 "requirements files without == pins install whatever is newest, so builds can change "
                                 "without you noticing and these packages can't be checked.",
                                 "Pin versions (pip freeze > requirements.txt, or use pip-tools / poetry / uv lock)",
                                 ", ".join(col["unpinned"][:15])))
        job.tick("looking for secrets in the code", 2)
        secret_info = {"enabled": secrets_scan, "files_checked": 0, "files_with_secrets": 0}
        if secrets_scan:
            f, secret_info = self._secrets(root, job)
            findings += f
            if not f:
                passed.append(wc.P("secrets", "secrets",
                                   f"No keys or passwords found in {secret_info['files_checked']} files"))
        job.tick("checking project settings", 3)
        cfg = da.config_checks(root)
        findings += cfg
        if not cfg:
            passed.append(wc.P("config", "config", "No risky project settings found"))
        job.tick("scoring", 4)
        findings = wc.sort_findings(wc.dedupe(findings))
        sc = wc.score(findings)
        prev = self._previous(job.user_id, "project", job.target, job.created_at)
        changes = wc.diff(prev["result"].get("findings", []), findings) if prev else None
        by_eco: dict[str, int] = {}
        for d in deps:
            by_eco[d["ecosystem"]] = by_eco.get(d["ecosystem"], 0) + 1
        packages.sort(key=lambda p: (-SEV[p["severity"]], p["name"].lower()))
        return {
            "kind": "project", "project": {"path": root, "name": os.path.basename(root.rstrip(os.sep)) or root},
            "files": col["files"], "file_errors": col["errors"],
            "dependencies": {"total": len(deps), "by_ecosystem": by_eco, "vulnerable": len(packages),
                             "direct": sum(1 for d in deps if d["direct"]), "dev": sum(1 for d in deps if d["dev"]),
                             "approximate": sum(1 for d in deps if d["approx"])},
            "packages": packages, "lookup": online_info, "secrets": secret_info,
            "findings": findings, "passed": passed, "score": sc,
            "changes": {k: [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in v]
                        for k, v in changes.items()} if changes else None,
            "previous": {"id": prev["id"], "grade": prev["grade"], "score": prev["score"]} if prev else None,
        }

    def _secrets(self, root: str, job: Job | None) -> tuple[list[dict], dict]:
        """Keys / tokens / passwords in project files - Part 13's sensitive-file rules, values masked."""
        findings: list[dict] = []
        checked = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in da.SKIP_DIRS and d != ".git")
            for fn in sorted(filenames):
                if fn in SECRET_SKIP or fn.endswith((".min.js", ".map", ".lock")):
                    continue
                env_example = fn.lower().startswith(".env") and bool(ENV_TEMPLATE.search(fn.lower()))
                if fn.lower().startswith(".env") and not env_example:
                    continue                    # .env is where secrets belong - config_checks reports if it's not git-ignored
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.islink(p) or os.path.getsize(p) > 1024 * 1024 or not _secret_candidate(p):
                        continue
                except OSError:
                    continue
                if checked >= MAX_SECRET_FILES:
                    break
                checked += 1
                if job and checked % 200 == 0:
                    job.tick(current=os.path.relpath(p, root))
                try:
                    found, _how = sf.analyze_file(p, SECRET_TYPES, 1024 * 1024, _project_text)
                except Exception:                                        # pragma: no cover
                    continue
                if not found:
                    continue
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                low = rel.lower()
                example = bool(EXAMPLE_FILE.search("/" + low)) or low.endswith((".md", ".txt", ".rst"))
                sev, _pts = sf.summarize(found)
                if example and sev != "critical":
                    sev = "low"
                elif example:
                    sev = "medium"
                if env_example:                 # committed on purpose, so real values in it leak with the repo
                    sev = wc.sev_max(sev, "medium") if sev != "critical" else sev
                samples = [s for v in found.values() for s in v.get("samples", [])][:5]
                kinds = sorted({sf.DETECTORS[k][0] for k in found})
                findings.append(wc.F(f"secret:{rel}", "secrets", sev, f"{', '.join(kinds)} in {rel}",
                                     f"Found: {'; '.join(samples)}. Anyone with this code (Git history, a zip you "
                                     "share, a public repo) gets them." + (" Looks like an example file." if example
                                                                           else ""),
                                     "Move secrets to environment variables or a secrets manager, add the file to "
                                     ".gitignore, and rotate (re-issue) every key that was ever committed.", rel,
                                     file=rel))
        return findings, {"enabled": True, "files_checked": checked, "files_with_secrets": len(findings)}

    # ================================================================== vulnerability lookups
    def _store_vulns(self, records: list[dict], source: str) -> int:
        n = 0
        with self.db.tx() as c:
            for v in records:
                if not v.get("id"):
                    continue
                if v.get("withdrawn"):
                    c.execute("DELETE FROM web_vulns WHERE id=?", (v["id"],))
                    continue
                c.execute("INSERT INTO web_vulns(id, summary, severity, cvss, aliases, published, modified, data, "
                          "source, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                          "summary=excluded.summary, severity=excluded.severity, cvss=excluded.cvss, "
                          "aliases=excluded.aliases, published=excluded.published, modified=excluded.modified, "
                          "data=excluded.data, source=CASE WHEN web_vulns.source='import' AND excluded.source='online' "
                          "THEN 'import' ELSE excluded.source END, fetched_at=excluded.fetched_at",
                          (v["id"], v.get("summary"), v["severity"], v.get("cvss"), json.dumps(v.get("aliases") or []),
                           v.get("published"), v.get("modified"), json.dumps(v), source, _now()))
                for a in v.get("affected") or []:
                    eco = a["package"]["ecosystem"]
                    c.execute("INSERT OR IGNORE INTO web_vuln_pkgs(ecosystem, name, vuln_id) VALUES (?,?,?)",
                              (eco, da.norm_name(eco, a["package"]["name"]), v["id"]))
                n += 1
        return n

    def _load_vulns(self, ids: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = ",".join("?" * len(chunk))
            for r in self.db.fetchall(f"SELECT id, data, fetched_at FROM web_vulns WHERE id IN ({q})", tuple(chunk)):
                d = json.loads(r["data"])
                d["_fetched_at"] = r["fetched_at"]
                out[r["id"]] = d
        return out

    def lookup(self, deps: list[dict], online: bool, job: Job | None = None) -> tuple[dict, dict]:
        """{(eco, norm name, version): [vuln{id, severity, summary, fixed, url, aliases, cvss}]}, info."""
        info = {"online": online, "ok": None, "error": None, "queried": 0, "cached": 0, "details_fetched": 0,
                "offline_records": self.db.fetchone("SELECT COUNT(*) AS n FROM web_vulns WHERE source='import'")["n"]}
        keyed = [(d["ecosystem"], da.norm_name(d["ecosystem"], d["name"]), d["version"], d["name"]) for d in deps
                 if d["version"] and d["ecosystem"] in OSV_ECOSYSTEMS]
        keyed = list({(e, n, v): (e, n, v, raw) for e, n, v, raw in keyed}.values())
        ids_for: dict[tuple, set[str]] = {(e, n, v): set() for e, n, v, _r in keyed}
        # ---- offline: packages that have any stored record, matched with OSV's range rules
        names = sorted({(e, n) for e, n, _v, _r in keyed})
        cand: dict[tuple, list[str]] = {}
        for i in range(0, len(names), 300):
            chunk = names[i:i + 300]
            q = " OR ".join("(ecosystem=? AND name=?)" for _ in chunk)
            for r in self.db.fetchall(f"SELECT ecosystem, name, vuln_id FROM web_vuln_pkgs WHERE {q}",
                                      tuple(x for pair in chunk for x in pair)):
                cand.setdefault((r["ecosystem"], r["name"]), []).append(r["vuln_id"])
        stored = self._load_vulns(sorted({v for lst in cand.values() for v in lst}))
        for e, n, v, raw in keyed:
            for vid in cand.get((e, n), []):
                rec = stored.get(vid)
                if rec and da.is_affected(rec, e, raw, v):
                    ids_for[(e, n, v)].add(vid)
        # ---- online: osv.dev querybatch (cached), then details for ids we don't have
        if online and keyed:
            cache_days = int(self._g("web_osv_cache_days"))
            fresh_after = (datetime.now(timezone.utc) - timedelta(days=cache_days)).strftime("%Y-%m-%dT%H:%M:%S")
            todo = []
            for e, n, v, raw in keyed:
                r = self.db.fetchone("SELECT vuln_ids, fetched_at FROM web_osv_cache WHERE key=?", (f"{e}|{n}|{v}",))
                if r and cache_days > 0 and r["fetched_at"] >= fresh_after:
                    ids_for[(e, n, v)].update(json.loads(r["vuln_ids"]))
                    info["cached"] += 1
                else:
                    todo.append((e, n, v, raw))
            try:
                if todo:
                    if job:
                        job.tick(current=f"asking osv.dev about {len(todo)} packages")
                    res = self.osv.query_batch([(e, raw, v) for e, _n, v, raw in todo])
                    info["queried"] = len(todo)
                    now = _now()
                    with self.db.tx() as c:
                        for (e, n, v, _raw), ids in zip(todo, res):
                            ids_for[(e, n, v)].update(ids)
                            c.execute("INSERT INTO web_osv_cache(key, vuln_ids, fetched_at) VALUES (?,?,?) ON CONFLICT"
                                      "(key) DO UPDATE SET vuln_ids=excluded.vuln_ids, fetched_at=excluded.fetched_at",
                                      (f"{e}|{n}|{v}", json.dumps(ids), now))
                need = sorted({i for s in ids_for.values() for i in s} - set(stored))
                have = self._load_vulns(need)
                stored.update(have)
                missing = [i for i in need if i not in have][:MAX_DETAIL_FETCH]
                if missing:
                    if job:
                        job.tick(current=f"downloading {len(missing)} advisories")

                    def get(vid: str):
                        try:
                            return da.compact(self.osv.vuln(vid))
                        except da.DepError:
                            return None
                    with ThreadPoolExecutor(max_workers=8) as ex:
                        recs = [r for r in ex.map(get, missing) if r]
                    self._store_vulns(recs, "online")
                    info["details_fetched"] = len(recs)
                    stored.update({r["id"]: r for r in recs})
                info["ok"] = True
            except da.DepError as e:
                info["ok"], info["error"] = False, e.message
        out: dict[tuple, list[dict]] = {}
        for e, n, v, raw in keyed:
            hits = []
            for vid in sorted(ids_for[(e, n, v)]):
                rec = stored.get(vid)
                if rec is None:
                    hits.append({"id": vid, "severity": "medium", "summary": None, "aliases": [], "cvss": None,
                                 "fixed": None, "url": f"https://osv.dev/vulnerability/{vid}"})
                    continue
                if rec.get("withdrawn"):
                    continue
                hits.append({"id": vid, "severity": rec["severity"], "summary": rec.get("summary"),
                             "aliases": rec.get("aliases") or [], "cvss": rec.get("cvss"),
                             "fixed": da.fixed_in(rec, e, raw, v), "url": rec.get("url")})
            if hits:
                out[(e, n, v)] = hits
        return out, info

    def check_package(self, ecosystem: str, name: str, version: str, online: bool | None = None) -> dict:
        if ecosystem not in OSV_ECOSYSTEMS:
            raise WebError(422, f"ecosystem must be one of {', '.join(OSV_ECOSYSTEMS)}")
        if da.version_key(ecosystem, version) is None:
            raise WebError(422, f"'{version}' is not a valid {ecosystem} version")
        online = bool(self._g("web_dep_online")) if online is None else online
        dep = {"ecosystem": ecosystem, "name": name, "version": version}
        res, info = self.lookup([dep], online)
        hits = res.get((ecosystem, da.norm_name(ecosystem, name), version), [])
        sev = max((h["severity"] for h in hits), key=lambda s: SEV[s]) if hits else None
        return {"package": dep, "vulnerable": bool(hits), "severity": sev, "advisories": hits, "lookup": info}

    # ---------------------------------------------------------------- offline database
    def vulndb_status(self) -> dict:
        rows = self.db.fetchall("SELECT p.ecosystem AS ecosystem, v.source AS source, COUNT(DISTINCT v.id) AS n "
                                "FROM web_vulns v JOIN web_vuln_pkgs p ON p.vuln_id=v.id GROUP BY 1, 2")
        by: dict[str, dict] = {}
        for r in rows:
            by.setdefault(r["ecosystem"], {"import": 0, "online": 0})[r["source"]] = r["n"]
        tot = self.db.fetchone("SELECT COUNT(*) AS n, SUM(source='import') AS imp FROM web_vulns")
        return {"records": tot["n"] or 0, "imported": tot["imp"] or 0, "by_ecosystem": by,
                "cached_versions": self.db.fetchone("SELECT COUNT(*) AS n FROM web_osv_cache")["n"],
                "last_import": self._state("vulndb_last_import"), "online_lookup": bool(self._g("web_dep_online")),
                "ecosystems": list(OSV_ECOSYSTEMS), "source": "OSV (osv.dev) - GitHub advisories, PyPA, npm, "
                                                            "Packagist, malicious packages"}

    def start_vulndb_import(self, cu, path: str | None = None, ecosystems: list[str] | None = None,
                            download: bool = False) -> dict:
        ecos = tuple(ecosystems or OSV_ECOSYSTEMS)
        bad = set(ecos) - set(OSV_ECOSYSTEMS)
        if bad:
            raise WebError(422, f"Unknown ecosystem(s): {', '.join(sorted(bad))}")
        if not download:
            if not path or not os.path.exists(path):
                raise WebError(404, "File not found - pick an OSV all.zip / .json file")
        elif self.data_dir is None:                                      # pragma: no cover
            raise WebError(503, "No data folder")
        job = Job("vulndb", cu, "download" if download else os.path.abspath(path),
                  {"ecosystems": list(ecos), "download": download}, key="vulndb")
        return self._spawn(job, (len(ecos) if download else 1) * 2, lambda j: self._run_import(j, path, ecos, download))

    def _run_import(self, job: Job, path: str | None, ecos: tuple[str, ...], download: bool) -> dict:
        sources: list[tuple[str, tuple[str, ...]]] = []
        step = 0
        if download:
            folder = self.data_dir / "osv"
            folder.mkdir(parents=True, exist_ok=True)
            tmpl = os.environ.get("CYBERHUB_OSV_DUMP_URL") or da.OSV_DUMP
            for eco in ecos:
                job.tick(f"downloading {eco} advisories", step, eco)
                dest = folder / f"{eco}.zip"
                part = folder / f"{eco}.zip.part"
                req = urllib.request.Request(tmpl.format(ecosystem=eco),
                                             headers={"User-Agent": "CyberHub-DependencyAudit/0.14"})
                try:
                    with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as fh:
                        while True:
                            job.check()
                            b = r.read(1 << 20)
                            if not b:
                                break
                            fh.write(b)
                except _Cancelled:
                    part.unlink(missing_ok=True)
                    raise
                except Exception as e:
                    part.unlink(missing_ok=True)
                    raise WebError(503, f"Could not download the {eco} database ({e})")
                os.replace(part, dest)
                sources.append((str(dest), (eco,)))
                step += 1
        else:
            sources.append((path, ecos))
        counts: dict[str, int] = {}
        total = skipped = 0
        for src, src_ecos in sources:
            job.tick("importing advisories", step, os.path.basename(src))
            batch: list[dict] = []
            try:
                for v in da.iter_osv_zip(src, src_ecos):
                    rec = da.compact(v, src_ecos)
                    if not rec["affected"]:
                        skipped += 1
                        continue
                    batch.append(rec)
                    for a in rec["affected"]:
                        counts[a["package"]["ecosystem"]] = counts.get(a["package"]["ecosystem"], 0) + 1
                    if len(batch) >= 500:
                        total += self._store_vulns(batch, "import")
                        batch = []
                        job.tick(current=f"{total:,} advisories")
            except (OSError, ValueError) as e:
                raise WebError(422, f"Could not read {os.path.basename(src)}: {e}")
            total += self._store_vulns(batch, "import")
            step += 1
        self.db.execute("DELETE FROM web_osv_cache")                     # answers may change with the new data
        st = {"ts": _now(), "records": total, "by_ecosystem": counts, "download": download}
        self._state("vulndb_last_import", st)
        self._event(job.user_id, "vulndb_imported", "info", f"Vulnerability database updated: {total:,} advisories",
                    ", ".join(f"{k}: {v:,}" for k, v in sorted(counts.items())))
        return {"kind": "vulndb", "imported": total, "skipped": skipped, "by_ecosystem": counts,
                "status": self.vulndb_status()}

    def clear_vulndb(self, source: str | None = None) -> dict:
        if source:
            n = self.db.execute("DELETE FROM web_vulns WHERE source=?", (source,)).rowcount
        else:
            n = self.db.execute("DELETE FROM web_vulns").rowcount
        self.db.execute("DELETE FROM web_osv_cache")
        return {"deleted": n}

    # ================================================================== dev servers (Part 10 + Part 9)
    def dev_servers(self, refresh: bool = False) -> dict:
        if self.network is None:
            return {"available": False, "reason": "Network monitor (Part 10) not loaded", "items": [], "counts": {}}
        if not refresh and self._dev_cache and time.monotonic() - self._dev_cache[0] < self.DEV_TTL:
            return self._dev_cache[1]
        try:
            lst = self.network.listening()["items"]
        except Exception as e:                                           # never let Part 10 break Part 14
            return {"available": False, "reason": f"Could not read listening ports ({e})", "items": [], "counts": {}}
        items = []
        for m in lst:
            if m.get("proto") != "tcp" or m.get("cyberhub") or not m.get("port"):
                continue
            prog = os.path.splitext(os.path.basename(m.get("process") or m.get("exe") or ""))[0].lower()
            port = m["port"]
            if port not in DEV_PORTS and prog not in DEV_PROGRAMS:
                continue
            if port not in DEV_PORTS and m.get("ephemeral"):
                continue
            fw = m.get("firewall") or {}
            verdict = fw.get("verdict") if m["exposure"] != "local" else "not_needed"
            reachable = verdict in ("open", "allowed")
            public = fw.get("profile") == "public"
            name = DEV_PORTS.get(port) or f"{prog or 'dev'} server"
            if m["exposure"] == "local":
                sev, why = "info", "Only this PC can open it - that's the safe way to run a dev server"
            elif port in DEBUG_PORTS:
                sev = "critical" if reachable else ("medium" if verdict == "blocked" else "high")
                why = (f"The {name} is listening on the network - anyone who reaches it can run code on this PC. "
                       f"{fw.get('reason') or ''}").strip()
            elif reachable:
                sev = "high" if public else "medium"
                why = (f"Other devices on the {'public' if public else 'local'} network can open it "
                       f"({fw.get('reason')}). Dev servers show debug pages and source maps and are not hardened.")
            elif verdict == "blocked":
                sev, why = "low", f"Listening on all networks, only the firewall keeps it closed ({fw.get('reason')})"
            else:
                sev, why = "medium", f"Listening on all networks and the firewall state is unknown ({fw.get('reason')})"
            fix = None
            if m["exposure"] != "local" and verdict in ("open", "allowed", "unknown"):
                fix = {"action": "block_port", "port": port, "protocol": "tcp",
                       "label": f"Block incoming connections to port {port} (Part 9 firewall)"}
            advice = {"vite": "Start it without --host (Vite listens on localhost by default)",
                      "django": "Use python manage.py runserver (127.0.0.1) instead of 0.0.0.0:8000"}
            hint = ("Bind it to 127.0.0.1 / localhost (e.g. Vite without --host, Django runserver without 0.0.0.0, "
                    "Flask host='127.0.0.1')" if m["exposure"] != "local" else None)
            if port == 5173:
                hint = advice["vite"] if hint else None
            items.append({"port": port, "name": name, "process": m.get("process"), "pid": m.get("pid"),
                          "exe": m.get("exe"), "addresses": m.get("addresses"), "exposure": m["exposure"],
                          "firewall": fw if m["exposure"] != "local" else None, "reachable": reachable,
                          "severity": sev, "reason": why, "hint": hint, "fix": fix,
                          "url": f"http://127.0.0.1:{port}/", "debugger": port in DEBUG_PORTS})
        items.sort(key=lambda x: (-SEV[x["severity"]], x["port"]))
        counts = {"total": len(items), "exposed": sum(1 for x in items if x["exposure"] != "local"),
                  "reachable": sum(1 for x in items if x["reachable"]),
                  "risky": sum(1 for x in items if SEV[x["severity"]] >= SEV["medium"])}
        out = {"available": True, "items": items, "counts": counts}
        self._dev_cache = (time.monotonic(), out)
        return out

    def block_dev_server(self, cu, port: int) -> dict:
        ds = self.dev_servers(refresh=True)
        item = next((x for x in ds["items"] if x["port"] == port), None)
        if item is None:
            raise WebError(404, f"No dev server is listening on port {port}")
        if not item["fix"]:
            raise WebError(409, "Nothing to block - it is local-only or already blocked by the firewall")
        if self.firewall is None:
            raise WebError(501, "The firewall module (Part 9) is not available")
        from .firewall import FirewallError
        try:
            res = self.firewall.block_port(str(port), cu.user["username"], "tcp", "in", None,
                                           f"Dev server exposed: {item['name']} (port {port})")
        except FirewallError as e:
            raise WebError(e.status, e.message)
        if self.network is not None and hasattr(self.network, "invalidate"):
            try:
                self.network.invalidate()
            except Exception:                                            # pragma: no cover
                pass
        self._dev_cache = None
        self._event(None, "dev_blocked", "info", f"Blocked incoming connections to the {item['name']} (port {port})",
                    f"by {cu.user['username']}", {"port": port, "block_id": res.get("id")})
        return {"server": item, "block": res}

    # ================================================================== after a scan: targets + alerts
    def _after(self, job: Job) -> None:
        if job.kind == "vulndb":
            return
        r = job.result or {}
        sc = r.get("score") or {}
        if job.target_id:
            cert = ((r.get("tls") or {}).get("cert") or {}).get("not_after") if job.kind == "site" else None
            if job.status == "done":
                self.db.execute("UPDATE web_targets SET last_scan_id=?, last_scan_at=?, last_score=?, last_grade=?, "
                                "last_error=NULL, cert_not_after=COALESCE(?, cert_not_after) WHERE id=?",
                                (job.id, job.finished_at, sc.get("score"), sc.get("grade"), cert, job.target_id))
            elif job.status == "failed":
                self.db.execute("UPDATE web_targets SET last_scan_at=?, last_error=? WHERE id=?",
                                (job.finished_at, job.error, job.target_id))
        label = r.get("target", {}).get("host") if job.kind == "site" else os.path.basename(job.target.rstrip(os.sep))
        label = label or job.target
        uid, tid = job.user_id, job.target_id
        if job.status == "failed":
            if job.trigger == "monitor":
                key = f"unreachable:{tid}:{datetime.now(timezone.utc):%Y-%m-%d}"
                if not self._state(key):
                    self._state(key, True)
                    self._event(uid, "unreachable", "medium", f"{label}: scan failed", job.error, {"scan_id": job.id},
                                tid)
            return
        if job.status != "done":
            return
        fs = r.get("findings") or []
        changes = r.get("changes")
        prev = r.get("previous")
        crit = [f for f in fs if f["severity"] == "critical"]
        new_ids = {c["id"] for c in (changes or {}).get("new", [])}
        new_bad = [f for f in fs if f["id"] in new_ids and SEV[f["severity"]] >= SEV["medium"]]
        if crit and (prev is None or any(f["id"] in new_ids for f in crit)):
            self._event(uid, "critical_found", "critical", f"{label}: {len(crit)} critical problem(s)",
                        "; ".join(f["title"] for f in crit[:4]), {"scan_id": job.id}, tid)
        elif new_bad and tid and self._g("web_alert_regressions"):
            worst = max((f["severity"] for f in new_bad), key=lambda s: SEV[s])
            kind = "new_vulnerabilities" if all(f["category"] == "deps" for f in new_bad) else "new_issues"
            self._event(uid, kind, worst, f"{label}: {len(new_bad)} new problem(s)",
                        "; ".join(f["title"] for f in new_bad[:4]), {"scan_id": job.id}, tid)
        if prev and tid and self._g("web_alert_regressions") and prev.get("grade") and sc.get("grade") and \
                wc.GRADES.index(next(x for x in wc.GRADES if x[1] == sc["grade"])) > \
                wc.GRADES.index(next(x for x in wc.GRADES if x[1] == prev["grade"])):
            self._event(uid, "grade_drop", "medium", f"{label}: grade dropped {prev['grade']} → {sc['grade']}",
                        None, {"scan_id": job.id, "from": prev["grade"], "to": sc["grade"]}, tid)
        cert = (r.get("tls") or {}).get("cert") if job.kind == "site" else None
        if cert and tid:
            dl = cert.get("days_left", 999)
            warn = int(self._g("web_cert_warn_days"))
            bucket = "expired" if dl < 0 else "7" if dl <= 7 else "warn" if dl <= warn else None
            key = f"cert:{tid}:{cert.get('not_after')}"
            if bucket and self._state(key) != bucket:
                self._state(key, bucket)
                sev = {"expired": "critical", "7": "high", "warn": "medium"}[bucket]
                self._event(uid, "cert_expiring", sev, f"{label}: certificate " +
                            ("has expired" if dl < 0 else f"expires in {dl} day(s)"), cert.get("not_after"),
                            {"days_left": dl, "scan_id": job.id}, tid)

    # ================================================================== background
    def watch_once(self) -> dict:
        out = {"started": [], "dev_alerts": 0, "cleaned": 0}
        if self._stopping.is_set():
            return out
        if self._g("web_monitor_enabled"):
            hours = int(self._g("web_monitor_interval_hours"))
            due_before = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
            rows = self.db.fetchall("SELECT t.*, u.username, u.role, u.display_name FROM web_targets t JOIN users u "
                                    "ON u.id=t.user_id WHERE t.monitor=1 AND (t.last_scan_at IS NULL OR "
                                    "t.last_scan_at < ?) ORDER BY t.last_scan_at", (due_before,))
            for t in rows:
                cu = _User({"id": t["user_id"], "username": t["username"], "role": t["role"]})
                try:
                    if t["kind"] == "site":
                        j = self.start_site_scan(cu, t["target"], trigger="monitor")
                    else:
                        j = self.start_project_scan(cu, t["target"], trigger="monitor")
                    out["started"].append(j["id"])
                except WebError as e:
                    if e.status == 429:
                        break
                    if e.status != 409:
                        self.db.execute("UPDATE web_targets SET last_scan_at=?, last_error=? WHERE id=?",
                                        (_now(), e.message, t["id"]))
        if self._g("web_dev_watch"):
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            for x in self.dev_servers(refresh=True).get("items", []):
                if SEV[x["severity"]] < SEV["medium"]:
                    continue
                key = f"dev:{x['port']}:{day}"
                if self._state(key):
                    continue
                self._state(key, True)
                self._event(None, "dev_exposed", x["severity"],
                            f"{x['name']} on port {x['port']} can be reached from the network", x["reason"],
                            {"port": x["port"], "process": x["process"], "fix": x["fix"]})
                out["dev_alerts"] += 1
        out["cleaned"] = self.cleanup()
        return out

    def cleanup(self) -> int:
        days = int(self._g("web_history_days"))
        cut = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        n = self.db.execute("DELETE FROM web_scans WHERE created_at < ? AND status!='running' AND id NOT IN "
                            "(SELECT last_scan_id FROM web_targets WHERE last_scan_id IS NOT NULL)", (cut,)).rowcount
        n += self.db.execute("DELETE FROM web_events WHERE ts < ?", (cut,)).rowcount
        old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
        self.db.execute("DELETE FROM web_osv_cache WHERE fetched_at < ?", (old,))
        self.db.execute("DELETE FROM web_state WHERE (key LIKE 'dev:%' OR key LIKE 'unreachable:%') AND key < ?",
                        ("dev:" + old[:10],))
        return n

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
        rows = self.db.fetchall(f"SELECT * FROM web_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        for r in rows:
            r["data"] = json.loads(r["data"]) if r.get("data") else None
            r["acknowledged"] = bool(r["acknowledged"])
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM web_events")["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM web_events WHERE (user_id IS ? OR user_id IS NULL) "
                                 "AND acknowledged=0", (cu.user["id"],))["n"]
        return {"items": rows, "last_id": last, "unacknowledged": unack}

    def acknowledge(self, cu, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE web_events SET acknowledged=1 WHERE id IN ({q}) AND "
                                   "(user_id IS ? OR user_id IS NULL)", tuple(ids) + (cu.user["id"],)).rowcount
        return self.db.execute("UPDATE web_events SET acknowledged=1 WHERE user_id IS ? OR user_id IS NULL",
                               (cu.user["id"],)).rowcount

    def clear_events(self, cu) -> int:
        return self.db.execute("DELETE FROM web_events WHERE user_id IS ?", (cu.user["id"],)).rowcount

    # ================================================================== dashboard
    def _latest(self, uid: int) -> list[dict]:
        rows = self.db.fetchall("SELECT t.id, t.kind, t.target, t.label, t.monitor, t.cert_not_after, s.score, s.grade, "
                                "s.critical, s.high, s.medium, s.low, s.result, s.finished_at FROM web_targets t "
                                "LEFT JOIN web_scans s ON s.id=t.last_scan_id WHERE t.user_id=?", (uid,))
        return rows

    def health(self, user_id: int) -> dict:
        """For Part 18: one number for 'my websites and code' + the facts behind it."""
        rows = self._latest(user_id)
        scored = [r for r in rows if r["score"] is not None]
        by = {k: sum(r[k] or 0 for r in scored) for k in ("critical", "high", "medium", "low")}
        certs = []
        vulnerable = 0
        for r in scored:
            res = json.loads(r["result"]) if r.get("result") else {}
            if r["kind"] == "project":
                vulnerable += (res.get("dependencies") or {}).get("vulnerable", 0)
            na = _parse_ts(r.get("cert_not_after"))
            if na:
                dl = int((na - datetime.now(timezone.utc)).total_seconds() // 86400)
                if dl <= int(self._g("web_cert_warn_days")):
                    certs.append({"target": r["target"], "days_left": dl})
        score = round(sum(r["score"] for r in scored) / len(scored)) if scored else None
        worst = min(scored, key=lambda r: r["score"]) if scored else None
        ds = self.dev_servers()
        dev_risky = ds.get("counts", {}).get("risky", 0) if ds.get("available") else 0
        if score is not None and dev_risky:
            score = min(score, 84)
        grade = next(g for lim, g in wc.GRADES if score >= lim) if score is not None else None
        return {"score": score, "grade": grade, "sites": sum(1 for r in rows if r["kind"] == "site"),
                "projects": sum(1 for r in rows if r["kind"] == "project"), "scanned": len(scored),
                "monitored": sum(1 for r in rows if r["monitor"]), "open": by,
                "worst": {"target": worst["target"], "grade": worst["grade"], "score": worst["score"]} if worst else None,
                "certs_expiring": sorted(certs, key=lambda c: c["days_left"]), "vulnerable_packages": vulnerable,
                "dev_servers_exposed": dev_risky}

    def summary(self, cu, days: int = 30) -> dict:
        uid = cu.user["id"]
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        per_day = self.db.fetchall("SELECT substr(created_at,1,10) AS day, SUM(kind='site') AS sites, "
                                   "SUM(kind='project') AS projects, ROUND(AVG(score)) AS avg_score, "
                                   "SUM(critical) AS critical, SUM(high) AS high FROM web_scans WHERE user_id=? AND "
                                   "status='done' AND kind IN ('site','project') AND created_at >= ? GROUP BY 1 "
                                   "ORDER BY 1", (uid, since))
        rows = self._latest(uid)
        cats: dict[str, dict] = {}
        grades: dict[str, int] = {}
        pkgs: dict[str, dict] = {}
        techs: dict[str, int] = {}
        for r in rows:
            if r["grade"]:
                grades[r["grade"]] = grades.get(r["grade"], 0) + 1
            res = json.loads(r["result"]) if r.get("result") else {}
            for f in res.get("findings", []):
                c = cats.setdefault(f["category"], {"category": f["category"], "label": wc.CATEGORIES.get(
                    f["category"], f["category"]), **{s: 0 for s in SEVERITIES}})
                c[f["severity"]] += 1
            for p in res.get("packages", []):
                k = f"{p['ecosystem']}:{p['name']}"
                x = pkgs.setdefault(k, {"ecosystem": p["ecosystem"], "name": p["name"], "projects": 0,
                                        "severity": p["severity"], "fixed": p.get("fixed")})
                x["projects"] += 1
                x["severity"] = wc.sev_max(x["severity"], p["severity"])
            for t in res.get("technologies", []):
                techs[t["name"]] = techs.get(t["name"], 0) + 1
        history = {}
        for r in rows:
            pts = self.db.fetchall("SELECT substr(created_at,1,16) AS ts, score, grade FROM web_scans WHERE target_id=? "
                                   "AND status='done' ORDER BY created_at DESC LIMIT 20", (r["id"],))
            history[r["label"] or r["target"]] = list(reversed(pts))
        certs = []
        for r in rows:
            na = _parse_ts(r.get("cert_not_after"))
            if na:
                certs.append({"target": r["label"] or r["target"], "not_after": r["cert_not_after"],
                              "days_left": int((na - datetime.now(timezone.utc)).total_seconds() // 86400)})
        return {"per_day": per_day, "findings_by_category": sorted(cats.values(), key=lambda c: c["category"]),
                "grades": grades, "score_history": history, "certificates": sorted(certs, key=lambda c: c["days_left"]),
                "top_vulnerable_packages": sorted(pkgs.values(), key=lambda p: (-SEV[p["severity"]], -p["projects"],
                                                                                p["name"]))[:15],
                "technologies": sorted(({"name": k, "sites": v} for k, v in techs.items()),
                                       key=lambda x: -x["sites"])[:20],
                "health": self.health(uid)}

    def status(self, cu) -> dict:
        with self._lock:
            running = [j.public() for j in self._jobs.values() if j.status == "running" and self._can(cu, j.user_id)]
        g = self._g
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM web_events WHERE (user_id IS ? OR user_id IS NULL) AND "
                                 "acknowledged=0", (cu.user["id"],))["n"]
        ds = self.dev_servers()
        return {
            "features": {"website_scan": True, "tls": True, "headers": True, "exposed_files": True, "ports": True,
                         "technology": True, "dependencies": True, "secrets": True, "monitoring": True,
                         "dev_servers": bool(ds.get("available")), "firewall_fix": self.firewall is not None},
            "checks": {c: wc.CATEGORIES.get(c, c) for c in SITE_CHECKS},
            "active_checks": sorted(ACTIVE_CHECKS),
            "settings": {k: g(k) for k in ("web_scan_timeout_seconds", "web_cert_warn_days", "web_check_exposed_files",
                                           "web_monitor_enabled", "web_monitor_interval_hours",
                                           "web_alert_regressions", "web_dev_watch", "web_dep_online",
                                           "web_osv_cache_days", "web_secret_scan", "web_history_days")},
            "health": self.health(cu.user["id"]), "jobs_running": running,
            "targets": len(self.targets(cu)), "vulndb": self.vulndb_status(),
            "dev_servers": ds.get("counts", {}), "unacknowledged": unack,
            "ecosystems": list(OSV_ECOSYSTEMS), "ports_checked": len(wp.PORTS),
            "tables_reviewed": wc.TABLES_REVIEWED,
        }


async def web_loop(svc: WebScannerService, settings, first_delay: float = 90, every: float = 600) -> None:
    """Every 10 minutes: start due monitor scans, check dev-server exposure, prune history."""
    import asyncio
    await asyncio.sleep(first_delay)
    while True:
        try:
            await asyncio.to_thread(svc.watch_once)
        except Exception as e:                                           # pragma: no cover
            log.warning("Web scanner watch failed: %s", e)
        await asyncio.sleep(every)
