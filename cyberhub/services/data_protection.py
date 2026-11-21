"""
Cyber Hub Backend - Data Protection (Part 13)
Developed by Syed Muhammad Tayyab

One service behind /api/data that runs four tools as background jobs with
live progress, cancel and a history:

* File & folder encryption (.chx, see file_crypto): password mode (portable,
  scrypt + AES-256-GCM) or device mode (no password, tied to this Windows user
  through Part 6's DPAPI-sealed vault key). Every file is encrypted to a temp
  name, decrypted again and compared (SHA-256) BEFORE the original is shredded /
  deleted - a crash or a full disk can never leave you with neither copy.
  The password can be saved into the user's Part 12 password vault.
* Decryption back to the original name (stored encrypted inside the file),
  conflict = rename / overwrite / skip, decrypted files scanned by Part 5.
* Secure shredder (see shredder): zero / random / DoD 3-pass / 3x random,
  read-back verify, name scrubbing, links never followed, SSD honesty.
* Privacy cleaner (see privacy_cleaner): analysis, then clean selected categories.
* Sensitive-file finder (see sensitive_finder): masked findings with
  encrypt / shred / ignore actions and a 0-100 data-exposure score for Part 18.

Safety rails shared by every job:
* Refuses Cyber Hub's own program / data folders, operating-system and
  program folders, whole drives and your home folder itself.
* Two jobs can never work on overlapping paths (409), at most 3 run at once.
* Programs running from a file stop it from being encrypted / shredded.
* Part 7 real-time protection is told about our own writes, so encrypting a
  big folder doesn't raise the ransomware-style burst alert and encrypted
  output isn't scanned (decrypted files still are).
* Jobs interrupted by a crash / shutdown are marked interrupted at the next
  start and their temp files removed.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import psutil

from ..database import Database
from ..logger import get_logger
from . import file_crypto as fc
from . import sensitive_finder as sf
from . import shredder as sh
from .password_tools import normalize, strength
from .platform_tools import IS_WINDOWS
from .privacy_cleaner import PrivacyCleaner
from .quarantine import system_dirs

log = get_logger("dataprotect")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
KINDS = ("encrypt", "decrypt", "shred", "clean", "cleaner_analyze", "finder")
MAX_RUNNING = 3
MAX_TARGETS = 100
MAX_FILES = 200_000
RESULT_ITEMS = 500
OWN_TEMP = (".chpart", ".chdec", ".shred")
FINDING_STATES = ("open", "ignored", "encrypted", "shredded", "resolved")
GRADES = [(90, "Excellent"), (75, "Good"), (50, "Needs attention"), (0, "At risk")]
POINTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


def _inside(path_n: str, folder_n: str) -> bool:
    return path_n == folder_n or path_n.startswith(folder_n.rstrip(os.sep) + os.sep)


def _overlap(a: str, b: str) -> bool:
    return _inside(a, b) or _inside(b, a)


def _fmt(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or u == "TB":
            return f"{f:.0f} {u}" if u == "B" else f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


class DPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class _Cancelled(Exception):
    pass


class Job:
    def __init__(self, kind: str, cu, claims: list[str], params: dict):
        self.id = secrets.token_hex(8)
        self.kind = kind
        self.user_id = cu.user["id"] if cu else None
        self.username = cu.user["username"] if cu else "system"
        self.claims = claims
        self.params = params
        self.status = "running"
        self.created_at = _now()
        self.finished_at: str | None = None
        self.progress = {"files_done": 0, "files_total": 0, "bytes_done": 0, "bytes_total": 0, "current": None,
                         "phase": "preparing", "percent": 0}
        self.result: dict = {}
        self.error: str | None = None
        self.cancel = threading.Event()
        self.thread: threading.Thread | None = None
        self.temp: str | None = None

    def check(self) -> None:
        if self.cancel.is_set():
            raise _Cancelled()

    def tick(self, files: int | None = None, bytes_done: int | None = None, current: str | None = None,
             phase: str | None = None) -> None:
        p = self.progress
        if files is not None:
            p["files_done"] = files
        if bytes_done is not None:
            p["bytes_done"] = bytes_done
        if current is not None:
            p["current"] = os.path.basename(current) or current
        if phase:
            p["phase"] = phase
        if p["bytes_total"]:
            p["percent"] = min(99, int(p["bytes_done"] * 100 / p["bytes_total"]))
        elif p["files_total"]:
            p["percent"] = min(99, int(p["files_done"] * 100 / p["files_total"]))
        self.check()

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "username": self.username,
                "created_at": self.created_at, "finished_at": self.finished_at, "progress": dict(self.progress),
                "result": self.result, "error": self.error}


# ====================================================================== service
class DataProtectionService:
    def __init__(self, db: Database, settings, activity, vault=None, data_dir: Path | None = None, processes=None,
                 scanner=None, realtime=None, passwords=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.vault, self.processes, self.scanner = vault, processes, scanner
        self.realtime, self.passwords = realtime, passwords
        self.data_dir = norm(str(data_dir)) if data_dir else None
        self.app_dir = norm(str(Path(__file__).resolve().parents[2]))
        self.cleaner = PrivacyCleaner(exclude=[x for x in (self.data_dir, self.app_dir) if x])
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._recover()

    # ------------------------------------------------------------------ start-up recovery
    def _recover(self) -> None:
        rows = self.db.fetchall("SELECT id, temp FROM dp_jobs WHERE status IN ('running','queued')")
        for r in rows:
            t = r.get("temp")
            if t and t.endswith(OWN_TEMP) and os.path.isfile(t):
                try:
                    os.unlink(t)
                except OSError:
                    pass
            self.db.execute("UPDATE dp_jobs SET status='interrupted', finished_at=?, error=? WHERE id=?",
                            (_now(), "Cyber Hub stopped while this job was running - files already finished are "
                                     "complete, the one in progress was left untouched", r["id"]))
        if rows:
            log.info("Marked %d interrupted data-protection job(s)", len(rows))

    # ------------------------------------------------------------------ events / stats
    def _event(self, uid: int | None, kind: str, severity: str, title: str, detail: str | None = None,
               data: dict | None = None, category: str = "data") -> None:
        self.db.execute("INSERT INTO dp_events(user_id, kind, severity, title, detail, data) VALUES (?,?,?,?,?,?)",
                        (uid, kind, severity, title, detail, json.dumps(data) if data else None))
        try:
            self.activity.record(category, title, detail, severity="info" if severity == "info" else severity,
                                 source="dataprotect")
        except ValueError:                                              # pragma: no cover
            pass

    def _bump(self, **inc: int) -> None:
        cols = [k for k, v in inc.items() if v]
        if not cols:
            return
        sets = ", ".join(f"{k}={k}+?" for k in cols)
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO dp_daily(day) VALUES (?)", (_day(),))
            c.execute(f"UPDATE dp_daily SET {sets} WHERE day=?", tuple(int(inc[k]) for k in cols) + (_day(),))

    def _state(self, key: str, value: Any = None, write: bool = False) -> Any:
        if write:
            self.db.execute("INSERT INTO dp_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                            "value=excluded.value", (key, json.dumps(value)))
            return value
        r = self.db.fetchone("SELECT value FROM dp_state WHERE key=?", (key,))
        return json.loads(r["value"]) if r else None

    # ------------------------------------------------------------------ guards
    def _forbidden_roots(self) -> list[str]:
        out = list(system_dirs())
        if IS_WINDOWS:                                                  # pragma: no cover - Windows only
            env = os.environ
            for k, d in (("SystemRoot", r"C:\Windows"), ("ProgramFiles", r"C:\Program Files"),
                         ("ProgramFiles(x86)", r"C:\Program Files (x86)"), ("ProgramData", r"C:\ProgramData")):
                out.append(norm(env.get(k, d)))
        else:
            out += [norm(d) for d in ("/usr", "/proc", "/sys", "/dev", "/run", "/var/lib", "/opt", "/snap", "/srv")]
        return out

    def check_path(self, path: str, op: str, must_exist: bool = True) -> str:
        """Raise DPError unless path is a sensible target for op (encrypt | decrypt | shred | find | dest)."""
        if not isinstance(path, str) or not path.strip() or "\x00" in path:
            raise DPError(422, "Give a file or folder path")
        p = os.path.abspath(os.path.expanduser(path.strip()))
        n = norm(p)
        if must_exist and not os.path.lexists(p):
            raise DPError(404, f"Not found: {p}")
        if os.path.dirname(p) == p:
            raise DPError(403, "That is a whole drive - pick the folders you mean")
        home = norm(str(Path.home()))
        for own, what in ((self.data_dir, "Cyber Hub's own data folder"), (self.app_dir, "the Cyber Hub program")):
            if own and (_inside(n, own) or (op != "find" and _inside(own, n))):
                raise DPError(403, f"That path holds {what}")
        if op in ("find",):
            return p
        if n == home or (_inside(home, n) and n != home):
            raise DPError(403, "That is your whole user folder (or contains it) - pick the folders you mean")
        if any(_inside(n, d) or _inside(d, n) for d in self._forbidden_roots()):
            raise DPError(403, "That is an operating-system or program folder - changing it could stop Windows or "
                               "your programs from working")
        return p

    @staticmethod
    def _running_exes() -> set[str]:
        out = set()
        for p in psutil.process_iter(["exe"]):
            exe = p.info.get("exe")
            if exe:
                out.add(norm(exe))
        return out

    def _claim(self, kind: str, cu, claims: list[str], params: dict) -> Job:
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
            if len(running) >= MAX_RUNNING:
                raise DPError(429, f"{MAX_RUNNING} data-protection jobs are already running - wait for one to finish")
            for j in running:
                for a in claims:
                    for b in j.claims:
                        if _overlap(a, b):
                            raise DPError(409, f"Another job ({j.kind}) is already working on {os.path.basename(b) or b}")
            job = Job(kind, cu, claims, params)
            self._jobs[job.id] = job
            if len(self._jobs) > 100:
                for jid in [k for k, v in self._jobs.items() if v.status != "running"][:len(self._jobs) - 100]:
                    del self._jobs[jid]
        self.db.execute("INSERT INTO dp_jobs(id, kind, user_id, username, status, created_at, params) "
                        "VALUES (?,?,?,?,?,?,?)", (job.id, kind, job.user_id, job.username, "running", job.created_at,
                                                   json.dumps(params)))
        return job

    def _run(self, job: Job, fn: Callable[[Job], dict]) -> dict:
        def target():
            try:
                job.result = fn(job)
                job.status = "cancelled" if job.cancel.is_set() else "done"
            except _Cancelled:
                job.status = "cancelled"
            except DPError as e:
                job.status, job.error = "failed", e.message
            except Exception as e:                                       # pragma: no cover - logged, never silent
                log.exception("Data-protection job %s failed", job.kind)
                job.status, job.error = "failed", f"{type(e).__name__}: {e}"[:300]
            finally:
                if job.temp and os.path.isfile(job.temp):
                    try:
                        os.unlink(job.temp)
                    except OSError:
                        pass
                job.temp = None
                job.finished_at = _now()
                if job.status == "done":
                    job.progress["percent"] = 100
                job.progress["phase"] = job.status
                self.db.execute("UPDATE dp_jobs SET status=?, finished_at=?, progress=?, result=?, error=?, temp=NULL "
                                "WHERE id=?", (job.status, job.finished_at, json.dumps(job.progress),
                                               json.dumps(job.result)[:2_000_000], job.error, job.id))
                if job.status == "failed":
                    self._event(job.user_id, "job_failed", "medium", f"{job.kind.replace('_', ' ').title()} failed",
                                job.error, {"job_id": job.id})
        job.thread = threading.Thread(target=target, name=f"dp-{job.kind}-{job.id}", daemon=True)
        job.thread.start()
        return job.public()

    def _set_temp(self, job: Job, path: str | None) -> None:
        job.temp = path
        self.db.execute("UPDATE dp_jobs SET temp=? WHERE id=?", (path, job.id))

    def _rt(self, path: str, scan: bool = False) -> None:
        """Tell Part 7 real-time protection that this write is ours."""
        if self.realtime is not None and hasattr(self.realtime, "suppress"):
            try:
                self.realtime.suppress(path, scan=scan)
            except Exception:                                            # pragma: no cover
                pass

    # ------------------------------------------------------------------ collecting files
    @staticmethod
    def _collect(paths: list[str], want: Callable[[str], bool], job: Job | None = None) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        seen: set[str] = set()
        for p in paths:
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if sh.is_link(p, st):
                continue
            if stat.S_ISREG(st.st_mode):
                if norm(p) not in seen and want(p):
                    seen.add(norm(p))
                    out.append((p, st.st_size))
                continue
            for kind, fp, size in sh.iter_tree(p):
                if kind == "file" and norm(fp) not in seen and want(fp):
                    seen.add(norm(fp))
                    out.append((fp, size))
                    if len(out) >= MAX_FILES:
                        raise DPError(413, f"More than {MAX_FILES:,} files - pick smaller folders")
                if job is not None and len(out) % 500 == 0:
                    job.check()
        return out

    def jobs_for(self, cu, limit: int = 30, kind: str | None = None) -> dict:
        uid = cu.user["id"]
        admin = cu.user["role"] == "admin"
        with self._lock:
            live = [j.public() for j in self._jobs.values()
                    if j.status == "running" and (admin or j.user_id == uid)]
        where, params = ["status NOT IN ('running')"], []
        if not admin:
            where.append("user_id=?"); params.append(uid)
        if kind:
            where.append("kind=?"); params.append(kind)
        rows = self.db.fetchall(f"SELECT * FROM dp_jobs WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT ?",
                                tuple(params) + (limit,))
        hist = [self._row_public(r) for r in rows]
        return {"running": live, "history": hist}

    @staticmethod
    def _row_public(r: dict) -> dict:
        return {"id": r["id"], "kind": r["kind"], "status": r["status"], "username": r["username"],
                "created_at": r["created_at"], "finished_at": r["finished_at"],
                "progress": json.loads(r["progress"]) if r.get("progress") else None,
                "result": json.loads(r["result"]) if r.get("result") else None, "error": r["error"]}

    def job(self, cu, job_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if j and (cu.user["role"] == "admin" or j.user_id == cu.user["id"]):
            return j.public()
        r = self.db.fetchone("SELECT * FROM dp_jobs WHERE id=?", (job_id,))
        if not r or (cu.user["role"] != "admin" and r["user_id"] != cu.user["id"]):
            raise DPError(404, "Job not found")
        return self._row_public(r)

    def cancel(self, cu, job_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(job_id)
        if not j or (cu.user["role"] != "admin" and j.user_id != cu.user["id"]):
            raise DPError(404, "Job not found")
        if j.status != "running":
            raise DPError(409, f"Job is already {j.status}")
        j.cancel.set()
        return {"id": j.id, "cancelling": True,
                "note": "Stops after the current file - files already finished stay finished"}

    def wait(self, job_id: str, timeout: float = 30) -> dict:
        """Tests / internal callers: block until a job ends."""
        with self._lock:
            j = self._jobs.get(job_id)
        if j and j.thread:
            j.thread.join(timeout)
        return j.public() if j else {}

    # ================================================================== keys
    def _device_keys(self) -> fc.KeySource:
        if self.vault is None or not getattr(self.vault, "available", False):
            raise DPError(503, "This PC's device key is unavailable - use password mode")
        return fc.KeySource(fc.MODE_DEVICE, device_key=self.vault.derive_subkey(fc.DEVICE_LABEL))

    @staticmethod
    def check_file_password(password: str, allow_weak: bool) -> dict:
        pw = normalize(password or "")
        if len(pw) < 8:
            raise DPError(422, "Use a password of at least 8 characters")
        if len(pw) > 1024:
            raise DPError(422, "Password is too long")
        s = strength(pw)
        if s["score"] < 3 and not allow_weak:
            raise DPError(422, f"This password is {s['label'].lower()} - anyone with the file could guess it. "
                               "Use a longer one (a passphrase works well) or send allow_weak=true")
        return s

    # ================================================================== encrypt
    def start_encrypt(self, cu, paths: list[str], mode: str = "password", password: str | None = None,
                      delete_original: str | None = None, hide_names: bool | None = None,
                      save_to_vault: bool = False, allow_weak: bool = False) -> dict:
        if not paths or len(paths) > MAX_TARGETS:
            raise DPError(422, f"Give 1-{MAX_TARGETS} files or folders")
        if mode not in ("password", "device"):
            raise DPError(422, "mode must be password or device")
        delete_original = delete_original or self.settings.get("dp_encrypt_original")
        if delete_original not in ("shred", "delete", "keep"):
            raise DPError(422, "delete_original must be shred, delete or keep")
        hide = self.settings.get("dp_encrypt_hide_names") if hide_names is None else bool(hide_names)
        targets = [self.check_path(p, "encrypt") for p in paths]
        if mode == "password":
            if not password:
                raise DPError(422, "Enter a password for the encrypted file(s)")
            self.check_file_password(password, allow_weak)
            keys = fc.KeySource(fc.MODE_PASSWORD, password=normalize(password))
        else:
            if save_to_vault:
                raise DPError(422, "Device mode has no password to save")
            keys = self._device_keys()
        if save_to_vault:
            self._save_password(cu, targets, password)                   # 404 / 423 before any file is touched
        params = {"mode": mode, "delete_original": delete_original, "hide_names": hide,
                  "targets": targets[:20], "target_count": len(targets)}
        job = self._claim("encrypt", cu, [norm(t) for t in targets], params)
        return self._run(job, lambda j: self._encrypt_job(j, targets, keys, delete_original, hide))

    def _save_password(self, cu, targets: list[str], password: str | None) -> None:
        if self.passwords is None:
            raise DPError(503, "Password vault is not available")
        from .password_vault import PVError
        names = ", ".join(os.path.basename(t.rstrip("/\\")) or t for t in targets[:5])
        more = f" and {len(targets) - 5} more" if len(targets) > 5 else ""
        try:
            self.passwords.create_item(cu, "login", {
                "title": f"Encrypted files - {names[:150]}{more}"[:200],
                "password": password,
                "notes": f"Password for files encrypted with Cyber Hub (.chx) on {_day()}: {names}{more}"[:9000],
                "folder": "Encrypted files", "tags": ["cyberhub", "file-encryption"]})
        except PVError as e:
            raise DPError(e.status, f"Couldn't save the password to your vault: {e.message}")

    @staticmethod
    def _free(path: str, suffix: str = "") -> str:
        if not os.path.lexists(path):
            return path
        base, ext = os.path.splitext(path[:-len(suffix)] if suffix and path.endswith(suffix) else path)
        i = 2
        while True:
            cand = f"{base} ({i}){ext}{suffix}"
            if not os.path.lexists(cand):
                return cand
            i += 1

    def _encrypt_job(self, job: Job, targets: list[str], keys: fc.KeySource, delete_original: str,
                     hide: bool) -> dict:
        touched: set = set()
        try:
            files = self._collect(targets, lambda p: not p.lower().endswith((fc.EXT,) + OWN_TEMP), job)
            if not files:
                raise DPError(404, "Nothing to encrypt - the files are already encrypted (.chx) or the folder is empty")
            job.progress.update(files_total=len(files), bytes_total=sum(s for _, s in files) * 2, phase="encrypting")
            running = self._running_exes()
            items, done_bytes = [], 0
            counts = {"encrypted": 0, "skipped": 0, "failed": 0, "originals_kept": 0}
            for i, (src, size) in enumerate(files):
                job.tick(files=i, bytes_done=done_bytes, current=src)
                r = self._encrypt_one(job, src, size, keys, delete_original, hide, running, done_bytes)
                done_bytes += size * 2
                counts[r["status"] if r["status"] in counts else "failed"] += 1
                if r.get("original") == "kept" and delete_original != "keep":
                    counts["originals_kept"] += 1
                if r["status"] == "encrypted":
                    self._close_findings(src, "encrypted", "Encrypted with Cyber Hub", touched)
                if len(items) < RESULT_ITEMS:
                    items.append(r)
            job.tick(files=len(files), bytes_done=done_bytes)
        finally:
            keys.wipe()
            for uid in touched:
                self._record_score(uid)
        if counts["encrypted"]:
            self._bump(encrypted_files=counts["encrypted"])
            self._event(job.user_id, "encrypted", "info", f"Encrypted {counts['encrypted']} file(s)",
                        f"{job.params['mode']} mode, originals: {delete_original}"
                        + (f", {counts['failed']} failed" if counts["failed"] else ""), {"job_id": job.id})
        return {"summary": counts, "items": items, "files": len(files)}

    def _encrypt_one(self, job: Job, src: str, size: int, keys: fc.KeySource, delete_original: str, hide: bool,
                     running: set[str], base: int) -> dict:
        r: dict[str, Any] = {"path": src, "status": "failed", "output": None, "original": None, "error": None}
        if norm(src) in running:
            return r | {"status": "skipped", "error": "A program is running from this file"}
        if fc.is_chx(src):
            return r | {"status": "skipped", "error": "Already encrypted"}
        folder = os.path.dirname(src)
        out = os.path.join(folder, secrets.token_hex(8) + fc.EXT) if hide else src + fc.EXT
        out = self._free(out, fc.EXT)
        tmp = out + ".chpart"
        for p in (src, out, tmp):
            self._rt(p)
        self._set_temp(job, tmp)
        try:
            enc = fc.encrypt_file(src, tmp, keys, lambda n: job.tick(bytes_done=base + n))
            ver = fc.decrypt_stream(tmp, keys, None, lambda n: job.tick(bytes_done=base + size + n))
            if ver["sha256"] != enc["sha256"]:
                raise fc.CryptoError("Verification failed - the encrypted copy doesn't match")
            os.replace(tmp, out)
            self._set_temp(job, None)
        except _Cancelled:
            raise
        except PermissionError:
            return r | {"error": "Access denied or the file is open in another program"}
        except (fc.CryptoError, OSError) as e:
            return r | {"error": str(e)[:200]}
        finally:
            if os.path.isfile(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        r.update(status="encrypted", output=out, sha256=enc["sha256"], size=size)
        if delete_original == "keep":
            r["original"] = "kept"
        else:
            try:
                if delete_original == "shred":
                    sh.shred_file(src, "random", verify=False, allow_hardlinks=False)
                else:
                    os.unlink(src)
                r["original"] = "shredded" if delete_original == "shred" else "deleted"
            except sh.ShredError as e:
                r.update(original="kept", error=f"Encrypted, but the original stayed: {e.message}")
            except OSError as e:
                r.update(original="kept", error=f"Encrypted, but the original stayed: {e}")
        self.db.execute("INSERT INTO dp_encrypted(user_id, path, source_path, mode, size, hidden_name, job_id) "
                        "VALUES (?,?,?,?,?,?,?)", (job.user_id, out, None if hide else src,
                                                   fc.MODES[keys.mode], size, 1 if hide else 0, job.id))
        return r

    # ================================================================== decrypt
    def start_decrypt(self, cu, paths: list[str], password: str | None = None, destination: str | None = None,
                      conflict: str = "rename", delete_encrypted: bool = True) -> dict:
        if not paths or len(paths) > MAX_TARGETS:
            raise DPError(422, f"Give 1-{MAX_TARGETS} files or folders")
        if conflict not in ("rename", "overwrite", "skip"):
            raise DPError(422, "conflict must be rename, overwrite or skip")
        targets = [self.check_path(p, "decrypt") for p in paths]
        dest = None
        if destination:
            dest = self.check_path(destination, "dest")
            if not os.path.isdir(dest):
                raise DPError(422, "destination must be an existing folder")
        pw_keys = fc.KeySource(fc.MODE_PASSWORD, password=normalize(password)) if password else None
        try:
            dev_keys = self._device_keys()
        except DPError:
            dev_keys = None
        claims = [norm(t) for t in targets] + ([norm(dest)] if dest else [])
        job = self._claim("decrypt", cu, claims, {"targets": targets[:20], "target_count": len(targets),
                                                  "destination": dest, "conflict": conflict,
                                                  "delete_encrypted": delete_encrypted})
        return self._run(job, lambda j: self._decrypt_job(j, targets, pw_keys, dev_keys, dest, conflict,
                                                          delete_encrypted))

    def _decrypt_job(self, job: Job, targets: list[str], pw_keys, dev_keys, dest: str | None, conflict: str,
                     delete_encrypted: bool) -> dict:
        try:
            single = len(targets) == 1 and os.path.isfile(targets[0])
            files = self._collect(targets, (lambda p: True) if single else
                                  (lambda p: p.lower().endswith(fc.EXT) and fc.is_chx(p)), job)
            job.progress.update(files_total=len(files), bytes_total=sum(s for _, s in files), phase="decrypting")
            counts = {"decrypted": 0, "skipped": 0, "wrong_password": 0, "failed": 0, "threats": 0}
            items, done = [], 0
            scan = bool(self.settings.get("dp_decrypt_scan")) and self.scanner is not None
            for i, (path, size) in enumerate(files):
                job.tick(files=i, bytes_done=done, current=path)
                r = self._decrypt_one(job, path, pw_keys, dev_keys, dest, conflict, delete_encrypted, done, scan)
                done += size
                counts[r["status"]] = counts.get(r["status"], 0) + 1
                if r.get("threats"):
                    counts["threats"] += 1
                if len(items) < RESULT_ITEMS:
                    items.append(r)
            job.tick(files=len(files), bytes_done=done)
        finally:
            for k in (pw_keys, dev_keys):
                if k:
                    k.wipe()
        if counts["decrypted"]:
            self._bump(decrypted_files=counts["decrypted"])
            self._event(job.user_id, "decrypted", "info", f"Decrypted {counts['decrypted']} file(s)",
                        None, {"job_id": job.id})
        if counts["wrong_password"] and not counts["decrypted"]:
            self._event(job.user_id, "decrypt_failed", "low", "Wrong password for encrypted file(s)",
                        f"{counts['wrong_password']} file(s) could not be opened", {"job_id": job.id})
        if counts["threats"]:
            self._event(job.user_id, "decrypted_threat", "high", "A decrypted file is a threat",
                        "Quarantine it from the scan results / Protection history", {"job_id": job.id})
        if not files:
            raise DPError(404, "No Cyber Hub encrypted files (.chx) found there")
        return {"summary": counts, "items": items, "files": len(files)}

    def _decrypt_one(self, job: Job, path: str, pw_keys, dev_keys, dest: str | None, conflict: str,
                     delete_encrypted: bool, base: int, scan: bool) -> dict:
        r: dict[str, Any] = {"path": path, "status": "failed", "output": None, "error": None}
        try:
            with open(path, "rb") as f:
                h = fc.read_header(f)
        except fc.CryptoError as e:
            return r | {"status": "skipped", "error": str(e)}
        except OSError as e:
            return r | {"error": str(e)[:200]}
        keys = dev_keys if h["mode"] == fc.MODE_DEVICE else pw_keys
        if keys is None:
            return r | {"status": "wrong_password",
                        "error": "This file needs its password" if h["mode"] == fc.MODE_PASSWORD
                        else "This PC's device key is unavailable"}
        folder = dest or os.path.dirname(path)
        tmp = os.path.join(folder, f".{secrets.token_hex(6)}.chdec")
        self._rt(tmp)
        self._set_temp(job, tmp)
        try:
            res = fc.decrypt_file(path, tmp, keys, lambda n: job.tick(bytes_done=base + n))
        except _Cancelled:
            raise
        except fc.WrongKey as e:
            return r | {"status": "wrong_password", "error": str(e)}
        except (fc.CryptoError, OSError) as e:
            return r | {"error": str(e)[:200]}
        meta = res["meta"]
        fallback = os.path.basename(path)[:-len(fc.EXT)] if path.lower().endswith(fc.EXT) else os.path.basename(path) + ".out"
        final = os.path.join(folder, fc.safe_name(meta.get("name"), fallback or "decrypted"))
        try:
            if os.path.lexists(final):
                if conflict == "skip":
                    os.unlink(tmp)
                    return r | {"status": "skipped", "error": f"{os.path.basename(final)} already exists"}
                if conflict == "rename":
                    final = self._free(final)
                elif os.path.isdir(final) or sh.is_link(final):
                    os.unlink(tmp)
                    return r | {"error": "A folder or link with that name is in the way"}
            try:
                mt = float(meta.get("mtime") or 0)
                if mt > 0:
                    os.utime(tmp, (mt, mt))
            except (OSError, ValueError, OverflowError):
                pass
            self._rt(final, scan=True)
            os.replace(tmp, final)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return r | {"error": str(e)[:200]}
        finally:
            self._set_temp(job, None)
        r.update(status="decrypted", output=final, size=res["size"])
        if delete_encrypted:
            try:
                self._rt(path)
                os.unlink(path)
                r["encrypted_removed"] = True
            except OSError:
                r["encrypted_removed"] = False
        self.db.execute("UPDATE dp_encrypted SET status='decrypted', decrypted_at=? WHERE path=? AND status='encrypted'",
                        (_now(), path))
        if scan:
            try:
                s = self.scanner.scan_file(final)
                if s.get("status") == "infected":
                    r["threats"] = [d.get("name") or d.get("threat_name") for d in s.get("detections", [])][:5]
            except Exception as e:                                       # pragma: no cover
                log.debug("Scan after decrypt failed: %s", e)
        return r

    def inspect(self, path: str, password: str | None = None) -> dict:
        p = self.check_path(path, "find")
        if not os.path.isfile(p):
            raise DPError(422, "Pick a .chx file")
        keys = None
        try:
            with open(p, "rb") as f:
                h = fc.read_header(f)
            if h["mode"] == fc.MODE_DEVICE:
                keys = self._device_keys()
            elif password:
                keys = fc.KeySource(fc.MODE_PASSWORD, password=normalize(password))
            return fc.inspect(p, keys)
        except fc.WrongKey as e:
            raise DPError(401, str(e))
        except fc.CryptoError as e:
            raise DPError(422, str(e))
        except OSError as e:
            raise DPError(400, str(e)[:200])
        finally:
            if keys:
                keys.wipe()

    def verify(self, path: str, password: str | None = None) -> dict:
        """Check a .chx opens and every block is intact, without writing anything."""
        p = self.check_path(path, "find")
        keys = None
        try:
            with open(p, "rb") as f:
                h = fc.read_header(f)
            keys = self._device_keys() if h["mode"] == fc.MODE_DEVICE else (
                fc.KeySource(fc.MODE_PASSWORD, password=normalize(password)) if password else None)
            if keys is None:
                raise DPError(422, "This file needs its password")
            res = fc.decrypt_stream(p, keys)
            return {"ok": True, "name": res["meta"].get("name"), "size": res["size"], "sha256": res["sha256"]}
        except fc.WrongKey as e:
            raise DPError(401, str(e))
        except fc.CryptoError as e:
            return {"ok": False, "error": str(e)}
        except OSError as e:
            raise DPError(400, str(e)[:200])
        finally:
            if keys:
                keys.wipe()

    def encrypted_files(self, cu, status: str | None = "encrypted", limit: int = 200) -> dict:
        where, params = [], []
        if cu.user["role"] != "admin":
            where.append("user_id=?"); params.append(cu.user["id"])
        if status:
            where.append("status=?"); params.append(status)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        rows = self.db.fetchall(f"SELECT * FROM dp_encrypted {clause} ORDER BY id DESC LIMIT ?", tuple(params) + (limit,))
        for r in rows:
            r["exists"] = os.path.isfile(r["path"])
            r["hidden_name"] = bool(r["hidden_name"])
        return {"total": len(rows), "items": rows}

    # ================================================================== shred
    def shred_preview(self, paths: list[str]) -> dict:
        if not paths or len(paths) > MAX_TARGETS:
            raise DPError(422, f"Give 1-{MAX_TARGETS} files or folders")
        targets = [self.check_path(p, "shred") for p in paths]
        files, folders, links, size, hard = 0, 0, 0, 0, 0
        running = self._running_exes()
        busy: list[str] = []
        for t in targets:
            try:
                st = os.lstat(t)
            except OSError:
                continue
            if sh.is_link(t, st):
                links += 1
                continue
            if stat.S_ISREG(st.st_mode):
                files += 1
                size += st.st_size
                hard += st.st_nlink > 1
                if norm(t) in running:
                    busy.append(t)
                continue
            folders += 1
            for kind, fp, sz in sh.iter_tree(t):
                if kind == "file":
                    files += 1
                    size += sz
                    if norm(fp) in running and len(busy) < 20:
                        busy.append(fp)
                elif kind == "link":
                    links += 1
                elif kind == "dir":
                    folders += 1
                if files > MAX_FILES:
                    raise DPError(413, f"More than {MAX_FILES:,} files - pick smaller folders")
        media = sorted({sh.media_type(t) for t in targets})
        warnings = []
        if "ssd" in media:
            warnings.append("This is an SSD / flash drive: wear-levelling can keep old copies of some blocks that no "
                            "program can overwrite. Shredding still removes the file for normal recovery tools; "
                            "BitLocker (full-disk encryption) is the complete protection.")
        if hard:
            warnings.append(f"{hard} file(s) have extra hard links and will be skipped")
        if busy:
            warnings.append(f"{len(busy)} program(s) are running from these files - they will be skipped")
        method = self.settings.get("dp_shred_method")
        return {"targets": targets, "files": files, "folders": folders, "links": links, "bytes": size,
                "size": _fmt(size), "media": media, "method": method, "method_label": sh.METHOD_LABELS[method],
                "methods": sh.METHOD_LABELS, "warnings": warnings, "irreversible": True}

    def start_shred(self, cu, paths: list[str], method: str | None = None, verify: bool | None = None,
                    confirm: bool = False, allow_hardlinks: bool = False) -> dict:
        method = method or self.settings.get("dp_shred_method")
        if method not in sh.METHODS:
            raise DPError(422, f"method must be one of: {', '.join(sh.METHODS)}")
        preview = self.shred_preview(paths)
        if not confirm:
            raise DPError(428, f"Shredding {preview['files']} file(s) ({preview['size']}) can't be undone - "
                               "send again with confirm=true")
        verify = self.settings.get("dp_shred_verify") if verify is None else bool(verify)
        targets = preview["targets"]
        job = self._claim("shred", cu, [norm(t) for t in targets],
                          {"method": method, "verify": verify, "targets": targets[:20], "target_count": len(targets)})
        return self._run(job, lambda j: self._shred_job(j, targets, method, verify, allow_hardlinks))

    def _shred_job(self, job: Job, targets: list[str], method: str, verify: bool, allow_hardlinks: bool) -> dict:
        passes = len(sh.METHODS[method])
        plan: list[tuple[str, str, int]] = []
        for t in targets:
            try:
                st = os.lstat(t)
            except OSError:
                continue
            if sh.is_link(t, st):
                plan.append(("link", t, 0))
            elif stat.S_ISREG(st.st_mode):
                plan.append(("file", t, st.st_size))
            else:
                plan.extend(sh.iter_tree(t))
                plan.append(("dir", t, 0))
            job.check()
        nfiles = sum(1 for k, _, _ in plan if k == "file")
        job.progress.update(files_total=nfiles, bytes_total=sum(s for k, _, s in plan if k == "file") * passes,
                            phase="shredding")
        running = self._running_exes()
        counts = {"shredded": 0, "links_removed": 0, "folders_removed": 0, "skipped": 0, "failed": 0}
        items, done, fi, freed, touched = [], 0, 0, 0, set()
        for kind, p, size in plan:
            if kind == "file":
                job.tick(files=fi, bytes_done=done, current=p)
                r: dict[str, Any] = {"path": p, "status": "shredded", "error": None}
                if norm(p) in running:
                    r.update(status="skipped", error="A program is running from this file")
                else:
                    self._rt(p)
                    try:
                        res = sh.shred_file(p, method, verify, allow_hardlinks,
                                            lambda n, b=done: job.tick(bytes_done=b + n))
                        r["verified"] = res["verified"]
                        freed += size
                        self._close_findings(p, "shredded", "Shredded with Cyber Hub", touched)
                    except sh.ShredError as e:
                        r.update(status="skipped" if e.code in ("hardlinked", "missing", "not_a_file") else "failed",
                                 error=e.message)
                counts[r["status"]] += 1
                done += size * passes
                fi += 1
                if len(items) < RESULT_ITEMS:
                    items.append(r)
            elif kind == "link":
                try:
                    sh.shred_file(p)                                     # removes the link only
                    counts["links_removed"] += 1
                except sh.ShredError:
                    counts["failed"] += 1
            elif kind == "dir":
                if sh.remove_dir(p):
                    counts["folders_removed"] += 1
        for uid in touched:
            self._record_score(uid)
        job.tick(files=fi, bytes_done=done)
        if counts["shredded"]:
            self._bump(shredded_files=counts["shredded"], shredded_bytes=freed)
            self._event(job.user_id, "shredded", "info", f"Shredded {counts['shredded']} file(s) ({_fmt(freed)})",
                        f"{sh.METHOD_LABELS[method]}" + (f", {counts['failed']} failed" if counts["failed"] else ""),
                        {"job_id": job.id})
        return {"summary": counts, "bytes": freed, "method": method, "items": items}

    # ================================================================== cleaner
    def start_cleaner_analysis(self, cu) -> dict:
        job = self._claim("cleaner_analyze", cu, ["::cleaner"], {})
        return self._run(job, self._cleaner_analyze_job)

    def _cleaner_analyze_job(self, job: Job) -> dict:
        job.progress["phase"] = "analyzing"
        cats = self.cleaner.analyze(self.settings.get("dp_cleaner_temp_min_age_hours"), job.check)
        total = sum(c["bytes"] for c in cats)
        rep = {"ts": _now(), "categories": cats, "total_bytes": total, "total_size": _fmt(total),
               "total_files": sum(c["files"] for c in cats)}
        self._state("cleaner_analysis", rep, write=True)
        return rep

    def cleaner_report(self) -> dict:
        rep = self._state("cleaner_analysis")
        return rep or {"ts": None, "categories": [], "total_bytes": 0, "total_files": 0,
                       "note": "Run an analysis first"}

    def start_clean(self, cu, categories: list[str], secure: bool | None = None, confirm: bool = False) -> dict:
        if not categories:
            raise DPError(422, "Pick at least one category")
        known = {c.id: c for c in self.cleaner.categories(self.settings.get("dp_cleaner_temp_min_age_hours"))}
        unknown = [c for c in categories if c not in known]
        if unknown:
            raise DPError(422, f"Unknown or not on this PC: {', '.join(unknown[:10])}")
        risky = [known[c].label for c in categories if known[c].needs_confirm]
        if risky and not confirm:
            raise DPError(428, f"{', '.join(risky)}: {known[[c for c in categories if known[c].needs_confirm][0]].warning}"
                               " - send again with confirm=true")
        secure = self.settings.get("dp_cleaner_secure") if secure is None else bool(secure)
        job = self._claim("clean", cu, ["::cleaner"], {"categories": categories, "secure": secure})
        return self._run(job, lambda j: self._clean_job(j, categories, secure))

    def _clean_job(self, job: Job, categories: list[str], secure: bool) -> dict:
        job.progress.update(files_total=len(categories), phase="cleaning")
        state = {"done": 0, "base": 0}

        def cp(b: int, label: str):
            job.tick(bytes_done=state["base"] + b, current=label)
        res = []
        for i, cid in enumerate(categories):
            job.tick(files=i)
            r = self.cleaner.clean([cid], self.settings.get("dp_cleaner_temp_min_age_hours"), secure, cp)[0]
            state["base"] += r.get("bytes", 0)
            res.append(r)
        files = sum(r.get("files", 0) for r in res)
        size = sum(r.get("bytes", 0) for r in res)
        job.tick(files=len(categories))
        self._bump(cleaned_files=files, cleaned_bytes=size)
        self._event(job.user_id, "cleaned", "info", f"Privacy clean freed {_fmt(size)}",
                    f"{files} item(s) in {len(categories)} categor{'y' if len(categories) == 1 else 'ies'}",
                    {"job_id": job.id, "bytes": size}, category="privacy")
        rep = self._state("cleaner_analysis")
        if rep:                                                         # keep the analysis honest
            for c in rep.get("categories", []):
                if c["id"] in categories and any(r["id"] == c["id"] and r["status"] == "done" for r in res):
                    c["files"], c["bytes"] = 0, 0
            rep["total_bytes"] = sum(c["bytes"] for c in rep["categories"])
            rep["total_size"] = _fmt(rep["total_bytes"])
            rep["total_files"] = sum(c["files"] for c in rep["categories"])
            self._state("cleaner_analysis", rep, write=True)
        return {"categories": res, "files": files, "bytes": size, "size": _fmt(size), "secure": secure}

    # ================================================================== sensitive-file finder
    def finder_roots(self) -> list[dict]:
        roots = []
        if self.settings.get("dp_finder_default_folders"):
            override = os.environ.get("CYBERHUB_FINDER_DEFAULT_DIRS")
            if override:
                roots += [{"label": "Folder", "path": p} for p in override.split(os.pathsep) if p]
            else:
                from .realtime import default_folders
                roots += [{"label": f["label"], "path": f["path"]} for f in default_folders()
                          if f["id"] in ("downloads", "desktop", "documents")]
        roots += [{"label": "Your folder", "path": p} for p in self.settings.get("dp_finder_paths")]
        out, seen = [], set()
        for r in roots:
            n = norm(r["path"])
            if n not in seen:
                seen.add(n)
                out.append(r | {"exists": os.path.isdir(r["path"])})
        return out

    def start_finder(self, cu, paths: list[str] | None = None, types: list[str] | None = None) -> dict:
        types = types or self.settings.get("dp_finder_types")
        if not types:
            raise DPError(422, "Pick at least one kind of sensitive data to look for")
        bad = [t for t in types if t not in sf.DETECTORS]
        if bad:
            raise DPError(422, f"Unknown type(s): {', '.join(bad)}")
        if paths:
            if len(paths) > MAX_TARGETS:
                raise DPError(422, f"Give up to {MAX_TARGETS} folders")
            roots = [self.check_path(p, "find") for p in paths]
        else:
            roots = [r["path"] for r in self.finder_roots() if r["exists"]]
            if not roots:
                raise DPError(404, "No folders to search - add one in dp_finder_paths or pass paths")
        job = self._claim("finder", cu, [norm(r) + os.sep + "::find" for r in roots],
                          {"roots": roots[:20], "types": sorted(types)})
        return self._run(job, lambda j: self._finder_job(j, roots, set(types)))

    def _finder_job(self, job: Job, roots: list[str], types: set[str]) -> dict:
        uid = job.user_id
        max_bytes = self.settings.get("dp_finder_max_file_mb") * 1024 * 1024
        job.progress["phase"] = "listing files"
        exclude = [x for x in (self.data_dir, self.app_dir) if x]
        files = []
        for r in roots:
            for p, size in self._collect([r], sf.candidate, job):
                n = norm(p)
                if not any(_inside(n, e) for e in exclude):
                    files.append((p, size))
        job.progress.update(files_total=len(files), phase="searching")
        existing = {r["path"]: r for r in self.db.fetchall("SELECT * FROM dp_findings WHERE user_id IS ?", (uid,))}
        now = _now()
        stats = {"checked": 0, "skipped": 0, "with_findings": 0, "new": 0, "new_high": 0}
        seen: set[str] = set()
        for i, (p, size) in enumerate(files):
            job.tick(files=i, current=p)
            seen.add(p)
            try:
                st = os.stat(p)
            except OSError:
                stats["skipped"] += 1
                continue
            old = existing.get(p)
            if old and old["status"] == "ignored" and old["size"] == st.st_size and abs((old["mtime"] or 0) - st.st_mtime) < 0.01:
                stats["checked"] += 1
                stats["with_findings"] += 1
                continue                                             # unchanged and ignored - leave it
            found, how = sf.analyze_file(p, types, max_bytes)
            if how in ("too_large",) or how.startswith("error"):
                stats["skipped"] += 1
                if not found:
                    continue
            stats["checked"] += 1
            if not found:
                if old and old["status"] == "open":
                    self.db.execute("UPDATE dp_findings SET status='resolved', status_changed_at=?, note=? WHERE id=?",
                                    (now, "No longer contains sensitive data", old["id"]))
                continue
            stats["with_findings"] += 1
            sev, pts = sf.summarize(found)
            data = json.dumps(found)
            if old:
                reopen = old["status"] != "open" and not (old["status"] == "ignored" and old["size"] == st.st_size
                                                          and abs((old["mtime"] or 0) - st.st_mtime) < 0.01)
                self.db.execute("UPDATE dp_findings SET size=?, mtime=?, severity=?, points=?, types=?, last_seen=?, "
                                "status=CASE WHEN ? THEN 'open' ELSE status END, "
                                "status_changed_at=CASE WHEN ? THEN ? ELSE status_changed_at END WHERE id=?",
                                (st.st_size, st.st_mtime, sev, pts, data, now, reopen, reopen, now, old["id"]))
                if reopen:
                    stats["new"] += 1
                    stats["new_high"] += sev in ("high", "critical")
            else:
                self.db.execute("INSERT INTO dp_findings(user_id, path, name, size, mtime, severity, points, types, "
                                "first_seen, last_seen, status_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                (uid, p, os.path.basename(p), st.st_size, st.st_mtime, sev, pts, data, now, now, now))
                stats["new"] += 1
                stats["new_high"] += sev in ("high", "critical")
        job.tick(files=len(files))
        nroots = [norm(r) for r in roots]
        for path, old in existing.items():                            # gone since the last search
            if path in seen or old["status"] not in ("open", "ignored"):
                continue
            if any(_inside(norm(path), r) for r in nroots) and not os.path.exists(path):
                self.db.execute("UPDATE dp_findings SET status='resolved', status_changed_at=?, note=? WHERE id=?",
                                (now, "File removed", old["id"]))
        self._bump(findings_new=stats["new"])
        self._state(f"finder_last:{uid}", {"ts": now, "roots": roots, "stats": stats}, write=True)
        h = self._record_score(uid)
        if stats["new_high"] and self.settings.get("dp_finder_alert"):
            self._event(uid, "sensitive_found", "high", f"{stats['new_high']} file(s) with sensitive data found",
                        "Card numbers, CNICs, private keys or saved passwords in plain files - encrypt or shred them",
                        {"job_id": job.id, "new": stats["new"]})
        else:
            self._event(uid, "finder_done", "info", f"Sensitive-file search checked {stats['checked']} file(s)",
                        f"{stats['with_findings']} with sensitive data", {"job_id": job.id})
        return {"stats": stats, "roots": roots, "score": h["score"], "grade": h["grade"]}

    # ------------------------------------------------------------------ findings
    def _finding_public(self, r: dict) -> dict:
        types = json.loads(r["types"]) if r.get("types") else {}
        return {"id": r["id"], "path": r["path"], "name": r["name"], "folder": os.path.dirname(r["path"]),
                "size": r["size"], "mtime": r["mtime"], "severity": r["severity"], "status": r["status"],
                "exists": os.path.exists(r["path"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "status_changed_at": r["status_changed_at"], "note": r["note"],
                "types": [{"type": k, "label": sf.DETECTORS.get(k, (k,))[0], "count": v["count"],
                           "severity": v["severity"], "samples": v["samples"], "kinds": v.get("kinds", []),
                           "advice": sf.ADVICE.get(k)} for k, v in
                          sorted(types.items(), key=lambda kv: -sf.SEV_ORDER[kv[1]["severity"]])],
                "actions": (["encrypt", "shred", "ignore"] if r["status"] == "open" else
                            ["unignore"] if r["status"] == "ignored" else [])}

    def findings(self, cu, status: str | None = "open", severity: str | None = None, type_: str | None = None,
                 q: str | None = None, limit: int = 100, offset: int = 0) -> dict:
        where, params = ["user_id IS ?"], [cu.user["id"]]
        if status:
            where.append("status=?"); params.append(status)
        if severity:
            where.append("severity=?"); params.append(severity)
        if type_:
            where.append("types LIKE ?"); params.append(f'%"{type_}"%')
        if q:
            where.append("path LIKE ? ESCAPE '\\'")
            params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        clause = " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM dp_findings WHERE {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM dp_findings WHERE {clause} ORDER BY points DESC, last_seen DESC "
                                "LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
        return {"total": total, "items": [self._finding_public(r) for r in rows],
                "last_search": self._state(f"finder_last:{cu.user['id']}")}

    def _finding_row(self, cu, fid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM dp_findings WHERE id=? AND user_id IS ?", (fid, cu.user["id"]))
        if not r:
            raise DPError(404, "Finding not found")
        return r

    def finding(self, cu, fid: int) -> dict:
        return self._finding_public(self._finding_row(cu, fid))

    def _close_findings(self, path: str, status: str, note: str, touched: set) -> None:
        """A file that was encrypted / shredded - by a finding's button or from the Encrypt / Shred panels - is no
        longer an open finding for anyone."""
        same = "path=? COLLATE NOCASE" if IS_WINDOWS else "path=?"           # Windows paths ignore case
        rows = self.db.fetchall(f"SELECT id, user_id FROM dp_findings WHERE {same} AND status IN ('open','ignored')",
                                (os.path.abspath(path),))
        for r in rows:
            self.db.execute("UPDATE dp_findings SET status=?, status_changed_at=?, note=? WHERE id=?",
                            (status, _now(), note, r["id"]))
            touched.add(r["user_id"])

    def _finding_status(self, fid: int, status: str, note: str | None = None) -> None:
        r = self.db.fetchone("SELECT user_id FROM dp_findings WHERE id=?", (fid,))
        self.db.execute("UPDATE dp_findings SET status=?, status_changed_at=?, note=? WHERE id=?",
                        (status, _now(), note, fid))
        if r:
            self._record_score(r["user_id"])

    def set_ignored(self, cu, fid: int, ignored: bool, note: str | None = None) -> dict:
        r = self._finding_row(cu, fid)
        if ignored and r["status"] != "open":
            raise DPError(409, f"Finding is {r['status']}")
        if not ignored and r["status"] != "ignored":
            raise DPError(409, "Finding is not ignored")
        self._finding_status(fid, "ignored" if ignored else "open", (note or "Marked as OK")[:300] if ignored else None)
        return self.finding(cu, fid)

    def encrypt_finding(self, cu, fid: int, **kw) -> dict:
        r = self._finding_row(cu, fid)
        if r["status"] != "open":
            raise DPError(409, f"Finding is {r['status']}")
        if not os.path.isfile(r["path"]):
            self._finding_status(fid, "resolved", "File removed")
            raise DPError(404, "The file no longer exists")
        return self.start_encrypt(cu, [r["path"]], **kw)

    def shred_finding(self, cu, fid: int, confirm: bool = False, method: str | None = None) -> dict:
        r = self._finding_row(cu, fid)
        if r["status"] not in ("open", "ignored"):
            raise DPError(409, f"Finding is {r['status']}")
        if not os.path.isfile(r["path"]):
            self._finding_status(fid, "resolved", "File removed")
            raise DPError(404, "The file no longer exists")
        return self.start_shred(cu, [r["path"]], method=method, confirm=confirm)

    # ------------------------------------------------------------------ score (Part 18)
    def health(self, uid: int | None = None) -> dict:
        """Data-exposure score from open sensitive-file findings. uid None = every user (Part 18)."""
        where, params = ("WHERE status='open'", ()) if uid is None else ("WHERE status='open' AND user_id IS ?", (uid,))
        rows = self.db.fetchall(f"SELECT severity, points FROM dp_findings {where}", params)
        counts = {s: 0 for s in SEVERITIES}
        for r in rows:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        penalty = sum(POINTS.get(r["severity"], 0) for r in rows)
        score = round(100 * 100 / (100 + penalty))
        if counts["critical"]:
            score = min(score, 49)
        elif counts["high"]:
            score = min(score, 84)
        searched = (self._state(f"finder_last:{uid}") if uid is not None else
                    self.db.fetchone("SELECT 1 AS x FROM dp_state WHERE key LIKE 'finder_last:%'"))
        rep = self._state("cleaner_analysis") or {}
        enc = self.db.fetchone("SELECT COUNT(*) AS n FROM dp_encrypted WHERE status='encrypted'" +
                               ("" if uid is None else " AND user_id IS ?"), () if uid is None else (uid,))["n"]
        return {"score": score, "grade": next(g for t, g in GRADES if score >= t), "open_findings": len(rows),
                "by_severity": counts, "searched": bool(searched), "encrypted_files": enc,
                "junk_bytes": rep.get("total_bytes", 0), "junk_size": _fmt(rep.get("total_bytes", 0)),
                "cleaner_analyzed_at": rep.get("ts")}

    def analyze(self) -> dict:
        """Part 18 hook (same shape as the other modules: {'score': ...})."""
        return self.health(None)

    def _record_score(self, uid: int | None) -> dict:
        h = self.health(uid)
        c = h["by_severity"]
        self.db.execute("INSERT INTO dp_scores(user_id, score, critical, high, medium, low) VALUES (?,?,?,?,?,?)",
                        (uid, h["score"], c["critical"], c["high"], c["medium"], c["low"]))
        return h

    # ------------------------------------------------------------------ events
    def events(self, cu, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100) -> dict:
        where, params = ["(user_id IS ? OR user_id IS NULL)", "id > ?"], [cu.user["id"], after_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if kind:
            where.append("kind=?"); params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        rows = self.db.fetchall(f"SELECT * FROM dp_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        for r in rows:
            r["data"] = json.loads(r["data"]) if r.get("data") else None
            r["acknowledged"] = bool(r["acknowledged"])
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM dp_events")["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM dp_events WHERE (user_id IS ? OR user_id IS NULL) "
                                 "AND acknowledged=0", (cu.user["id"],))["n"]
        return {"items": rows, "last_id": last, "unacknowledged": unack}

    def acknowledge(self, cu, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE dp_events SET acknowledged=1 WHERE id IN ({q}) AND "
                                   "(user_id IS ? OR user_id IS NULL)", tuple(ids) + (cu.user["id"],)).rowcount
        return self.db.execute("UPDATE dp_events SET acknowledged=1 WHERE user_id IS ? OR user_id IS NULL",
                               (cu.user["id"],)).rowcount

    def clear_events(self, cu) -> int:
        return self.db.execute("DELETE FROM dp_events WHERE user_id IS ?", (cu.user["id"],)).rowcount

    # ------------------------------------------------------------------ dashboard
    def status(self, cu) -> dict:
        uid = cu.user["id"]
        with self._lock:
            running = [j.public() for j in self._jobs.values() if j.status == "running" and
                       (j.user_id == uid or cu.user["role"] == "admin")]
        g = self.settings.get
        return {
            "features": {"encryption": True, "device_mode": bool(self.vault is not None and self.vault.available),
                         "save_to_password_vault": self.passwords is not None, "shredder": True, "cleaner": True,
                         "finder": True},
            "encryption": {"format": ".chx (AES-256-GCM, 1 MiB authenticated chunks)",
                           "kdf": f"scrypt N=2^{fc.kdf_params()['n'].bit_length() - 1}, r=8, p=1",
                           "originals": g("dp_encrypt_original"), "hide_names": g("dp_encrypt_hide_names")},
            "shredder": {"method": g("dp_shred_method"), "verify": g("dp_shred_verify"), "methods": sh.METHOD_LABELS,
                         "home_media": sh.media_type(str(Path.home()))},
            "cleaner": {"last_analysis": (self._state("cleaner_analysis") or {}).get("ts"),
                        "junk_bytes": (self._state("cleaner_analysis") or {}).get("total_bytes", 0),
                        "temp_min_age_hours": g("dp_cleaner_temp_min_age_hours"), "secure": g("dp_cleaner_secure")},
            "finder": {"roots": self.finder_roots(), "types": [{"id": k, "label": v[0], "severity": v[1],
                                                                "enabled": k in g("dp_finder_types")}
                                                               for k, v in sf.DETECTORS.items()],
                       "last_search": self._state(f"finder_last:{uid}")},
            "health": self.health(uid),
            "jobs_running": running,
            "unacknowledged": self.db.fetchone("SELECT COUNT(*) AS n FROM dp_events WHERE (user_id IS ? OR "
                                               "user_id IS NULL) AND acknowledged=0", (uid,))["n"],
        }

    def summary(self, cu, days: int = 30) -> dict:
        uid = cu.user["id"]
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        rows = {r["day"]: r for r in self.db.fetchall("SELECT * FROM dp_daily WHERE day >= ? ORDER BY day", (since,))}
        series = []
        for i in range(days):
            d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
            r = rows.get(d, {})
            series.append({"day": d, **{k: r.get(k, 0) for k in ("encrypted_files", "decrypted_files", "shredded_files",
                                                                  "shredded_bytes", "cleaned_files", "cleaned_bytes",
                                                                  "findings_new")}})
        by_type: dict[str, int] = {}
        by_sev = {s: 0 for s in SEVERITIES}
        for r in self.db.fetchall("SELECT severity, types FROM dp_findings WHERE status='open' AND user_id IS ?", (uid,)):
            by_sev[r["severity"]] += 1
            for k in json.loads(r["types"] or "{}"):
                by_type[k] = by_type.get(k, 0) + 1
        by_status = {r["status"]: r["n"] for r in self.db.fetchall(
            "SELECT status, COUNT(*) AS n FROM dp_findings WHERE user_id IS ? GROUP BY status", (uid,))}
        scores = self.db.fetchall("SELECT substr(ts,1,10) AS day, MIN(score) AS score FROM dp_scores WHERE user_id IS ? "
                                  "AND ts >= ? GROUP BY day ORDER BY day", (uid, since))
        rep = self._state("cleaner_analysis") or {}
        return {"days": days, "per_day": series,
                "totals": {k: sum(s[k] for s in series) for k in series[0] if k != "day"} if series else {},
                "findings_by_type": [{"type": k, "label": sf.DETECTORS[k][0], "files": v}
                                     for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])],
                "findings_by_severity": by_sev, "findings_by_status": by_status, "score_history": scores,
                "junk_by_category": [{"id": c["id"], "label": c["label"], "bytes": c["bytes"], "files": c["files"]}
                                     for c in rep.get("categories", []) if c["bytes"] or c["files"]],
                "health": self.health(uid)}

    def prune(self, days: int | None = None) -> int:
        days = days or self.settings.get("dp_history_days")
        cut = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        n = self.db.execute("DELETE FROM dp_jobs WHERE status NOT IN ('running') AND created_at < ?", (cut,)).rowcount
        n += self.db.execute("DELETE FROM dp_events WHERE ts < ?", (cut,)).rowcount
        n += self.db.execute("DELETE FROM dp_scores WHERE ts < ?", (cut,)).rowcount
        n += self.db.execute("DELETE FROM dp_findings WHERE status='resolved' AND status_changed_at < ?", (cut,)).rowcount
        return n

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.status == "running"]
        for j in jobs:
            j.cancel.set()
        end = time.monotonic() + timeout
        for j in jobs:
            if j.thread:
                j.thread.join(max(0.1, end - time.monotonic()))


async def data_protection_loop(svc: DataProtectionService, every_seconds: int = 6 * 3600) -> None:
    """Housekeeping: prune old job / event history."""
    import asyncio
    while True:
        await asyncio.sleep(every_seconds)
        try:
            await asyncio.to_thread(svc.prune)
        except Exception as e:                                           # pragma: no cover
            log.warning("Data-protection housekeeping failed: %s", e)
