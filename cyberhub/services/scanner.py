"""
Cyber Hub Backend - Antivirus scan engine (Part 5)
Developed by Syed Muhammad Tayyab

Quick / Full / Custom scans, run one at a time on a background thread:

    queued -> running (enumerating -> scanning -> finalizing) -> completed
                 |  ^                                      +-> cancelled / failed
                 v  |
                paused                         (engine restart -> interrupted)

Every file is streamed once to compute SHA-256 + SHA-1 + MD5, looked up in
the local signature DB (malware_db.py), checked against built-in byte
patterns, and - for .zip / .jar / .docx-style archives - opened and every
entry inside is checked too (nested up to 2 levels, zip-bomb guarded).

Hashes of unchanged files are cached (path + size + modified time), so a
second Quick scan takes seconds. Progress, threats and job changes are
pushed to the UI over a WebSocket (routers/scanner.py).

Part 6 adds quarantine / allow-list actions on the detections recorded here
(allowed files are filtered in _verdict, on_detections drives auto-quarantine),
Part 7 calls `scan_file()` for real-time protection, Part 17 schedules jobs.
Part 8: files no hash signature knows get a second opinion from the
`inspector` (YARA rules + heuristics, verdict cached per SHA-256 + name) -
also for files inside archives - and clean programs can be queued for an
online hash lookup (`cloud`).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import threading
import time
import zipfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import psutil

from ..database import Database
from ..logger import get_logger
from .allowlist import threat_event
from .malware_db import EICAR, PATTERN_HEAD_BYTES, MalwareDB
from .platform_tools import IS_WINDOWS

log = get_logger("scanner")

KINDS = ("quick", "full", "custom")
ACTIVE = ("queued", "running", "paused")
FINISHED = ("completed", "cancelled", "failed", "interrupted")

CHUNK = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_DEPTH = 2
NESTED_ARCHIVE_MAX = 32 * 1024 * 1024          # nested archives are opened in memory up to 32 MB
BOMB_RATIO = 250                                # uncompressed / compressed above this = zip bomb guard
CACHE_FLUSH = 400
PERSIST_EVERY = 2.0                             # seconds between progress writes to SQLite

# File types malware actually uses - deep quick-scan locations (AppData...) only look at these.
RISKY_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".drv", ".ocx", ".msi", ".msp", ".msix",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk",
    ".jar", ".zip", ".rar", ".7z", ".cab", ".iso", ".img", ".vhd", ".docm", ".xlsm", ".pptm", ".dotm",
    ".xlam", ".one", ".url", ".reg", ".inf", ".sh", ".py", ".pl", ".elf", ".so", ".apk", ".appimage",
}
ARCHIVE_MAGIC = b"PK\x03\x04"

# Never descend into these (pseudo file systems / OS bookkeeping).
_POSIX_SKIP = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers"}
_WIN_SKIP_NAMES = {"system volume information", "$windows.~bt", "$windows.~ws", "$winreagent"}


_LINK_TAGS = {0xA0000003, 0xA000000C}           # IO_REPARSE_TAG_MOUNT_POINT (junction), IO_REPARSE_TAG_SYMLINK
_CLOUD_ONLY = 0x400000 | 0x40000 | 0x1000       # RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE


def _is_reparse_point(e: os.DirEntry) -> bool:
    """Windows junctions (e.g. 'Application Data' -> AppData\\Local) would loop forever.
    Only junctions / symlinks are skipped - OneDrive folders are reparse points too and must be scanned."""
    if not IS_WINDOWS:
        return False
    if hasattr(e, "is_junction") and e.is_junction():               # pragma: no cover
        return True
    try:                                                            # pragma: no cover
        return getattr(os.lstat(e.path), "st_reparse_tag", 0) in _LINK_TAGS
    except OSError:
        return True


def _cloud_only(st: os.stat_result) -> bool:
    """OneDrive / Dropbox 'online-only' files: reading them would download them - skip."""
    return bool(getattr(st, "st_file_attributes", 0) & _CLOUD_ONLY)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


class ScanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class _Stop(Exception):
    """Raised inside the worker when a job is cancelled or the engine shuts down."""


# ====================================================================== targets
def _env_list(name: str) -> list[str] | None:
    v = os.environ.get(name)
    return [p for p in v.split(os.pathsep) if p] if v else None


def quick_locations() -> list[dict]:
    """Where malware usually lives. CYBERHUB_QUICK_SCAN_DIRS overrides (tests / power users)."""
    override = _env_list("CYBERHUB_QUICK_SCAN_DIRS")
    if override:
        return [{"path": p, "depth": None, "risky_only": False, "label": "Custom quick location"} for p in override]
    home = Path.home()
    out: list[dict] = []

    def add(p, depth, risky, label):
        if p and os.path.isdir(p):
            out.append({"path": str(p), "depth": depth, "risky_only": risky, "label": label})

    if IS_WINDOWS:                                                  # pragma: no cover
        env = os.environ
        windir = env.get("SystemRoot", r"C:\Windows")
        add(env.get("TEMP"), 4, False, "Your temp folder")
        add(os.path.join(windir, "Temp"), 3, False, "Windows temp folder")
        add(home / "Downloads", 3, False, "Downloads")
        add(home / "Desktop", 2, False, "Desktop")
        add(env.get("APPDATA"), 3, True, "AppData\\Roaming (programs & scripts)")
        add(env.get("LOCALAPPDATA"), 2, True, "AppData\\Local (programs & scripts)")
        add(env.get("PROGRAMDATA"), 2, True, "ProgramData (programs & scripts)")
        add(Path(env.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup", 1, False,
            "Your Startup folder")
        add(Path(env.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp", 1, False,
            "All users Startup folder")
        add(env.get("PUBLIC"), 2, True, "Public user folder")
    else:
        add("/tmp", 3, False, "/tmp")
        add("/var/tmp", 2, False, "/var/tmp")
        add("/dev/shm", 2, False, "/dev/shm")
        add(home / "Downloads", 3, False, "Downloads")
        add(home / "Desktop", 2, False, "Desktop")
        add(home / ".config" / "autostart", 1, False, "Autostart entries")
        add(home / ".local" / "bin", 1, False, "~/.local/bin")
    return out


def full_roots() -> list[str]:
    """Every fixed drive (Windows) or / (Linux / macOS). CYBERHUB_FULL_SCAN_ROOTS overrides."""
    override = _env_list("CYBERHUB_FULL_SCAN_ROOTS")
    if override:
        return override
    if IS_WINDOWS:                                                  # pragma: no cover
        roots = []
        for p in psutil.disk_partitions(all=False):
            if "cdrom" in p.opts or "removable" in p.opts or p.fstype == "" or "remote" in p.opts:
                continue
            roots.append(p.mountpoint)
        return roots or [os.environ.get("SystemDrive", "C:") + "\\"]
    return ["/"]


def running_program_files() -> list[str]:
    paths = set()
    for p in psutil.process_iter(["exe"]):
        exe = p.info.get("exe")
        if exe and os.path.isfile(exe):
            paths.add(exe)
    return sorted(paths)


# ====================================================================== the engine
class ScanManager:
    def __init__(self, db: Database, malware: MalwareDB, settings, activity, startup=None,
                 data_dir: Path | None = None):
        self.db, self.malware, self.settings, self.activity, self.startup = db, malware, settings, activity, startup
        self.data_dir = data_dir
        self._lock = threading.RLock()
        self._jobs: dict[int, dict] = {}            # live state of queued / running / paused jobs
        self._threads: dict[int, threading.Thread] = {}
        self._events: deque = deque(maxlen=1000)
        self._seq = 0
        self._closing = False
        self.per_file_delay = 0.0                   # test hook: slows the worker down
        self.allowlist = None                       # Part 6: AllowList - allowed files / threats are not reported
        self.on_detections = None                   # Part 6: callback(rows) -> auto-quarantine policy
        self.inspector = None                       # Part 8: rules_engine.Inspector (YARA + heuristics)
        self.cloud = None                           # Part 8: cloud_lookup.CloudLookup (background hash lookups)
        n = db.execute("UPDATE scan_jobs SET status='interrupted', finished_at=?, "
                       "message='Engine stopped while the scan was running' WHERE status IN ('queued','running','paused')",
                       (_now(),)).rowcount
        if n:
            log.info("Marked %s unfinished scan job(s) as interrupted", n)

    # ------------------------------------------------------------ events (WebSocket feed)
    def _emit(self, type_: str, **data) -> None:
        with self._lock:
            self._seq += 1
            self._events.append({"seq": self._seq, "type": type_, "ts": _now(), **data})

    def events_since(self, seq: int) -> tuple[int, list[dict]]:
        with self._lock:
            return self._seq, [e for e in self._events if e["seq"] > seq]

    # ------------------------------------------------------------ options
    def _options(self, extra: dict | None = None) -> dict:
        g = self.settings.get
        excl = [norm(p) for p in g("scan_excluded_paths")]
        if self.data_dir:
            excl.append(norm(str(self.data_dir / "quarantine")))   # never re-scan our own vault
        o = {
            "max_file_bytes": g("scan_max_file_mb") * 1024 * 1024,
            "archives": bool(g("scan_archives")),
            "archive_max_bytes": g("scan_archive_max_mb") * 1024 * 1024,
            "excluded_paths": excl,
            "excluded_ext": {e.lower() if e.startswith(".") else "." + e.lower() for e in g("scan_excluded_extensions")},
            "hash_cache": bool(g("scan_hash_cache")),
            "inspect": self.inspector is not None,                 # Part 8
            "insp": self.inspector.options() if self.inspector is not None else None,
            "cloud": self.cloud is not None,
            "origin": "scan",
        }
        if extra:
            o.update(extra)
        return o

    @staticmethod
    def _excluded(path_n: str, opts: dict) -> bool:
        for e in opts["excluded_paths"]:
            if path_n == e or path_n.startswith(e.rstrip(os.sep) + os.sep):
                return True
        return False

    # ------------------------------------------------------------ walking
    def iter_target(self, t: dict, opts: dict, seen: set | None, checkpoint=None):
        """Yield every file under a target dict {path, depth, risky_only}."""
        root = t["path"]
        risky = t.get("risky_only", False)
        max_depth = t.get("depth")
        if os.path.isfile(root):
            n = norm(root)
            if not self._excluded(n, opts) and (seen is None or n not in seen):
                if seen is not None:
                    seen.add(n)
                yield root
            return
        stack = [(root, 0)]
        while stack:
            d, depth = stack.pop()
            if checkpoint:
                checkpoint()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        if e.is_symlink() or _is_reparse_point(e):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if max_depth is not None and depth >= max_depth:
                                continue
                            if IS_WINDOWS and e.name.lower() in _WIN_SKIP_NAMES:
                                continue
                            if not IS_WINDOWS and e.path in _POSIX_SKIP:
                                continue
                            if self._excluded(norm(e.path), opts):
                                continue
                            stack.append((e.path, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            ext = os.path.splitext(e.name)[1].lower()
                            if risky and ext not in RISKY_EXT:
                                continue
                            n = norm(e.path)
                            if seen is not None:
                                if n in seen:
                                    continue
                                seen.add(n)
                            yield e.path
                    except OSError:
                        continue

    def resolve_targets(self, kind: str, paths: list[str] | None) -> list[dict]:
        if kind == "quick":
            ts = quick_locations()
            extra = running_program_files()
            if self.startup is not None:
                try:
                    extra += [i["path"] for i in self.startup.scan(with_signatures=False)
                              if i.get("path") and os.path.isfile(i["path"])]
                except Exception as e:                              # pragma: no cover
                    log.warning("Startup items unavailable for quick scan: %s", e)
            ts += [{"path": p, "depth": 0, "risky_only": False, "label": "Running program / startup item"}
                   for p in dict.fromkeys(extra)]
            return ts
        if kind == "full":
            return [{"path": r, "depth": None, "risky_only": False, "label": f"Drive {r}"} for r in full_roots()]
        return [{"path": p, "depth": None, "risky_only": False, "label": p} for p in (paths or [])]

    # ------------------------------------------------------------ one file
    def _hash_stream(self, f, limit: int, checkpoint=None) -> tuple[str, str, str, bytes, int]:
        h256, h1, h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
        head = b""
        n = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if not head:
                head = chunk[:PATTERN_HEAD_BYTES]
            n += len(chunk)
            if n > limit:
                raise _TooBig()
            h256.update(chunk); h1.update(chunk); h5.update(chunk)
            if checkpoint and n % (16 * CHUNK) == 0:
                checkpoint()
        return h256.hexdigest(), h1.hexdigest(), h5.hexdigest(), head, n

    def _verdict(self, sha256: str, sha1: str, md5: str, head: bytes, use_allowlist: bool = True) -> dict | None:
        v = None
        sig = self.malware.lookup(sha256=sha256, sha1=sha1, md5=md5)
        if sig:
            v = {"threat_name": sig["name"], "severity": sig["severity"], "method": "hash",
                 "signature_source": sig["source"]}
        else:
            pat = self.malware.match_patterns(head)
            if pat:
                v = {"threat_name": pat[0], "severity": pat[1], "method": "pattern", "signature_source": "builtin"}
        if v and use_allowlist and self._allowed(sha256, v["threat_name"]):
            return None
        return v

    def _allowed(self, sha256: str, threat_name: str) -> bool:
        """Part 6: "Allow on device" - by SHA-256 or by threat name."""
        if self.allowlist is None:
            return False
        entry = self.allowlist.match(sha256, threat_name)
        if entry is not None:
            self.allowlist.hit(entry)
            return True
        return False

    def _inspect(self, res: dict, sha256: str, md5: str, name: str, size: int, data: bytes | None,
                 path: str | None, opts: dict, member: str | None = None) -> None:
        """Part 8: YARA + heuristics for a file (or archive member) the hash database doesn't know."""
        insp = opts.get("insp")
        if not (opts.get("inspect") and insp and self.inspector is not None):
            return
        if member is not None and not insp["archives"]:
            return
        try:
            verdicts = self.inspector.inspect(sha256, name, size, data, path, insp)
        except Exception as e:                                          # never fail a scan over a rule
            log.warning("Rules / heuristics failed on %s: %s", path or name, e)
            return
        for iv in verdicts:
            if opts.get("use_allowlist", True) and self._allowed(sha256, iv["threat_name"]):
                continue
            res["detections"].append(iv | {"archive_member": member, "sha256": sha256, "md5": md5, "size": size})

    def scan_file(self, path: str, opts: dict | None = None, checkpoint=None, cache_out: list | None = None) -> dict:
        """Scan one file. Returns {path, status: clean|infected|skipped|error, reason, size,
        sha256, md5, bytes_read, archive_entries, detections[]}. Used by jobs, the
        on-demand 'scan this file' endpoint and (Part 7) real-time protection."""
        opts = opts or self._options()
        res = {"path": path, "status": "clean", "reason": None, "size": None, "sha256": None, "sha1": None,
               "md5": None, "bytes_read": 0, "archive_entries": 0, "cached": False, "detections": []}
        n = norm(path)
        if self._excluded(n, opts):
            return res | {"status": "skipped", "reason": "excluded"}
        if os.path.splitext(path)[1].lower() in opts["excluded_ext"]:
            return res | {"status": "skipped", "reason": "excluded_type"}
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return res | {"status": "skipped", "reason": "missing"}
        except PermissionError:
            return res | {"status": "skipped", "reason": "access_denied"}
        except OSError as e:
            return res | {"status": "error", "reason": str(e)[:200]}
        if not stat.S_ISREG(st.st_mode):
            return res | {"status": "skipped", "reason": "not_a_file"}
        if _cloud_only(st):
            return res | {"status": "skipped", "reason": "cloud_only"}
        res["size"] = st.st_size
        if st.st_size > opts["max_file_bytes"]:
            return res | {"status": "skipped", "reason": "too_large"}
        mtime = round(st.st_mtime, 3)
        cached = None
        if opts["hash_cache"]:
            cached = self.db.fetchone("SELECT sha256, sha1, md5 FROM file_hash_cache WHERE path=? AND size=? "
                                      "AND abs(mtime-?) < 0.01", (n, st.st_size, mtime))
        insp = opts.get("insp") if opts.get("inspect") else None
        keep = bool(insp) and st.st_size <= insp["max_bytes"]           # Part 8: read small files once
        data = None
        try:
            with open(path, "rb") as f:
                if cached:
                    head = f.read(PATTERN_HEAD_BYTES)
                    sha256, sha1, md5 = cached["sha256"], cached["sha1"], cached["md5"]
                    res["cached"] = True
                else:
                    if keep:
                        data = f.read(opts["max_file_bytes"] + 1)
                        if len(data) > opts["max_file_bytes"]:
                            raise _TooBig()
                        sha256, sha1, md5 = (hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                                             hashlib.md5(data).hexdigest())
                        head, nread = data[:PATTERN_HEAD_BYTES], len(data)
                    else:
                        sha256, sha1, md5, head, nread = self._hash_stream(f, opts["max_file_bytes"], checkpoint)
                    res["bytes_read"] = nread
                    if opts["hash_cache"]:
                        row = (n, st.st_size, mtime, sha256, sha1, md5)
                        if cache_out is not None:
                            cache_out.append(row)
                        else:
                            self._write_cache([row])
        except _TooBig:
            return res | {"status": "skipped", "reason": "too_large"}
        except PermissionError:
            return res | {"status": "skipped", "reason": "access_denied"}
        except OSError as e:                     # locked by another program, device error...
            return res | {"status": "skipped", "reason": "unreadable", "detail": str(e)[:200]}
        res.update(sha256=sha256, sha1=sha1, md5=md5)
        v = self._verdict(sha256, sha1, md5, head, opts.get("use_allowlist", True))
        if v:
            res["detections"].append(v | {"archive_member": None, "sha256": sha256, "md5": md5, "size": st.st_size})
        else:
            self._inspect(res, sha256, md5, path, st.st_size, data, path, opts)
        data = None
        if opts["archives"] and head.startswith(ARCHIVE_MAGIC) and st.st_size <= opts["archive_max_bytes"]:
            try:
                with open(path, "rb") as f:
                    self._scan_zip(f, "", 1, opts, res, checkpoint)
            except _Stop:
                raise
            except Exception as e:               # damaged / unsupported archive: the outer file was still checked
                res["archive_note"] = f"Archive could not be fully opened: {type(e).__name__}"
        inner = {d["threat_name"] for d in res["detections"] if d["archive_member"]}
        if inner:                       # Part 8: a stored (uncompressed) member also matches the container - report it once
            res["detections"] = [d for d in res["detections"]
                                 if d["archive_member"] or d["method"] != "yara" or d["threat_name"] not in inner]
        if res["detections"]:
            res["status"] = "infected"
        elif opts.get("cloud") and self.cloud is not None:            # Part 8: background online lookup
            try:
                self.cloud.submit(path, sha256, head, opts.get("origin", "scan"), st.st_size)
            except Exception as e:                                      # pragma: no cover
                log.debug("Cloud queue: %s", e)
        return res

    def _scan_zip(self, fileobj, prefix: str, depth: int, opts: dict, res: dict, checkpoint) -> None:
        with zipfile.ZipFile(fileobj) as z:
            budget = opts["archive_max_bytes"] * 4
            for i, info in enumerate(z.infolist()):
                if i >= MAX_ARCHIVE_MEMBERS:
                    res["archive_note"] = f"Only the first {MAX_ARCHIVE_MEMBERS} entries were checked"
                    break
                if info.is_dir():
                    continue
                name = prefix + info.filename
                if info.flag_bits & 0x1:
                    res.setdefault("encrypted_entries", []).append(name)
                    continue
                if info.file_size > opts["max_file_bytes"]:
                    continue
                if info.compress_size and info.file_size > 10 * 1024 * 1024 and \
                        info.file_size / info.compress_size > BOMB_RATIO:
                    res["archive_note"] = "Possible zip bomb - oversized entries were skipped"
                    continue
                budget -= info.file_size
                if budget < 0:
                    res["archive_note"] = "Archive is too large to unpack completely"
                    break
                if checkpoint:
                    checkpoint()
                insp = opts.get("insp") if opts.get("inspect") else None
                keep = bool(insp) and insp["archives"] and info.file_size <= insp["max_bytes"]
                data = None
                try:
                    with z.open(info) as m:
                        if keep:
                            data = m.read(opts["max_file_bytes"] + 1)
                            if len(data) > opts["max_file_bytes"]:
                                raise _TooBig()
                            sha256, sha1, md5 = (hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                                                 hashlib.md5(data).hexdigest())
                            head, nread = data[:PATTERN_HEAD_BYTES], len(data)
                        else:
                            sha256, sha1, md5, head, nread = self._hash_stream(m, opts["max_file_bytes"], checkpoint)
                except _TooBig:
                    continue
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError,
                        zipfile.LargeZipFile):
                    continue
                res["archive_entries"] += 1
                res["bytes_read"] += nread
                v = self._verdict(sha256, sha1, md5, head, opts.get("use_allowlist", True))
                if v:
                    res["detections"].append(v | {"archive_member": name, "sha256": sha256, "md5": md5, "size": nread})
                else:
                    self._inspect(res, sha256, md5, info.filename, nread, data, None, opts, member=name)
                if head.startswith(ARCHIVE_MAGIC) and depth < MAX_ARCHIVE_DEPTH and nread <= NESTED_ARCHIVE_MAX:
                    try:
                        with z.open(info) as m:
                            buf = io.BytesIO(m.read(NESTED_ARCHIVE_MAX + 1))
                        self._scan_zip(buf, name + " > ", depth + 1, opts, res, checkpoint)
                    except _Stop:
                        raise
                    except Exception:
                        pass

    def _write_cache(self, rows: list[tuple]) -> None:
        if not rows:
            return
        with self.db.tx() as c:
            c.executemany("INSERT OR REPLACE INTO file_hash_cache(path, size, mtime, sha256, sha1, md5) "
                          "VALUES (?,?,?,?,?,?)", rows)

    # ------------------------------------------------------------ detections
    def _record_detections(self, job_id: int | None, res: dict, auto_action: bool = True) -> list[dict]:
        """auto_action=False lets the caller (Part 7 real-time protection) apply its own policy."""
        out = []
        for d in res["detections"]:
            with self.db.tx() as c:
                old = [r["id"] for r in c.execute(
                    "SELECT id FROM scan_detections WHERE path=? AND COALESCE(archive_member,'')=? AND status='active'",
                    (res["path"], d["archive_member"] or "")).fetchall()]
                c.execute("UPDATE scan_detections SET status='superseded', status_changed_at=? WHERE path=? "
                          "AND COALESCE(archive_member,'')=? AND status='active'",
                          (_now(), res["path"], d["archive_member"] or ""))
                cur = c.execute(
                    "INSERT INTO scan_detections(job_id, path, archive_member, size, sha256, md5, threat_name, "
                    "severity, method, details) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (job_id, res["path"], d["archive_member"], d["size"], d["sha256"], d["md5"],
                     d["threat_name"], d["severity"], d["method"],
                     json.dumps(d["details"]) if d.get("details") else None))
                det_id = cur.lastrowid
            for o in old:
                threat_event(self.db, "superseded", o, detail=f"found again (detection {det_id})")
            how = {"yara": f"YARA rule {(d.get('details') or {}).get('rule', '')}".strip(),
                   "heuristic": f"heuristics (score {(d.get('details') or {}).get('score', '?')})",
                   "cloud": "online lookup"}.get(d["method"], f"{d['method']} match")
            threat_event(self.db, "detected", det_id, detail=f"found by {how}" +
                         (f" in job {job_id}" if job_id else ""))
            where = res["path"] + (f" > {d['archive_member']}" if d["archive_member"] else "")
            self.activity.record("threat", f"Threat found: {d['threat_name']}", where,
                                 severity=d["severity"], source="scanner")
            row = self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))
            self._emit("threat", job_id=job_id, detection=row)
            out.append(row)
        if out and auto_action and self.on_detections is not None:      # Part 6: auto-quarantine policy
            try:
                self.on_detections(out)
            except Exception as e:                                      # never break a scan over it
                log.warning("Automatic action failed: %s", e)
            out = [self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (r["id"],)) for r in out]
        return out

    def _resolve(self, path: str, by: str) -> int:
        ids = [r["id"] for r in self.db.fetchall("SELECT id FROM scan_detections WHERE path=? AND status='active'",
                                                 (path,))]
        for i in ids:
            self.db.execute("UPDATE scan_detections SET status='resolved', status_changed_at=?, status_by=? "
                            "WHERE id=? AND status='active'", (_now(), by, i))
            threat_event(self.db, "resolved", i, detail=by)
        return len(ids)

    def _resolve_clean(self, path: str) -> None:
        self._resolve(path, "rescan")

    def resolve_missing(self) -> int:
        """Active detections whose file has since disappeared -> resolved."""
        n = 0
        for r in self.db.fetchall("SELECT DISTINCT path FROM scan_detections WHERE status='active'"):
            if not os.path.exists(r["path"]):
                n += self._resolve(r["path"], "file removed")
        return n

    def detections(self, status: str = "active", job_id: int | None = None, limit: int = 100,
                   offset: int = 0) -> dict:
        where, params = [], []
        if status != "all":
            where.append("status=?"); params.append(status)
        if job_id is not None:
            where.append("job_id=?"); params.append(job_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM scan_detections {clause}", tuple(params))["n"]
        items = self.db.fetchall(f"SELECT * FROM scan_detections {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                 tuple(params) + (limit, offset))
        return {"total": total, "items": items}

    def dismiss(self, det_id: int, username: str) -> dict:
        row = self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))
        if not row:
            raise ScanError(404, "Detection not found")
        if row["status"] != "active":
            raise ScanError(409, f"Detection is already {row['status']}")
        self.db.execute("UPDATE scan_detections SET status='dismissed', status_changed_at=?, status_by=? WHERE id=?",
                        (_now(), username, det_id))
        threat_event(self.db, "dismissed", det_id, username=username)
        self.activity.record("threat", f"Threat dismissed: {row['threat_name']}", row["path"],
                             severity="info", source="scanner")
        return self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))

    # ------------------------------------------------------------ jobs: create / control
    def start(self, kind: str, username: str, paths: list[str] | None = None) -> dict:
        if kind not in KINDS:
            raise ScanError(422, "Unknown scan type")
        if self._closing:
            raise ScanError(503, "Engine is shutting down")
        if kind == "custom":
            if not paths:
                raise ScanError(422, "Choose at least one file or folder to scan")
            clean = []
            for p in paths:
                p = os.path.expandvars(os.path.expanduser(p.strip()))
                if not os.path.isabs(p):
                    raise ScanError(422, f"Use a full path: {p}")
                if not os.path.exists(p):
                    raise ScanError(404, f"Not found: {p}")
                clean.append(os.path.abspath(p))
            paths = list(dict.fromkeys(clean))
        with self._lock:
            dup = next((j for j in self._jobs.values() if j["kind"] == kind and kind != "custom"
                        and j["status"] in ACTIVE), None)
            if dup:
                raise ScanError(409, f"A {kind} scan is already {dup['status']} (job {dup['id']})")
            opts = self._options()
            cur = self.db.execute(
                "INSERT INTO scan_jobs(kind, status, targets, options, started_by) VALUES (?,?,?,?,?)",
                (kind, "queued", json.dumps(paths or []), json.dumps({k: v for k, v in opts.items()
                                                                       if k != "excluded_ext"}
                                                                      | {"excluded_ext": sorted(opts["excluded_ext"])}),
                 username))
            jid = cur.lastrowid
            job = {
                "id": jid, "kind": kind, "status": "queued", "phase": "queued", "paths": paths or [],
                "started_by": username, "created_at": _now(), "started_at": None, "finished_at": None,
                "files_total": 0, "files_found": 0, "files_scanned": 0, "files_skipped": 0, "archive_entries": 0,
                "bytes_scanned": 0, "threats_found": 0, "errors": 0, "current_path": None,
                "skipped_by_reason": {}, "targets": [], "message": None,
                "_opts": opts, "_run": threading.Event(), "_cancel": False, "_active": 0.0, "_scan_active": 0.0,
                "_t": None, "_persisted": 0.0,
            }
            job["_run"].set()
            self._jobs[jid] = job
        self._emit("job_queued", job=self.snapshot(job))
        self._dispatch()
        return self.snapshot(job)

    def _dispatch(self) -> None:
        with self._lock:
            if self._closing or any(j["status"] in ("running", "paused") for j in self._jobs.values()):
                return
            nxt = min((j for j in self._jobs.values() if j["status"] == "queued"), key=lambda j: j["id"], default=None)
            if not nxt:
                return
            nxt["status"] = "running"
            t = threading.Thread(target=self._run, args=(nxt,), name=f"scan-{nxt['id']}", daemon=True)
            self._threads[nxt["id"]] = t
        t.start()

    def _live(self, jid: int) -> dict:
        with self._lock:
            j = self._jobs.get(jid)
        if not j:
            if self.db.fetchone("SELECT id FROM scan_jobs WHERE id=?", (jid,)):
                raise ScanError(409, "This scan has already finished")
            raise ScanError(404, "Scan job not found")
        return j

    def pause(self, jid: int) -> dict:
        j = self._live(jid)
        if j["status"] != "running":
            raise ScanError(409, f"Only a running scan can be paused (this one is {j['status']})")
        j["_run"].clear()
        self._set_status(j, "paused")
        self._emit("job_paused", job=self.snapshot(j))
        return self.snapshot(j)

    def resume(self, jid: int) -> dict:
        j = self._live(jid)
        if j["status"] != "paused":
            raise ScanError(409, f"Only a paused scan can be resumed (this one is {j['status']})")
        self._set_status(j, "running")
        j["_run"].set()
        self._emit("job_resumed", job=self.snapshot(j))
        return self.snapshot(j)

    def cancel(self, jid: int) -> dict:
        j = self._live(jid)
        j["_cancel"] = True
        if j["status"] == "queued":
            with self._lock:
                self._jobs.pop(jid, None)
            j["status"], j["phase"], j["finished_at"] = "cancelled", "done", _now()
            j["message"] = "Cancelled before it started"
            self._persist(j, final=True)
            self._emit("job_finished", job=self.snapshot(j))
            return self.snapshot(j)
        j["_run"].set()                         # wake a paused worker so it can stop
        deadline = time.time() + 5
        while j["status"] in ACTIVE and time.time() < deadline:
            time.sleep(0.02)
        return self.snapshot(j)

    def _set_status(self, j: dict, status: str) -> None:
        j["status"] = status
        self._persist(j)

    # ------------------------------------------------------------ worker
    def _checkpoint_for(self, j: dict):
        def checkpoint():
            if j["_cancel"] or self._closing:
                raise _Stop()
            if not j["_run"].is_set():
                self._persist(j)
                paused_at = time.monotonic()
                while not j["_run"].wait(0.25):
                    if j["_cancel"] or self._closing:
                        raise _Stop()
                paused_for = time.monotonic() - paused_at          # paused time doesn't count
                j["_t"] += paused_for
                if j.get("_scan_start"):
                    j["_scan_start"] += paused_for
                if j["_cancel"] or self._closing:
                    raise _Stop()
            if time.monotonic() - j["_persisted"] > PERSIST_EVERY:
                self._persist(j)
        return checkpoint

    def _run(self, j: dict) -> None:
        cache_rows: list[tuple] = []
        cp = self._checkpoint_for(j)
        label = {"quick": "Quick scan", "full": "Full scan", "custom": "Custom scan"}[j["kind"]]
        j["started_at"] = _now()
        j["_t"] = time.monotonic()
        self._persist(j)
        self._emit("job_started", job=self.snapshot(j))
        self.activity.record("scan", f"{label} started", f"by {j['started_by']}", source="scanner")
        try:
            targets = self.resolve_targets(j["kind"], j["paths"])
            j["targets"] = [{"path": t["path"], "label": t["label"]} for t in targets[:200]]
            opts = j["_opts"]
            dedupe = j["kind"] != "full"

            # ---- phase 1: count files so progress can show a real percentage
            j["phase"] = "enumerating"
            seen = set() if dedupe else None
            for t in targets:
                for _ in self.iter_target(t, opts, seen, cp):
                    j["files_found"] += 1
                    if j["files_found"] % 500 == 0:
                        cp()
            j["files_total"] = j["files_found"]

            # ---- phase 2: scan
            j["phase"] = "scanning"
            j["_scan_start"] = time.monotonic()
            active_paths = {r["path"] for r in self.db.fetchall(
                "SELECT DISTINCT path FROM scan_detections WHERE status='active'")}
            seen = set() if dedupe else None
            for t in targets:
                for path in self.iter_target(t, opts, seen, cp):
                    cp()
                    j["current_path"] = path
                    r = self.scan_file(path, opts, cp, cache_rows)
                    if r["status"] == "skipped":
                        j["files_skipped"] += 1
                        j["skipped_by_reason"][r["reason"]] = j["skipped_by_reason"].get(r["reason"], 0) + 1
                    elif r["status"] == "error":
                        j["errors"] += 1
                    else:
                        j["files_scanned"] += 1
                        j["bytes_scanned"] += r["bytes_read"] or 0
                        j["archive_entries"] += r["archive_entries"]
                        if r["status"] == "infected":
                            j["threats_found"] += len(self._record_detections(j["id"], r))
                        elif path in active_paths:
                            self._resolve_clean(path)
                    if len(cache_rows) >= CACHE_FLUSH:
                        self._write_cache(cache_rows); cache_rows.clear()
                    if j["files_scanned"] + j["files_skipped"] + j["errors"] > j["files_total"]:
                        j["files_total"] = j["files_scanned"] + j["files_skipped"] + j["errors"]   # files added mid-scan
                    j["_scan_active"] = time.monotonic() - j["_scan_start"]
                    if self.per_file_delay:
                        time.sleep(self.per_file_delay)
            j["phase"] = "finalizing"
            self._write_cache(cache_rows); cache_rows.clear()
            self.resolve_missing()
            j["status"] = "completed"
            j["message"] = (f"{j['threats_found']} threat(s) found" if j["threats_found"]
                            else "No current threats")
        except _Stop:
            self._write_cache(cache_rows)
            j["status"] = "cancelled"
            j["message"] = "Engine shut down" if self._closing and not j["_cancel"] else "Cancelled by user"
            if self._closing and not j["_cancel"]:
                j["status"] = "interrupted"
        except Exception as e:                                # pragma: no cover - safety net
            log.exception("Scan job %s failed", j["id"])
            j["status"], j["message"] = "failed", f"{type(e).__name__}: {e}"[:300]
        finally:
            j["phase"], j["finished_at"], j["current_path"] = "done", _now(), None
            j["_active"] = time.monotonic() - j["_t"]
            try:
                self._persist(j, final=True)
                sev = "medium" if j["threats_found"] else "info"
                self.activity.record("scan", f"{label} {j['status']}",
                                     f"{j['files_scanned']:,} files scanned, {j['files_skipped']:,} skipped, "
                                     f"{j['threats_found']} threat(s) - {j['_active']:.0f} s",
                                     severity=sev, source="scanner")
            except Exception:                                 # DB already closed during shutdown
                pass
            self._emit("job_finished", job=self.snapshot(j))
            with self._lock:
                self._jobs.pop(j["id"], None)
                self._threads.pop(j["id"], None)
            self._dispatch()

    def _persist(self, j: dict, final: bool = False) -> None:
        j["_persisted"] = time.monotonic()
        dur = j["_active"] if final else (time.monotonic() - j["_t"] if j["_t"] else 0)
        msg = j["message"]
        if j["skipped_by_reason"]:
            msg = json.dumps({"message": j["message"], "skipped": j["skipped_by_reason"]})
        self.db.execute(
            "UPDATE scan_jobs SET status=?, started_at=?, finished_at=?, files_total=?, files_scanned=?, "
            "files_skipped=?, archive_entries=?, bytes_scanned=?, threats_found=?, errors=?, duration_seconds=?, "
            "message=?, targets=CASE WHEN ? != '[]' THEN ? ELSE targets END WHERE id=?",
            (j["status"], j["started_at"], j["finished_at"], j["files_total"] or j["files_found"], j["files_scanned"],
             j["files_skipped"], j["archive_entries"], j["bytes_scanned"], j["threats_found"], j["errors"],
             round(dur, 2), msg, json.dumps(j["targets"]), json.dumps(j["targets"]), j["id"]))

    # ------------------------------------------------------------ views
    @staticmethod
    def snapshot(j: dict) -> dict:
        processed = j["files_scanned"] + j["files_skipped"] + j["errors"]
        elapsed = (time.monotonic() - j["_t"]) if j["_t"] and j["status"] in ACTIVE else j["_active"]
        pct = None
        if j["phase"] == "scanning" and j["files_total"]:
            pct = round(min(99.9, processed * 100 / j["files_total"]), 1)
        elif j["phase"] == "enumerating":
            pct = 0.0
        elif j["status"] == "completed":
            pct = 100.0
        rate = processed / j["_scan_active"] if j["_scan_active"] > 0.5 else None
        eta = round((j["files_total"] - processed) / rate) if rate and j["phase"] == "scanning" else None
        return {
            "id": j["id"], "kind": j["kind"], "status": j["status"], "phase": j["phase"],
            "percent": pct, "files_total": j["files_total"], "files_found": j["files_found"],
            "files_scanned": j["files_scanned"], "files_skipped": j["files_skipped"], "errors": j["errors"],
            "archive_entries": j["archive_entries"], "bytes_scanned": j["bytes_scanned"],
            "mb_scanned": round(j["bytes_scanned"] / 1048576, 1), "threats_found": j["threats_found"],
            "current_path": j["current_path"], "elapsed_seconds": round(elapsed or 0, 1),
            "files_per_second": round(rate, 1) if rate else None,
            "mb_per_second": round(j["bytes_scanned"] / 1048576 / j["_scan_active"], 1) if j["_scan_active"] > 0.5 else None,
            "eta_seconds": eta, "skipped_by_reason": dict(j["skipped_by_reason"]),
            "started_by": j["started_by"], "created_at": j["created_at"], "started_at": j["started_at"],
            "finished_at": j["finished_at"], "message": j["message"], "targets": j["targets"],
            "paths": j["paths"],
        }

    def active(self) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [self.snapshot(j) for j in sorted(jobs, key=lambda j: j["id"])]

    @staticmethod
    def _row(r: dict) -> dict:
        r = dict(r)
        r["targets"] = json.loads(r["targets"] or "[]")
        r["options"] = json.loads(r["options"] or "{}")
        r["skipped_by_reason"] = {}
        if r["message"] and r["message"].startswith("{"):
            m = json.loads(r["message"])
            r["message"], r["skipped_by_reason"] = m.get("message"), m.get("skipped", {})
        r["mb_scanned"] = round(r["bytes_scanned"] / 1048576, 1)
        r["percent"] = 100.0 if r["status"] == "completed" else None
        return r

    def get(self, jid: int) -> dict:
        with self._lock:
            j = self._jobs.get(jid)
        if j:
            return self.snapshot(j)
        r = self.db.fetchone("SELECT * FROM scan_jobs WHERE id=?", (jid,))
        if not r:
            raise ScanError(404, "Scan job not found")
        return self._row(r)

    def history(self, limit: int = 20, kind: str | None = None) -> list[dict]:
        live = {j["id"]: self.snapshot(j) for j in list(self._jobs.values())}
        q = "SELECT * FROM scan_jobs" + (" WHERE kind=?" if kind else "") + " ORDER BY id DESC LIMIT ?"
        rows = self.db.fetchall(q, ((kind,) if kind else ()) + (limit,))
        return [live.get(r["id"]) or self._row(r) for r in rows]

    def delete_job(self, jid: int) -> int:
        with self._lock:
            if jid in self._jobs:
                raise ScanError(409, "Cancel the scan before deleting it")
        return self.db.execute("DELETE FROM scan_jobs WHERE id=?", (jid,)).rowcount

    def summary(self, days: int = 14) -> dict:
        last = {}
        for k in KINDS:
            r = self.db.fetchone("SELECT * FROM scan_jobs WHERE kind=? AND status='completed' ORDER BY id DESC LIMIT 1",
                                 (k,))
            last[k] = self._row(r) if r else None
        last_any = self.db.fetchone("SELECT * FROM scan_jobs WHERE status='completed' ORDER BY id DESC LIMIT 1")
        sev = {s: 0 for s in ("low", "medium", "high", "critical")}
        for r in self.db.fetchall("SELECT severity, COUNT(*) AS n FROM scan_detections WHERE status='active' "
                                  "GROUP BY severity"):
            sev[r["severity"]] = r["n"]
        by_day = self.db.fetchall(
            "SELECT substr(created_at,1,10) AS day, COUNT(*) AS scans, SUM(threats_found) AS threats, "
            "SUM(files_scanned) AS files FROM scan_jobs WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) "
            "GROUP BY day ORDER BY day", (f"-{days} days",))
        totals = self.db.fetchone("SELECT COUNT(*) AS scans, COALESCE(SUM(files_scanned),0) AS files, "
                                  "COALESCE(SUM(threats_found),0) AS threats FROM scan_jobs")
        active_threats = sum(sev.values())
        days_since = None
        if last_any and last_any["finished_at"]:
            try:
                t = datetime.fromisoformat(last_any["finished_at"].replace("Z", "+00:00"))
                days_since = (datetime.now(timezone.utc) - t).days
            except ValueError:
                pass
        if active_threats:
            status, text = "action_needed", f"{active_threats} threat(s) need your attention"
        elif last_any is None:
            status, text = "never_scanned", "No scan has been run yet - run a Quick scan"
        elif days_since is not None and days_since >= 7:
            status, text = "scan_overdue", f"Last scan was {days_since} days ago"
        else:
            status, text = "protected", "No current threats"
        by_method = {r["method"]: r["n"] for r in self.db.fetchall(
            "SELECT method, COUNT(*) AS n FROM scan_detections GROUP BY method")}
        return {
            "status": status, "status_text": text, "active_threats": active_threats,
            "detections_by_method": by_method,
            "active_by_severity": sev, "last_scan": self._row(last_any) if last_any else None,
            "days_since_last_scan": days_since, "last_by_kind": last, "running": self.active(),
            "totals": totals, "by_day": by_day, "signatures": self.malware.stats(),
            "cache_entries": self.db.fetchone("SELECT COUNT(*) AS n FROM file_hash_cache")["n"],
        }

    def self_test(self) -> dict:
        """Proves the engine works end-to-end without writing a test virus to disk
        (Windows Defender would grab it before we could)."""
        sha256, sha1, md5 = (hashlib.sha256(EICAR).hexdigest(), hashlib.sha1(EICAR).hexdigest(),
                             hashlib.md5(EICAR).hexdigest())
        by_hash = self._verdict(sha256, sha1, md5, b"", use_allowlist=False)
        by_pattern = self.malware.match_patterns(EICAR + b"\r\n")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("readme.txt", b"hello")
            z.writestr("eicar.com", EICAR)
        buf.seek(0)
        res = {"detections": [], "archive_entries": 0, "bytes_read": 0}
        self._scan_zip(buf, "", 1, self._options({"use_allowlist": False, "inspect": False, "cloud": False}),
                       res, None)
        clean = self._verdict(hashlib.sha256(b"clean").hexdigest(), hashlib.sha1(b"clean").hexdigest(),
                              hashlib.md5(b"clean").hexdigest(), b"clean", use_allowlist=False)
        checks = {"hash_lookup": bool(by_hash), "pattern_match": bool(by_pattern),
                  "archive_scan": any(d["archive_member"] == "eicar.com" for d in res["detections"]),
                  "clean_file_passes": clean is None}
        if self.inspector is not None:                                  # Part 8
            rt = self.inspector.self_test()
            checks["yara_rules"] = rt["checks"]["yara_match"]
            checks["heuristics"] = rt["checks"]["heuristic_double_extension"]
        return {"passed": all(checks.values()), "checks": checks,
                "signature_db": self.malware.stats()["enabled"], "engine": platform.python_implementation()}

    def clear_cache(self) -> int:
        return self.db.execute("DELETE FROM file_hash_cache").rowcount

    def shutdown(self, timeout: float = 5.0) -> None:
        self._closing = True
        with self._lock:
            jobs = list(self._jobs.values())
            threads = list(self._threads.values())
        for j in jobs:
            j["_run"].set()
        for t in threads:
            t.join(timeout)


class _TooBig(Exception):
    pass
