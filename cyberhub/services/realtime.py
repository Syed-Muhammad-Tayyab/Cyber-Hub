"""
Cyber Hub Backend - Real-time Protection (Part 7)
Developed by Syed Muhammad Tayyab

    OS file notifications (watchdog: ReadDirectoryChangesW / inotify / FSEvents)
        -> debounce queue (waits until the file stops changing)
        -> ScanManager.scan_file()            (same engine as Part 5 scans)
        -> threat? quarantine (Part 6) or alert, per `rtp_action`
        -> realtime_events row + WebSocket event + daily counters

Watched: Downloads, Desktop, Documents and the Startup folder(s) (setting
`rtp_watch_default_folders`), any folder the user adds (`rtp_watched_paths`)
and every USB / removable drive while it is plugged in.

A control thread runs every second: it notices USB drives being plugged in /
out (alert, quick root checks, optional automatic scan), keeps the watch list
in line with the settings, ends a "pause for N minutes" and watches for mass
file-change bursts (an early ransomware warning).

Honest limit: this is on-write scanning - a new file is checked as soon as it
has finished being written (usually well under 2 s). Blocking a file before
it can be opened at all needs a kernel minifilter driver, which a Python
engine can't ship; Part 8's heuristics and Part 17's scheduled scans add
more layers.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..database import Database
from ..logger import get_logger
from .drives import inspect_drive, list_removable_drives
from .platform_tools import IS_WINDOWS
from .scanner import norm

log = get_logger("realtime")

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_ERROR = None
except Exception as _e:                                              # pragma: no cover
    FileSystemEventHandler, Observer = object, None
    WATCHDOG_ERROR = f"watchdog is not installed ({_e}) - run: pip install watchdog"

# Browsers / download managers write to these first, then rename to the real name (we catch the rename).
PARTIAL_EXT = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".!ut", ".!qb", ".tmp.drivedownload")
# Part 13: Cyber Hub's own data-protection temp files (encrypting / decrypting / shredding) - never scanned or counted
OWN_TEMP_EXT = (".chpart", ".chdec", ".shred")
SUPPRESS_SECONDS = 600.0
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
BURST_WINDOW = 10.0
BURST_COOLDOWN = 300.0
RESTORE_GRACE_MIN = 15
MAX_PENDING = 20000
DIR_EXPAND_LIMIT = 2000


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- default folders
def _known_folder(guid: str) -> str | None:                         # pragma: no cover - Windows only
    """Real location of Downloads / Desktop / Documents even if the user moved them (SHGetKnownFolderPath)."""
    try:
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]
        u = uuid.UUID(guid)
        g = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
        p = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) != 0:
            return None
        val = p.value
        ctypes.windll.ole32.CoTaskMemFree(p)
        return val
    except Exception:
        return None


def default_folders() -> list[dict]:
    """{id, label, path, recursive}. CYBERHUB_RTP_DEFAULT_DIRS (os.pathsep list) overrides - tests / power users."""
    override = os.environ.get("CYBERHUB_RTP_DEFAULT_DIRS")
    if override:
        return [{"id": f"default{i}", "label": "Protected folder", "path": p, "recursive": True}
                for i, p in enumerate(x for x in override.split(os.pathsep) if x)]
    home = Path.home()
    out = []
    if IS_WINDOWS:                                                   # pragma: no cover
        env = os.environ
        out = [
            {"id": "downloads", "label": "Downloads", "recursive": True,
             "path": _known_folder("374DE290-123F-4565-9164-39C4925E467B") or str(home / "Downloads")},
            {"id": "desktop", "label": "Desktop", "recursive": True,
             "path": _known_folder("B4BFCC3A-DB2C-424C-B029-7FE99A87C641") or str(home / "Desktop")},
            {"id": "documents", "label": "Documents", "recursive": True,
             "path": _known_folder("FDD39AD0-238F-46AF-ADB4-6C85480369C7") or str(home / "Documents")},
            {"id": "startup", "label": "Your Startup folder", "recursive": False,
             "path": str(Path(env.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup")},
            {"id": "startup_all", "label": "All users Startup folder", "recursive": False,
             "path": str(Path(env.get("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp")},
        ]
    else:
        out = [
            {"id": "downloads", "label": "Downloads", "path": str(home / "Downloads"), "recursive": True},
            {"id": "desktop", "label": "Desktop", "path": str(home / "Desktop"), "recursive": True},
            {"id": "documents", "label": "Documents", "path": str(home / "Documents"), "recursive": True},
            {"id": "autostart", "label": "Autostart entries", "path": str(home / ".config" / "autostart"),
             "recursive": False},
        ]
    return out


# ---------------------------------------------------------------- watchdog glue
class _Handler(FileSystemEventHandler):
    def __init__(self, svc: "RealtimeService", root: str, origin: str):
        self.svc, self.root, self.origin = svc, root, origin

    def on_any_event(self, event):                                   # runs on the observer thread - keep it cheap
        kind = event.event_type
        if kind not in ("created", "modified", "moved", "closed"):
            return
        path = getattr(event, "dest_path", None) if kind == "moved" else event.src_path
        if not path:
            return
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        self.svc._on_fs_event(path, "moved" if kind == "moved" else ("modified" if kind in ("modified", "closed")
                                                                      else "created"),
                              self.root, self.origin, event.is_directory)


# ---------------------------------------------------------------- service
class RealtimeService:
    def __init__(self, db: Database, settings, activity, scanner, quarantine, data_dir: Path | None = None):
        self.db, self.settings, self.activity = db, settings, activity
        self.scanner, self.quarantine = scanner, quarantine
        self.data_dir = norm(str(data_dir)) if data_dir else None
        self.drive_lister = list_removable_drives        # test hook
        self.settle_seconds = 1.5                        # file must be quiet this long before it is scanned
        self.control_interval = 1.0
        self._lock = threading.RLock()
        self._reconcile_lock = threading.Lock()          # control thread and API calls both reconcile
        self._pending: dict[str, dict] = {}
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._observer = None
        self._watches: dict[str, dict] = {}              # norm(root) -> {path, origin, label, handle, recursive}
        self._drives: dict[str, dict] = {}               # mountpoint -> drive dict (connected now)
        self._snoozed_until: datetime | None = None
        self._state = "stopped"
        self._error: str | None = None
        self._events: deque = deque(maxlen=1000)
        self._seq = 0
        self._bursts: dict[str, deque] = {}
        self._burst_alerted: dict[str, float] = {}
        self._inserts_since_prune = 0
        self._suppressed: dict[str, tuple[float, bool]] = {}   # Part 13: norm(path) -> (until, still scan?)
        self.counters = {"files_scanned": 0, "threats": 0, "skipped": 0, "dropped": 0, "events_seen": 0}
        self.started_at: str | None = None
        self.last_threat: dict | None = None
        self.db.execute("UPDATE usb_devices SET connected=0")

    # ============================================================ events (WebSocket feed)
    def _emit(self, type_: str, **data) -> None:
        with self._lock:
            self._seq += 1
            self._events.append({"seq": self._seq, "type": type_, "ts": _now(), **data})

    def events_since(self, seq: int) -> tuple[int, list[dict]]:
        with self._lock:
            return self._seq, [e for e in self._events if e["seq"] > seq]

    # ============================================================ lifecycle
    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        self.started_at = _now()
        for name, fn in (("rtp-control", self._control_loop), ("rtp-worker", self._worker_loop)):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        self._reconcile()                                             # watches are live when start() returns
        log.info("Real-time protection service started")

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        for t in self._threads:
            t.join(timeout)
        self._threads = []
        self._stop_observer()
        self._state = "stopped"

    def _start_observer(self) -> bool:
        if self._observer is not None:
            return True
        if Observer is None:
            self._state, self._error = "unavailable", WATCHDOG_ERROR
            return False
        try:
            self._observer = Observer()
            self._observer.daemon = True
            self._observer.start()
            self._error = None
            return True
        except Exception as e:                                       # pragma: no cover
            self._observer, self._state, self._error = None, "error", f"File watcher failed to start: {e}"
            log.warning(self._error)
            return False

    def _stop_observer(self) -> None:
        obs, self._observer = self._observer, None
        with self._lock:
            for w in self._watches.values():
                w["handle"] = None
        if obs is not None:
            try:
                obs.unschedule_all()
                obs.stop()
                obs.join(3)
            except Exception:                                        # pragma: no cover
                pass
        with self._lock:
            self._pending.clear()

    # ============================================================ desired state
    def enabled(self) -> bool:
        return bool(self.settings.get("realtime_protection"))

    def snoozed(self) -> bool:
        return self._snoozed_until is not None and datetime.now(timezone.utc) < self._snoozed_until

    def desired_folders(self) -> list[dict]:
        out = []
        if self.settings.get("rtp_watch_default_folders"):
            out += [dict(f, origin="folder", kind="default") for f in default_folders()]
        for p in self.settings.get("rtp_watched_paths"):
            out.append({"id": "custom", "label": os.path.basename(p.rstrip("\\/")) or p, "path": p,
                        "recursive": True, "origin": "folder", "kind": "custom"})
        if self.settings.get("rtp_watch_removable"):
            for d in self._drives.values():
                out.append({"id": "usb", "label": d.get("label") or f"USB drive {d['mountpoint']}",
                            "path": d["mountpoint"], "recursive": True, "origin": "usb", "kind": "usb"})
        return out

    def _reconcile(self) -> None:
        """Make the running watches match settings + plugged-in drives."""
        with self._reconcile_lock:
            self._reconcile_locked()

    def _reconcile_locked(self) -> None:
        want_on = self.enabled() and not self.snoozed()
        if not want_on:
            if self._observer is not None:
                self._stop_observer()
            with self._lock:
                self._watches.clear()
            self._state = "snoozed" if self.enabled() else "off"
            return
        if not self._start_observer():
            return
        want = {}
        for f in self.desired_folders():
            n = norm(os.path.abspath(os.path.expandvars(os.path.expanduser(f["path"]))))
            if self.data_dir and (n == self.data_dir or n.startswith(self.data_dir.rstrip(os.sep) + os.sep)):
                continue
            want.setdefault(n, f | {"path": os.path.abspath(os.path.expandvars(os.path.expanduser(f["path"])))})
        with self._lock:
            for n in [k for k in self._watches if k not in want]:
                w = self._watches.pop(n)
                if w.get("handle") is not None:
                    try:
                        self._observer.unschedule(w["handle"])
                    except Exception:
                        pass
            for n, f in want.items():
                w = self._watches.get(n)
                if w is None:
                    w = self._watches[n] = f | {"handle": None, "status": "pending", "error": None}
                else:
                    w.update({k: f[k] for k in ("label", "origin", "kind", "id")})
                if w["handle"] is None:
                    if not os.path.isdir(w["path"]):
                        w["status"], w["error"] = "missing", "Folder not found"
                        continue
                    try:
                        w["handle"] = self._observer.schedule(_Handler(self, w["path"], w["origin"]), w["path"],
                                                              recursive=w["recursive"])
                        w["status"], w["error"] = "watching", None
                    except Exception as e:
                        w["status"], w["error"] = "error", str(e)[:200]
        self._state = "on"

    # ============================================================ file events
    # ============================================================ Part 13: our own data-protection writes
    def suppress(self, path: str, seconds: float = SUPPRESS_SECONDS, scan: bool = False) -> None:
        """Data Protection is about to write / remove `path` itself (encrypting a folder, shredding). Those events
        don't count towards the mass-change (ransomware) burst alert; with scan=False the file isn't scanned either
        (encrypted output). Decrypted files pass scan=True - they are still scanned on arrival."""
        now = time.monotonic()
        with self._lock:
            self._suppressed[norm(path)] = (now + seconds, scan)
            if len(self._suppressed) > 50000:
                for k in [k for k, v in self._suppressed.items() if v[0] < now]:
                    del self._suppressed[k]

    def _suppression(self, path: str) -> bool | None:
        """None = a normal event; True = ours but still scan; False = ours, skip."""
        if not self._suppressed:
            return None
        k = norm(path)
        with self._lock:
            v = self._suppressed.get(k)
            if v is None:
                return None
            if v[0] < time.monotonic():
                del self._suppressed[k]
                return None
            return v[1]

    def _ignored(self, path: str) -> bool:
        low = path.lower()
        base = os.path.basename(low)
        if low.endswith(OWN_TEMP_EXT):
            return True
        if low.endswith(PARTIAL_EXT) or base.startswith("~$") or base in ("desktop.ini", "thumbs.db", ".ds_store"):
            return True
        n = norm(path)
        if self.data_dir and (n == self.data_dir or n.startswith(self.data_dir.rstrip(os.sep) + os.sep)):
            return True
        return False

    def _on_fs_event(self, path: str, kind: str, root: str, origin: str, is_dir: bool) -> None:
        self.counters["events_seen"] += 1
        sup = self._suppression(path)
        if sup is None and not path.lower().endswith(OWN_TEMP_EXT):
            self._count_burst(root)
        if sup is False:
            return
        if is_dir:
            if kind in ("created", "moved"):                       # a folder moved / extracted in: check what's inside
                threading.Thread(target=self._expand_dir, args=(path, root, origin), daemon=True).start()
            return
        if self._ignored(path):
            return
        self._enqueue(path, kind, root, origin)

    def _expand_dir(self, folder: str, root: str, origin: str) -> None:
        n = 0
        for dirpath, _dirs, files in os.walk(folder):
            for f in files:
                p = os.path.join(dirpath, f)
                if not self._ignored(p):
                    self._enqueue(p, "moved", root, origin)
                    n += 1
                    if n >= DIR_EXPAND_LIMIT:
                        return

    def _enqueue(self, path: str, kind: str, root: str, origin: str) -> None:
        now = time.monotonic()
        with self._lock:
            item = self._pending.get(path)
            if item is None:
                if len(self._pending) >= MAX_PENDING:
                    self.counters["dropped"] += 1
                    return
                self._pending[path] = {"path": path, "event": kind, "root": root, "origin": origin,
                                       "first": now, "last": now, "size": None, "tries": 0}
            else:
                item["last"] = now
                if kind == "moved":
                    item["event"] = "moved"
        self._wake.set()

    def queue_depth(self) -> int:
        with self._lock:
            return len(self._pending)

    def _due(self) -> list[dict]:
        now = time.monotonic()
        out = []
        with self._lock:
            for p, it in list(self._pending.items()):
                if now - it["last"] >= self.settle_seconds:
                    out.append(self._pending.pop(p))
        return out

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(0.25)
            self._wake.clear()
            for it in self._due():
                if self._stop.is_set():
                    return
                try:
                    self._process(it)
                except Exception as e:                               # never let one file stop protection
                    log.warning("Real-time scan of %s failed: %s", it["path"], e)

    def _process(self, it: dict) -> None:
        path = it["path"]
        try:
            st = os.stat(path)
        except OSError:
            return                                                   # temp file already gone - nothing to do
        if not os.path.isfile(path):
            return
        if it["size"] != st.st_size and it["tries"] < 20:            # still growing -> wait again
            it.update(size=st.st_size, last=time.monotonic(), tries=it["tries"] + 1)
            with self._lock:
                self._pending.setdefault(path, it)
            return
        self.scan_now(path, it["event"], it["root"], it["origin"], retry=it)

    # ============================================================ scan one file
    def _opts(self) -> dict:
        o = self.scanner._options()
        o["max_file_bytes"] = self.settings.get("rtp_max_file_mb") * 1024 * 1024
        o["origin"] = "realtime"                                    # Part 8: new arrivals jump the cloud queue
        return o

    def scan_now(self, path: str, event: str = "created", root: str | None = None, origin: str = "folder",
                 retry: dict | None = None) -> dict:
        t0 = time.monotonic()
        res = self.scanner.scan_file(path, self._opts())
        if res["status"] == "skipped" and res["reason"] == "unreadable" and retry is not None and retry["tries"] < 5:
            retry.update(last=time.monotonic() + 1.0 * retry["tries"], tries=retry["tries"] + 1)  # locked: retry
            with self._lock:
                self._pending.setdefault(path, retry)
            return res
        if res["status"] == "skipped" and res["reason"] in ("missing", "not_a_file"):
            return res
        dur = int((time.monotonic() - t0) * 1000)
        zone = _download_source(path) if res["status"] == "infected" or IS_WINDOWS else None
        row = {"path": path, "event": event, "origin": origin, "watch_root": root, "status": res["status"],
               "reason": res.get("reason"), "threat_name": None, "severity": None, "detection_id": None,
               "quarantine_id": None, "action": "none", "size": res.get("size"), "sha256": res.get("sha256"),
               "downloaded_from": zone, "duration_ms": dur}
        if res["status"] == "infected":
            dets = self.scanner._record_detections(None, res, auto_action=False)
            worst = max(dets, key=lambda d: SEVERITY_ORDER.get(d["severity"], 0))
            row.update(threat_name=worst["threat_name"], severity=worst["severity"], detection_id=worst["id"])
            row.update(self._act(path, res, dets))
            self.counters["threats"] += 1
        elif res["status"] == "skipped":
            self.counters["skipped"] += 1
        else:
            self.scanner._resolve_clean(path)                         # an old active detection for this path is gone
        if res["status"] in ("clean", "infected"):
            self.counters["files_scanned"] += 1
        self._bump(scanned=1 if res["status"] in ("clean", "infected") else 0,
                   threats=1 if res["status"] == "infected" else 0, skipped=1 if res["status"] == "skipped" else 0)
        if res["status"] != "clean" or self.settings.get("rtp_log_clean_files"):
            row["id"] = self._save_event(row)
        if res["status"] == "infected":
            self.last_threat = row
            self._emit("threat_blocked" if row["action"] == "quarantined" else "threat_found", event=row)
        else:
            self._emit("file_scanned", event=row)
        return res | {"realtime": row}

    def _act(self, path: str, res: dict, dets: list[dict]) -> dict:
        """Apply rtp_action. Files the user restored from quarantine in the last minutes are only reported."""
        name = dets[0]["threat_name"]
        recent = self.db.fetchone(
            "SELECT id FROM quarantine_items WHERE status='restored' AND restored_path=? AND sha256=? "
            "AND status_changed_at >= ?", (path, res["sha256"],
                                          (datetime.now(timezone.utc) - timedelta(minutes=RESTORE_GRACE_MIN))
                                          .strftime("%Y-%m-%dT%H:%M:%S")))
        if all(d.get("method") == "heuristic" for d in dets) and not self.settings.get("heuristics_auto_quarantine"):
            self.activity.record("realtime", f"Suspicious new file: {name}",                 # Part 8
                                 f"{path} - flagged by heuristics, review it in Protection history",
                                 severity="medium", source="realtime")
            return {"action": "alerted", "reason": "heuristic_review"}
        if recent or self.settings.get("rtp_action") == "alert":
            why = "you restored it from quarantine recently" if recent else "real-time action is set to alert only"
            self.activity.record("realtime", f"Threat in a new file: {name}", f"{path} - not quarantined: {why}",
                                 severity="high", source="realtime")
            if not recent and self.quarantine is not None:
                self.quarantine.auto_action(dets)                   # still honour the Part 6 global policy
                if any(self.db.fetchone("SELECT status FROM scan_detections WHERE id=?", (d["id"],))["status"]
                       == "quarantined" for d in dets):
                    return {"action": "quarantined"}
            return {"action": "alerted", "reason": "restored_recently" if recent else "alert_only"}
        if self.quarantine is None:
            return {"action": "alerted"}
        from .quarantine import QuarantineError
        try:
            item = self.quarantine.quarantine_detection(dets[0]["id"], "realtime", source="realtime")
            self.activity.record("realtime", f"Threat blocked: {name}", f"{path} was quarantined on arrival",
                                 severity="high", source="realtime")
            return {"action": "quarantined", "quarantine_id": item["id"]}
        except QuarantineError as e:
            self.activity.record("realtime", f"Threat found but not quarantined: {name}", f"{path}: {e.message}",
                                 severity="critical", source="realtime")
            return {"action": "failed", "reason": e.message[:200]}

    def _save_event(self, r: dict) -> int:
        cur = self.db.execute(
            "INSERT INTO realtime_events(path, event, origin, watch_root, status, reason, threat_name, severity, "
            "detection_id, quarantine_id, action, size, sha256, downloaded_from, duration_ms) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["path"], r["event"], r["origin"], r["watch_root"], r["status"], r["reason"], r["threat_name"],
             r["severity"], r["detection_id"], r["quarantine_id"], r["action"], r["size"], r["sha256"],
             r["downloaded_from"], r["duration_ms"]))
        self._inserts_since_prune += 1
        if self._inserts_since_prune >= 200:
            self._inserts_since_prune = 0
            self.prune()
        return cur.lastrowid

    def prune(self) -> int:
        keep = self.settings.get("rtp_event_retention")
        return self.db.execute("DELETE FROM realtime_events WHERE id <= (SELECT id FROM realtime_events "
                               "ORDER BY id DESC LIMIT 1 OFFSET ?)", (keep,)).rowcount

    def _bump(self, **inc) -> None:
        cols = [k for k, v in inc.items() if v]
        if not cols:
            return
        names = {"scanned": "files_scanned", "threats": "threats", "skipped": "skipped",
                 "usb": "usb_inserts", "bursts": "bursts"}
        sets = ", ".join(f"{names[k]}={names[k]}+{int(inc[k])}" for k in cols)
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO realtime_daily(day) VALUES (?)", (_day(),))
            c.execute(f"UPDATE realtime_daily SET {sets} WHERE day=?", (_day(),))

    # ============================================================ mass-change (ransomware) warning
    def _count_burst(self, root: str) -> None:
        limit = self.settings.get("rtp_burst_threshold")
        if not limit:
            return
        now = time.monotonic()
        with self._lock:
            dq = self._bursts.setdefault(root, deque())
            dq.append(now)
            while dq and now - dq[0] > BURST_WINDOW:
                dq.popleft()
            n = len(dq)
            if n < limit or now - self._burst_alerted.get(root, -1e9) < BURST_COOLDOWN:
                return
            self._burst_alerted[root] = now
        self.activity.record("realtime", "Unusual burst of file changes",
                             f"{n} changes in {int(BURST_WINDOW)} s in {root} - normal for a big copy or unzip, "
                             "but also how ransomware behaves. Check what is running.", severity="high",
                             source="realtime")
        self._bump(bursts=1)
        self._emit("burst", folder=root, changes=n, window_seconds=BURST_WINDOW)

    # ============================================================ control loop: USB + settings + snooze
    def _control_loop(self) -> None:
        last_reconcile = 0.0
        while not self._stop.is_set():
            try:
                changed = self.poll_drives()
                if self._snoozed_until is not None and not self.snoozed():
                    self._snoozed_until = None
                    self.activity.record("realtime", "Real-time protection resumed", "pause ended",
                                         source="realtime")
                    self._emit("protection", state="on")
                    changed = True
                if changed or time.monotonic() - last_reconcile > 5:
                    self._reconcile()
                    last_reconcile = time.monotonic()
            except Exception as e:                                   # pragma: no cover
                log.warning("Real-time control loop error: %s", e)
            self._stop.wait(self.control_interval)

    def poll_drives(self) -> bool:
        """Compare plugged-in removable drives with the last poll. Returns True if anything changed."""
        now = {d["mountpoint"]: d for d in self.drive_lister()}
        added = [d for m, d in now.items() if m not in self._drives]
        removed = [d for m, d in self._drives.items() if m not in now]
        self._drives = now
        for d in added:
            self._on_insert(d)
        for d in removed:
            self._on_remove(d)
        return bool(added or removed)

    def _on_insert(self, d: dict) -> None:
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO usb_devices(device_key) VALUES (?)", (d["device_key"],))
            c.execute("UPDATE usb_devices SET label=?, serial=?, model=COALESCE(?, model), bus=?, fstype=?, "
                      "total_bytes=?, last_seen=?, last_mount=?, insert_count=insert_count+1, connected=1 "
                      "WHERE device_key=?", (d.get("label"), d.get("serial"), d.get("model"), d.get("bus"),
                                             d.get("fstype"), d.get("total_bytes"), _now(), d["mountpoint"],
                                             d["device_key"]))
        dev = self.db.fetchone("SELECT * FROM usb_devices WHERE device_key=?", (d["device_key"],))
        d["id"] = dev["id"]
        warnings = inspect_drive(d["mountpoint"])
        self.db.execute("UPDATE usb_devices SET warnings=? WHERE id=?", (json.dumps(warnings), dev["id"]))
        self._bump(usb=1)
        name = d.get("label") or d.get("model") or "USB drive"
        new = dev["insert_count"] == 1
        sev = max((w["severity"] for w in warnings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
        if self.settings.get("rtp_usb_alerts") or warnings:
            self.activity.record("device", f"USB drive connected: {name}",
                                 f"{d['mountpoint']} ({_size(d.get('total_bytes'))}, {d.get('fstype') or '?'})"
                                 + (" - first time on this PC" if new else "")
                                 + ("".join(f" | {w['title']}" for w in warnings)),
                                 severity=sev if warnings else ("low" if new else "info"), source="realtime")
        scan_job, mode = None, self.settings.get("rtp_usb_scan")
        if mode == "auto" and not dev["trusted"] and self.enabled():
            scan_job = self.scan_device(dev["id"], "realtime", _quiet=True)
        self._emit("usb_inserted", device=self.device(dev["id"]), warnings=warnings, first_time=new,
                   scan_job=scan_job, suggest_scan=(mode == "notify" and not dev["trusted"]))

    def _on_remove(self, d: dict) -> None:
        dev = self.db.fetchone("SELECT * FROM usb_devices WHERE device_key=?", (d["device_key"],))
        self.db.execute("UPDATE usb_devices SET connected=0, last_seen=? WHERE device_key=?", (_now(), d["device_key"]))
        if dev and dev["last_scan_job"]:
            try:
                j = self.scanner.get(dev["last_scan_job"])
                if j["status"] in ("queued", "running", "paused"):
                    self.scanner.cancel(j["id"])
            except Exception:
                pass
        with self._lock:                                              # forget queued files from that drive
            for p in [p for p in self._pending if norm(p).startswith(norm(d["mountpoint"]))]:
                self._pending.pop(p, None)
        name = d.get("label") or d.get("model") or "USB drive"
        if self.settings.get("rtp_usb_alerts"):
            self.activity.record("device", f"USB drive removed: {name}", d["mountpoint"], source="realtime")
        self._emit("usb_removed", device=self.device(dev["id"]) if dev else d)

    # ============================================================ USB devices API
    def device(self, dev_id: int) -> dict | None:
        r = self.db.fetchone("SELECT * FROM usb_devices WHERE id=?", (dev_id,))
        if not r:
            return None
        r["trusted"], r["connected"] = bool(r["trusted"]), bool(r["connected"])
        r["warnings"] = json.loads(r["warnings"]) if r["warnings"] else []
        live = next((d for d in self._drives.values() if d["device_key"] == r["device_key"]), None)
        r["mountpoint"] = live["mountpoint"] if live else None
        if r["connected"] and not live:                               # stale flag after a crash
            r["connected"] = False
        return r

    def devices(self, connected_only: bool = False) -> list[dict]:
        ids = [r["id"] for r in self.db.fetchall("SELECT id FROM usb_devices ORDER BY connected DESC, last_seen DESC")]
        out = [self.device(i) for i in ids]
        return [d for d in out if d and (d["connected"] or not connected_only)]

    def set_trusted(self, dev_id: int, trusted: bool, username: str) -> dict:
        if not self.device(dev_id):
            raise RealtimeError(404, "Device not found")
        self.db.execute("UPDATE usb_devices SET trusted=? WHERE id=?", (int(trusted), dev_id))
        d = self.device(dev_id)
        self.activity.record("device", f"USB drive {'trusted' if trusted else 'no longer trusted'}: "
                                       f"{d['label'] or d['model'] or d['device_key']}", f"by {username}",
                             severity="low" if trusted else "info", source="realtime")
        return d

    def forget(self, dev_id: int) -> int:
        d = self.device(dev_id)
        if not d:
            raise RealtimeError(404, "Device not found")
        if d["connected"]:
            raise RealtimeError(409, "Unplug the drive before removing it from the list")
        return self.db.execute("DELETE FROM usb_devices WHERE id=?", (dev_id,)).rowcount

    def scan_device(self, dev_id: int, username: str, _quiet: bool = False) -> dict | None:
        d = self.device(dev_id)
        if not d:
            raise RealtimeError(404, "Device not found")
        if not d["mountpoint"]:
            raise RealtimeError(409, "That drive isn't plugged in")
        from .scanner import ScanError
        try:
            job = self.scanner.start("custom", username, [d["mountpoint"]])
        except ScanError as e:
            if _quiet:
                log.warning("Automatic USB scan failed: %s", e.message)
                return None
            raise RealtimeError(e.status, e.message)
        self.db.execute("UPDATE usb_devices SET last_scan_job=? WHERE id=?", (job["id"], dev_id))
        return job

    # ============================================================ control API
    def pause(self, minutes: int, username: str) -> dict:
        self._snoozed_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        self.activity.record("realtime", "Real-time protection paused", f"for {minutes} min by {username}",
                             severity="medium", source="realtime")
        self._reconcile()
        self._emit("protection", state="snoozed", until=self._snoozed_until.isoformat())
        return self.status()

    def resume(self, username: str) -> dict:
        was = self.snoozed()
        self._snoozed_until = None
        if was:
            self.activity.record("realtime", "Real-time protection resumed", f"by {username}", source="realtime")
        self._reconcile()
        self._emit("protection", state=self._state)
        return self.status()

    def set_enabled(self, on: bool, username: str) -> dict:
        self.settings.update({"realtime_protection": on})
        if on:
            self._snoozed_until = None
        self.activity.record("realtime", f"Real-time protection turned {'on' if on else 'off'}", f"by {username}",
                             severity="info" if on else "high", source="realtime")
        self._reconcile()
        self._emit("protection", state=self._state)
        return self.status()

    def add_folder(self, path: str) -> list[str]:
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(path.strip())))
        if not os.path.isdir(p):
            raise RealtimeError(404, "Folder not found")
        if self.data_dir and norm(p).startswith(self.data_dir):
            raise RealtimeError(422, "That is Cyber Hub's own data folder")
        cur = self.settings.get("rtp_watched_paths")
        if any(norm(x) == norm(p) for x in cur):
            raise RealtimeError(409, "That folder is already protected")
        self.settings.update({"rtp_watched_paths": cur + [p]})
        self._reconcile()
        return self.settings.get("rtp_watched_paths")

    def remove_folder(self, path: str) -> list[str]:
        cur = self.settings.get("rtp_watched_paths")
        n = norm(os.path.abspath(os.path.expandvars(os.path.expanduser(path.strip()))))
        new = [x for x in cur if norm(x) != n]
        if len(new) == len(cur):
            raise RealtimeError(404, "That folder isn't in your protected list")
        self.settings.update({"rtp_watched_paths": new})
        self._reconcile()
        return new

    # ============================================================ read API
    def folders(self) -> list[dict]:
        with self._lock:
            live = {n: dict(w) for n, w in self._watches.items()}
        out, seen = [], set()
        for f in self.desired_folders():
            n = norm(os.path.abspath(os.path.expandvars(os.path.expanduser(f["path"]))))
            if n in seen:
                continue
            seen.add(n)
            w = live.get(n, {})
            status = w.get("status") or ("off" if self._state in ("off", "snoozed") else
                                         ("missing" if not os.path.isdir(f["path"]) else "pending"))
            if self._state in ("off", "snoozed"):
                status = self._state
            out.append({"id": f["id"], "kind": f["kind"], "label": f["label"], "path": f["path"],
                        "recursive": f["recursive"], "origin": f["origin"], "status": status,
                        "error": w.get("error")})
        return out

    def status(self) -> dict:
        folders = self.folders()
        state = self._state
        if state == "on" and not any(f["status"] == "watching" for f in folders):
            state = "on_no_folders"
        return {
            "enabled": self.enabled(),
            "state": state,                                         # on | on_no_folders | snoozed | off | unavailable | error | stopped
            "protected": state == "on",
            "snoozed_until": self._snoozed_until.isoformat() if self.snoozed() else None,
            "error": self._error,
            "engine": "watchdog" if Observer is not None else None,
            "started_at": self.started_at,
            "folders": folders,
            "watching": sum(1 for f in folders if f["status"] == "watching"),
            "usb_connected": self.devices(connected_only=True),
            "queue": self.queue_depth(),
            "counters": dict(self.counters),
            "last_threat": self.last_threat,
            "settings": {k: self.settings.get(k) for k in (
                "rtp_action", "rtp_max_file_mb", "rtp_watch_default_folders", "rtp_watch_removable",
                "rtp_usb_alerts", "rtp_usb_scan", "rtp_burst_threshold", "rtp_log_clean_files")},
        }

    def events(self, status: str | None = None, origin: str | None = None, limit: int = 100,
               offset: int = 0) -> dict:
        where, params = [], []
        if status:
            where.append("status=?"); params.append(status)
        if origin:
            where.append("origin=?"); params.append(origin)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM realtime_events {clause}", tuple(params))["n"]
        items = self.db.fetchall(f"SELECT * FROM realtime_events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                 tuple(params) + (limit, offset))
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    def clear_events(self) -> int:
        return self.db.execute("DELETE FROM realtime_events").rowcount

    def summary(self, days: int = 14) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        rows = {r["day"]: r for r in self.db.fetchall("SELECT * FROM realtime_daily WHERE day >= ?", (since,))}
        series = []
        for i in range(days):
            day = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
            r = rows.get(day, {})
            series.append({"day": day, **{k: r.get(k, 0) for k in
                                         ("files_scanned", "threats", "skipped", "usb_inserts", "bursts")}})
        totals = {k: sum(s[k] for s in series) for k in ("files_scanned", "threats", "skipped", "usb_inserts", "bursts")}
        top = self.db.fetchall("SELECT threat_name, severity, COUNT(*) AS n FROM realtime_events WHERE status='infected' "
                               "AND ts >= ? GROUP BY threat_name ORDER BY n DESC LIMIT 10", (since,))
        by_action = self.db.fetchall("SELECT action, COUNT(*) AS n FROM realtime_events WHERE status='infected' "
                                     "AND ts >= ? GROUP BY action", (since,))
        by_folder = self.db.fetchall("SELECT watch_root, COUNT(*) AS n, SUM(status='infected') AS threats "
                                     "FROM realtime_events WHERE ts >= ? GROUP BY watch_root ORDER BY n DESC LIMIT 10",
                                     (since,))
        return {"days": days, "by_day": series, "totals": totals, "top_threats": top,
                "threats_by_action": {r["action"]: r["n"] for r in by_action}, "by_folder": by_folder,
                "state": self.status()["state"], "usb_known": len(self.devices()),
                "usb_connected": len(self.devices(connected_only=True))}

    def self_test(self, timeout: float = 8.0) -> dict:
        """Proves the OS is delivering file notifications: watches a scratch folder, writes a harmless
        file and measures how long the event takes. (Use the EICAR file in Downloads for a full test.)"""
        if Observer is None:
            return {"ok": False, "error": WATCHDOG_ERROR}
        base = Path(self.data_dir or Path.home()) / "rtp-selftest"
        base.mkdir(parents=True, exist_ok=True)
        got = threading.Event()

        class H(FileSystemEventHandler):
            def on_any_event(self, e):
                if not e.is_directory and os.path.basename(getattr(e, "src_path", "")) == "probe.txt":
                    got.set()
        obs = Observer()
        obs.schedule(H(), str(base), recursive=False)
        obs.start()
        try:
            time.sleep(0.2)
            t0 = time.monotonic()
            (base / "probe.txt").write_text("Cyber Hub real-time self-test - harmless")
            ok = got.wait(timeout)
            latency = int((time.monotonic() - t0) * 1000)
        finally:
            obs.stop()
            obs.join(3)
            try:
                (base / "probe.txt").unlink()
                base.rmdir()
            except OSError:
                pass
        eng = self.scanner.self_test()
        return {"ok": ok and eng.get("passed", False), "file_events": ok, "latency_ms": latency if ok else None,
                "scan_engine": eng, "state": self.status()["state"],
                "tip": "For an end-to-end test, save the EICAR test file into a protected folder."}


class RealtimeError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _size(n: int | None) -> str:
    if not n:
        return "? GB"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return "?"


def _download_source(path: str) -> str | None:
    """HostUrl / ReferrerUrl from Windows 'Mark of the Web' - where a downloaded file came from."""
    if not IS_WINDOWS:
        return None
    try:                                                             # pragma: no cover
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            txt = f.read(4096)
    except OSError:
        return None
    vals = dict(l.split("=", 1) for l in txt.splitlines() if "=" in l)  # pragma: no cover
    return (vals.get("HostUrl") or vals.get("ReferrerUrl") or None)    # pragma: no cover

