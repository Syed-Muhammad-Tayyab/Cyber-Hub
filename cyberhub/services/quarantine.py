"""
Cyber Hub Backend - Quarantine & Threat History (Part 6)
Developed by Syed Muhammad Tayyab

Quarantine = take a threat out of reach without destroying it:

    1. stop any program running from the file (protected processes are never touched)
    2. encrypt it into the vault (vault.py: AES-256-GCM, per-item key) and verify it was written
    3. delete the original (if Windows has it locked: schedule removal at next restart)
    4. link every active detection of that file to the vault item + write the timeline

Restore puts the exact bytes back (SHA-256 verified), with the original
modified time, permissions and Windows "Mark of the Web", optionally adding the
file to the allowed list so future scans stop reporting it. Delete destroys the
item's key and file. Items expire after `quarantine_retention_days` and the
oldest go first when the vault passes `quarantine_max_mb`.

ThreatHistory reads scan_detections + quarantine_items + threat_events and
feeds the "Protection history" page, its charts and the CSV export.
"""
from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

from ..database import Database
from ..logger import get_logger
from .allowlist import AllowList, threat_event
from .malware_db import PATTERN_HEAD_BYTES
from .platform_tools import IS_WINDOWS
from .vault import Vault, VaultError

log = get_logger("quarantine")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DETECTION_STATES = ("active", "quarantined", "restored", "removed", "allowed", "dismissed", "resolved", "superseded")
ITEM_STATES = ("quarantined", "restored", "deleted", "missing")
RESCAN_IN_MEMORY = 32 * 1024 * 1024
_PUBLIC = ("id", "status", "original_path", "file_name", "size", "sha256", "md5", "mtime", "threat_name",
           "severity", "detection_id", "source", "original_state", "stored_size", "note", "quarantined_by",
           "quarantined_at", "status_changed_at", "status_by", "restored_path")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


def _inside(path_n: str, folder_n: str) -> bool:
    return path_n == folder_n or path_n.startswith(folder_n.rstrip(os.sep) + os.sep)


class QuarantineError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ====================================================================== platform bits
def system_dirs() -> list[str]:
    """Folders whose files need force=true (admin) to quarantine - removing them can break the OS."""
    if IS_WINDOWS:                                                  # pragma: no cover
        w = os.environ.get("SystemRoot", r"C:\Windows")
        return [norm(os.path.join(w, d)) for d in ("System32", "SysWOW64", "WinSxS", "Boot", "SystemApps")]
    return [norm(d) for d in ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib",
                              "/usr/lib64", "/boot", "/etc")]


def _read_zone(path: str) -> str | None:
    """Windows 'Mark of the Web' (Zone.Identifier stream: where a download came from)."""
    if not IS_WINDOWS:
        return None
    try:                                                            # pragma: no cover
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            return f.read(4096)
    except OSError:
        return None


def _write_zone(path: str, text: str | None) -> None:
    if not (IS_WINDOWS and text):
        return
    try:                                                            # pragma: no cover
        with open(path + ":Zone.Identifier", "w", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        pass


def _delete_on_reboot(path: str) -> bool:                           # pragma: no cover - Windows only
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        return bool(ctypes.windll.kernel32.MoveFileExW(ctypes.c_wchar_p(path), None, MOVEFILE_DELAY_UNTIL_REBOOT))
    except Exception:
        return False


def _free_name(path: str) -> str:
    """'file.exe' -> 'file (restored).exe' -> 'file (restored 2).exe' ..."""
    base, ext = os.path.splitext(path)
    cand, i = f"{base} (restored){ext}", 2
    while os.path.exists(cand):
        cand, i = f"{base} (restored {i}){ext}", i + 1
    return cand


# ====================================================================== quarantine
class QuarantineService:
    def __init__(self, db: Database, vault: Vault, allow: AllowList, settings, activity, scanner=None,
                 processes=None, data_dir: Path | None = None):
        self.db, self.vault, self.allow, self.settings, self.activity = db, vault, allow, settings, activity
        self.scanner, self.processes = scanner, processes
        self.data_dir = norm(str(data_dir)) if data_dir else None
        self.app_dir = norm(str(Path(__file__).resolve().parents[2]))

    # ------------------------------------------------------------ helpers
    def _emit(self, type_: str, **data) -> None:
        if self.scanner is not None:                                # shows up on the /api/scan/stream feed
            self.scanner._emit(type_, **data)

    @staticmethod
    def public(row: dict | None) -> dict | None:
        if row is None:
            return None
        out = {k: row.get(k) for k in _PUBLIC}
        out["mark_of_the_web"] = bool(row.get("zone_identifier"))
        out["can_restore"] = row["status"] == "quarantined"
        return out

    def _row(self, qid: str) -> dict:
        r = self.db.fetchone("SELECT * FROM quarantine_items WHERE id=?", (qid,))
        if not r:
            raise QuarantineError(404, "Quarantine item not found")
        return r

    def _guard(self, path_n: str, force: bool) -> None:
        if self.data_dir and _inside(path_n, self.data_dir):
            raise QuarantineError(403, "That file belongs to Cyber Hub's own data folder")
        if _inside(path_n, self.app_dir):
            raise QuarantineError(403, "That file is part of the Cyber Hub program")
        crit = system_dirs()
        if IS_WINDOWS:                                              # pragma: no cover
            windir = norm(os.environ.get("SystemRoot", r"C:\Windows"))
            if os.path.dirname(path_n) == windir:
                crit.append(path_n)
        if not force and any(_inside(path_n, d) for d in crit):
            raise QuarantineError(409, "This is an operating-system file - removing it could stop the PC "
                                       "from working. An administrator can still do it with force=true")

    def _running(self, path: str) -> list[psutil.Process]:
        n, out = norm(path), []
        for p in psutil.process_iter(["exe"]):
            exe = p.info.get("exe")
            if exe and norm(exe) == n:
                out.append(p)
        return out

    def _stop(self, procs: list[psutil.Process]) -> list[dict]:
        stopped = []
        for p in procs:
            try:
                name = p.name()
            except psutil.Error:
                continue
            if self.processes is not None:
                reason = self.processes.protection(p.pid, name, None)
                if reason:
                    raise QuarantineError(403, f"Can't stop {name} (PID {p.pid}): {reason}")
        for p in procs:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                raise QuarantineError(403, f"Access denied stopping PID {p.pid} - run Cyber Hub as administrator")
        gone, alive = psutil.wait_procs(procs, timeout=3)
        for p in alive:
            try:
                p.kill()
            except psutil.Error:
                pass
        gone2, alive2 = psutil.wait_procs(alive, timeout=2)
        for p in gone + gone2:
            stopped.append({"pid": p.pid})
        if alive2:
            raise QuarantineError(423, f"{len(alive2)} program(s) using the file would not stop")
        return stopped

    def _remove_original(self, path: str) -> str:
        attempts = 5 if IS_WINDOWS else 1
        last: OSError | None = None
        for i in range(attempts):
            try:
                os.remove(path)
                return "removed"
            except FileNotFoundError:
                return "removed"
            except OSError as e:
                last = e
                try:
                    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)   # clears Windows read-only attribute
                except OSError:
                    pass
                if i + 1 < attempts:
                    time.sleep(0.2)                                 # a just-stopped program may still hold it
        if IS_WINDOWS and _delete_on_reboot(path):                  # pragma: no cover
            return "pending_reboot"
        if isinstance(last, PermissionError):
            raise QuarantineError(403, "Access denied removing the file - run Cyber Hub as administrator")
        raise QuarantineError(423, f"The file is in use and can't be removed ({last})")

    # ------------------------------------------------------------ quarantine
    def _quarantine(self, path: str, username: str, threat_name: str, severity: str, source: str,
                    detection: dict | None = None, kill: bool | None = None, force: bool = False,
                    note: str | None = None) -> dict:
        if not self.vault.available:
            raise QuarantineError(503, f"Quarantine vault unavailable: {self.vault.key_error}")
        p = os.path.abspath(path)
        self._guard(norm(p), force)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            raise QuarantineError(404, "File not found")
        except OSError as e:
            raise QuarantineError(403, f"Can't read the file: {e}")
        if stat.S_ISLNK(st.st_mode):
            raise QuarantineError(422, "That is a link / shortcut to another file - quarantine the target instead")
        if not stat.S_ISREG(st.st_mode):
            raise QuarantineError(422, "Only files can be quarantined")
        cap = self.settings.get("quarantine_max_mb") * 1024 * 1024
        if st.st_size > cap:
            raise QuarantineError(413, "File is bigger than the whole quarantine size limit")

        stopped = []
        kill = self.settings.get("quarantine_kill_processes") if kill is None else kill
        running = self._running(p)
        if running and kill:
            stopped = self._stop(running)

        qid, key = secrets.token_hex(16), secrets.token_bytes(32)
        zone = _read_zone(p)
        try:
            enc = self.vault.encrypt_file(p, qid, key)
        except PermissionError:
            raise QuarantineError(403, "Access denied reading the file - run Cyber Hub as administrator")
        except OSError as e:
            raise QuarantineError(423, f"The file is locked by another program ({e})")
        notes = [note] if note else []
        if detection and not detection.get("archive_member") and detection.get("sha256") \
                and detection["sha256"] != enc["sha256"]:
            notes.append("File changed since it was detected")
        self.db.execute(
            "INSERT INTO quarantine_items(id, original_path, file_name, size, sha256, md5, mtime, atime, mode, "
            "zone_identifier, threat_name, severity, detection_id, source, original_state, stored_size, wrapped_key, "
            "note, quarantined_by, quarantined_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (qid, p, os.path.basename(p), enc["size"], enc["sha256"], enc["md5"], st.st_mtime, st.st_atime,
             stat.S_IMODE(st.st_mode), zone, threat_name, severity, detection["id"] if detection else None, source,
             "removing", enc["stored_size"], self.vault.wrap_key(key, qid), "; ".join(notes) or None, username, _now()))
        try:
            state = self._remove_original(p)
        except QuarantineError:
            self.vault.remove(qid)
            self.db.execute("DELETE FROM quarantine_items WHERE id=?", (qid,))
            raise
        self.db.execute("UPDATE quarantine_items SET original_state=? WHERE id=?", (state, qid))

        # every active detection of this file (incl. ones inside it, if it's an archive)
        paths = {p, detection["path"]} if detection else {p}
        dets = []
        for dp in paths:
            dets += self.db.fetchall("SELECT id FROM scan_detections WHERE path=? AND status='active'", (dp,))
        for d in dets:
            self.db.execute("UPDATE scan_detections SET status='quarantined', quarantine_id=?, status_changed_at=?, "
                            "status_by=? WHERE id=?", (qid, _now(), username, d["id"]))
            threat_event(self.db, "quarantined", d["id"], qid, username,
                         "automatic" if source == "auto" else None)
        if not dets:
            threat_event(self.db, "quarantined", None, qid, username, f"{source}: {p}")
        extra = " (removal finishes after restart)" if state == "pending_reboot" else ""
        self.activity.record("threat", f"Quarantined: {threat_name}", p + extra,
                             severity="low", source="quarantine")
        item = self.public(self._row(qid)) | {"stopped_processes": stopped, "detections": [d["id"] for d in dets]}
        self._emit("quarantined", item=item)
        self.enforce_limits(keep=qid)
        return item

    def quarantine_detection(self, det_id: int, username: str, kill: bool | None = None, force: bool = False,
                             source: str = "detection") -> dict:
        d = self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))
        if not d:
            raise QuarantineError(404, "Detection not found")
        if d["status"] != "active":
            raise QuarantineError(409, f"This threat is already {d['status']}")
        if not os.path.lexists(d["path"]):
            if self.scanner is not None:
                self.scanner._resolve(d["path"], "file removed")
            raise QuarantineError(410, "The file no longer exists - the threat was marked resolved")
        return self._quarantine(d["path"], username, d["threat_name"], d["severity"], source, d, kill, force)

    def quarantine_path(self, path: str, username: str, threat_name: str | None = None, kill: bool | None = None,
                        force: bool = False, note: str | None = None) -> dict:
        """Manually quarantine any file. If it's a known threat its name and severity are used."""
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
        sev, name, det = "medium", threat_name, None
        active = self.db.fetchone("SELECT * FROM scan_detections WHERE path=? AND status='active' "
                                  "ORDER BY id DESC LIMIT 1", (p,))
        if active:
            det, sev, name = active, active["severity"], name or active["threat_name"]
        elif not name and self.scanner is not None and os.path.isfile(p):
            r = self.scanner.scan_file(p)
            if r["detections"]:
                d0 = max(r["detections"], key=lambda d: SEVERITY_ORDER.get(d["severity"], 0))
                name, sev = d0["threat_name"], d0["severity"]
        return self._quarantine(p, username, name or "Manually quarantined file", sev,
                                "detection" if det else "manual", det, kill, force, note)

    def remove_detection(self, det_id: int, username: str, kill: bool | None = None, force: bool = False) -> dict:
        """'Remove' = quarantine, then destroy the vault copy straight away."""
        item = self.quarantine_detection(det_id, username, kill, force)
        return self.delete(item["id"], username, action="removed")

    def auto_action(self, rows: list[dict]) -> None:
        """Called by the scanner after it records detections (scan_auto_quarantine setting)."""
        policy = self.settings.get("scan_auto_quarantine")
        if policy == "off":
            return
        done = set()
        heur_ok = bool(self.settings.get("heuristics_auto_quarantine"))
        for r in rows:
            if policy == "high" and SEVERITY_ORDER.get(r["severity"], 0) < 3:
                continue
            if r.get("method") == "heuristic" and not heur_ok:          # Part 8: suspicious, not proven - you decide
                continue
            if r["path"] in done:
                continue
            done.add(r["path"])
            try:
                self.quarantine_detection(r["id"], "auto", source="auto")
            except QuarantineError as e:
                if e.status == 409:                                 # already handled with another member
                    continue
                log.warning("Auto-quarantine of %s failed: %s", r["path"], e.message)
                self.activity.record("threat", f"Automatic quarantine failed: {r['threat_name']}",
                                     f"{r['path']}: {e.message}", severity="high", source="quarantine")

    # ------------------------------------------------------------ restore / delete
    def restore(self, qid: str, username: str, destination: str | None = None, conflict: str = "rename",
                allow: bool = False) -> dict:
        item = self._row(qid)
        if item["status"] != "quarantined":
            raise QuarantineError(409, f"This item is {item['status']} and can't be restored")
        try:
            key = self.vault.unwrap_key(item["wrapped_key"], qid)
        except VaultError as e:
            raise QuarantineError(500, str(e))
        if destination:
            d = os.path.abspath(os.path.expandvars(os.path.expanduser(destination)))
            if not os.path.isdir(d):
                raise QuarantineError(404, "Destination folder not found")
            target = os.path.join(d, item["file_name"])
        else:
            target = item["original_path"]
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
            except OSError as e:
                raise QuarantineError(403, f"Can't recreate the original folder: {e}")
        self._guard(norm(target), force=True)
        if os.path.lexists(target):
            if conflict == "fail":
                raise QuarantineError(409, "A file with that name already exists there")
            if os.path.isdir(target):
                raise QuarantineError(409, "A folder with that name already exists there")
            if conflict == "rename":
                target = _free_name(target)
        try:
            self.vault.decrypt_to(qid, key, target, item["sha256"])
        except VaultError as e:
            self.activity.record("threat", "Quarantine item damaged", f"{item['file_name']}: {e}",
                                 severity="high", source="quarantine")
            raise QuarantineError(500, str(e))
        except PermissionError:
            raise QuarantineError(403, "Access denied writing the file - run Cyber Hub as administrator")
        except OSError as e:
            raise QuarantineError(423, f"Couldn't write the file: {e}")
        try:
            if item["mode"] is not None:
                os.chmod(target, item["mode"])
            if item["mtime"]:
                os.utime(target, (item["atime"] or item["mtime"], item["mtime"]))
        except OSError:
            pass
        _write_zone(target, item["zone_identifier"])
        entry = None
        if allow:
            entry, _ = self.allow.add("sha256", item["sha256"], username, item["threat_name"],
                                      note=f"Restored from quarantine: {item['file_name']}")
        self.vault.remove(qid)
        self.db.execute("UPDATE quarantine_items SET status='restored', wrapped_key=NULL, status_changed_at=?, "
                        "status_by=?, restored_path=? WHERE id=?", (_now(), username, target, qid))
        new_state = "allowed" if allow else "restored"
        dets = self.db.fetchall("SELECT id FROM scan_detections WHERE quarantine_id=?", (qid,))
        for d in dets:
            self.db.execute("UPDATE scan_detections SET status=?, status_changed_at=?, status_by=? WHERE id=?",
                            (new_state, _now(), username, d["id"]))
            threat_event(self.db, "restored", d["id"], qid, username, target)
            if allow:
                threat_event(self.db, "allowed", d["id"], qid, username, "SHA-256 added to allowed threats")
        if not dets:
            threat_event(self.db, "restored", None, qid, username, target)
        self.activity.record("threat", f"Restored from quarantine: {item['threat_name']}",
                             target + (" (allowed)" if allow else ""), severity="medium", source="quarantine")
        out = self.public(self._row(qid))
        self._emit("restored", item=out)
        return {"item": out, "restored_path": target, "allowed": bool(allow), "allowed_entry": entry,
                "warning": None if allow else "The next scan will report this file again unless you allow it"}

    def delete(self, qid: str, username: str, action: str = "removed") -> dict:
        item = self._row(qid)
        if item["status"] not in ("quarantined", "missing"):
            raise QuarantineError(409, f"This item is already {item['status']}")
        self.vault.remove(qid)
        self.db.execute("UPDATE quarantine_items SET status='deleted', wrapped_key=NULL, status_changed_at=?, "
                        "status_by=? WHERE id=?", (_now(), username, qid))
        dets = self.db.fetchall("SELECT id FROM scan_detections WHERE quarantine_id=?", (qid,))
        for d in dets:
            self.db.execute("UPDATE scan_detections SET status='removed', status_changed_at=?, status_by=? WHERE id=?",
                            (_now(), username, d["id"]))
            threat_event(self.db, action, d["id"], qid, username)
        if not dets:
            threat_event(self.db, action, None, qid, username)
        title = "Removed" if action == "removed" else "Quarantine item expired"
        self.activity.record("threat", f"{title}: {item['threat_name']}", item["original_path"],
                             severity="info", source="quarantine")
        out = self.public(self._row(qid))
        self._emit("quarantine_deleted", item=out)
        return out

    def purge(self, username: str, older_than_days: int | None = None) -> int:
        sql, params = "SELECT id FROM quarantine_items WHERE status IN ('quarantined','missing')", []
        if older_than_days is not None:
            sql += " AND quarantined_at < ?"
            params.append((datetime.now(timezone.utc) - timedelta(days=older_than_days)).strftime("%Y-%m-%dT%H:%M:%S"))
        n = 0
        for r in self.db.fetchall(sql, tuple(params)):
            self.delete(r["id"], username, action="removed")
            n += 1
        return n

    def enforce_limits(self, keep: str | None = None) -> int:
        """Retention + size cap. Runs hourly and after every new quarantine."""
        n = 0
        days = self.settings.get("quarantine_retention_days")
        if days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
            for r in self.db.fetchall("SELECT id FROM quarantine_items WHERE status='quarantined' AND quarantined_at < ?",
                                      (cutoff,)):
                if r["id"] != keep:
                    self.delete(r["id"], "retention", action="purged"); n += 1
        cap = self.settings.get("quarantine_max_mb") * 1024 * 1024
        rows = self.db.fetchall("SELECT id, stored_size FROM quarantine_items WHERE status='quarantined' "
                                "ORDER BY quarantined_at ASC")
        total = sum(r["stored_size"] for r in rows)
        for r in rows:
            if total <= cap:
                break
            if r["id"] == keep:
                continue
            self.delete(r["id"], "size limit", action="purged"); n += 1
            total -= r["stored_size"]
        return n

    # ------------------------------------------------------------ inspection
    def verify(self, qid: str) -> dict:
        item = self._row(qid)
        if item["status"] != "quarantined":
            raise QuarantineError(409, f"This item is {item['status']}")
        try:
            r = self.vault.verify(qid, self.vault.unwrap_key(item["wrapped_key"], qid), item["sha256"])
            return {"id": qid, "ok": r["ok"], "size": r["size"],
                    "message": "Intact - matches the original SHA-256" if r["ok"] else "Content doesn't match"}
        except VaultError as e:
            return {"id": qid, "ok": False, "message": str(e)}

    def rescan(self, qid: str) -> dict:
        """Re-check a quarantined file against today's signatures without restoring it."""
        if self.scanner is None:
            raise QuarantineError(503, "Scanner unavailable")
        item = self._row(qid)
        if item["status"] != "quarantined":
            raise QuarantineError(409, f"This item is {item['status']}")
        try:
            key = self.vault.unwrap_key(item["wrapped_key"], qid)
            h256, h1, h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
            head, buf = b"", io.BytesIO() if item["size"] <= RESCAN_IN_MEMORY else None
            for b in self.vault.decrypt_chunks(qid, key):
                if not head:
                    head = b[:PATTERN_HEAD_BYTES]
                h256.update(b); h1.update(b); h5.update(b)
                if buf is not None:
                    buf.write(b)
        except VaultError as e:
            raise QuarantineError(500, str(e))
        sc = self.scanner
        dets = []
        v = sc._verdict(h256.hexdigest(), h1.hexdigest(), h5.hexdigest(), head, use_allowlist=False)
        if v:
            dets.append(v | {"archive_member": None})
        if buf is not None and head.startswith(b"PK\x03\x04"):
            res = {"detections": [], "archive_entries": 0, "bytes_read": 0}
            try:
                buf.seek(0)
                sc._scan_zip(buf, "", 1, sc._options({"use_allowlist": False}), res, None)
            except Exception:
                pass
            dets += res["detections"]
        allowed = self.allow.match(h256.hexdigest(), dets[0]["threat_name"] if dets else None) is not None
        return {"id": qid, "still_detected": bool(dets), "allowed": allowed,
                "detections": [{k: d.get(k) for k in ("threat_name", "severity", "method", "archive_member")}
                               for d in dets],
                "advice": ("Keep it quarantined or delete it" if dets and not allowed else
                           "No longer matches any signature - it may have been a false alarm" if not dets else
                           "Detected, but on your allowed list")}

    def check_vault(self, username: str = "system") -> dict:
        """Startup / on-demand consistency check: half-finished quarantines, missing vault files,
        orphan files and leftover temp files."""
        rolled = 0
        for r in self.db.fetchall("SELECT id, original_path FROM quarantine_items WHERE original_state='removing'"):
            if os.path.lexists(r["original_path"]):            # engine stopped before the original was removed
                self.vault.remove(r["id"])
                self.db.execute("DELETE FROM quarantine_items WHERE id=?", (r["id"],))
                rolled += 1
            else:
                self.db.execute("UPDATE quarantine_items SET original_state='removed' WHERE id=?", (r["id"],))
        files = self.vault.files()
        missing = 0
        for r in self.db.fetchall("SELECT id FROM quarantine_items WHERE status='quarantined'"):
            if r["id"] not in files:
                self.db.execute("UPDATE quarantine_items SET status='missing', status_changed_at=?, status_by=? "
                                "WHERE id=?", (_now(), username, r["id"]))
                threat_event(self.db, "missing", None, r["id"], username, "vault file not found")
                missing += 1
        live = {r["id"] for r in self.db.fetchall("SELECT id FROM quarantine_items WHERE status='quarantined'")}
        orphans = 0
        for fid in files:
            if fid not in live:
                self.vault.remove(fid); orphans += 1
        partial = 0
        for e in os.scandir(self.vault.dir):
            if e.name.endswith(".part"):
                try:
                    os.unlink(e.path); partial += 1
                except OSError:
                    pass
        if missing or orphans or rolled:
            self.activity.record("threat", "Quarantine vault checked",
                                 f"{missing} missing item(s), {orphans} orphan file(s) removed, "
                                 f"{rolled} unfinished quarantine(s) rolled back",
                                 severity="medium" if missing else "info", source="quarantine")
        return {"missing_items": missing, "orphan_files_removed": orphans, "temp_files_removed": partial,
                "unfinished_rolled_back": rolled}

    def list(self, status: str = "quarantined", search: str | None = None, limit: int = 100,
             offset: int = 0) -> dict:
        where, params = [], []
        if status != "all":
            where.append("status=?"); params.append(status)
        if search:
            where.append("(file_name LIKE ? OR original_path LIKE ? OR threat_name LIKE ? OR sha256 = ?)")
            like = f"%{search}%"
            params += [like, like, like, search.lower()]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM quarantine_items {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM quarantine_items {clause} ORDER BY quarantined_at DESC, rowid DESC "
                                "LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
        days = self.settings.get("quarantine_retention_days")
        items = []
        for r in rows:
            it = self.public(r)
            t = _parse(r["quarantined_at"])
            if t and r["status"] == "quarantined" and days:
                it["expires_at"] = (t + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            items.append(it)
        return {"total": total, "items": items}

    def get(self, qid: str) -> dict:
        item = self._row(qid)
        out = self.public(item)
        out["events"] = self.db.fetchall("SELECT * FROM threat_events WHERE quarantine_id=? ORDER BY id", (qid,))
        out["detections"] = self.db.fetchall("SELECT id, threat_name, severity, archive_member, method, status "
                                             "FROM scan_detections WHERE quarantine_id=?", (qid,))
        return out

    def stats(self) -> dict:
        by = {s: 0 for s in ITEM_STATES}
        for r in self.db.fetchall("SELECT status, COUNT(*) AS n FROM quarantine_items GROUP BY status"):
            by[r["status"]] = r["n"]
        q = self.db.fetchone("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes, COALESCE(SUM(stored_size),0) AS stored, "
                             "MIN(quarantined_at) AS oldest FROM quarantine_items WHERE status='quarantined'")
        sev = {s: 0 for s in SEVERITY_ORDER}
        for r in self.db.fetchall("SELECT severity, COUNT(*) AS n FROM quarantine_items WHERE status='quarantined' "
                                  "GROUP BY severity"):
            sev[r["severity"]] = r["n"]
        cap = self.settings.get("quarantine_max_mb") * 1024 * 1024
        return {"items": q["n"], "original_bytes": q["bytes"], "stored_bytes": q["stored"], "oldest": q["oldest"],
                "by_status": by, "by_severity": sev, "limit_bytes": cap,
                "used_percent": round(q["stored"] * 100 / cap, 2) if cap else 0,
                "retention_days": self.settings.get("quarantine_retention_days"),
                "auto_quarantine": self.settings.get("scan_auto_quarantine"),
                "allowed_threats": self.allow.count(), "vault": self.vault.info()}


# ====================================================================== threat history
class ThreatHistory:
    def __init__(self, db: Database, quarantine: QuarantineService, allow: AllowList):
        self.db, self.q, self.allow = db, quarantine, allow

    def _filters(self, status: str, severity: str | None, search: str | None, days: int | None):
        where, params = [], []
        if status == "history":
            where.append("d.status != 'superseded'")
        elif status != "all":
            where.append("d.status=?"); params.append(status)
        if severity:
            where.append("d.severity=?"); params.append(severity)
        if search:
            like = f"%{search}%"
            where.append("(d.path LIKE ? OR d.threat_name LIKE ? OR d.archive_member LIKE ? OR d.sha256 = ?)")
            params += [like, like, like, search.lower()]
        if days:
            where.append("d.detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?)"); params.append(f"-{days} days")
        return ("WHERE " + " AND ".join(where)) if where else "", params

    def list(self, status: str = "history", severity: str | None = None, search: str | None = None,
             days: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        clause, params = self._filters(status, severity, search, days)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM scan_detections d {clause}", tuple(params))["n"]
        items = self.db.fetchall(
            "SELECT d.*, q.status AS quarantine_status, q.original_state AS quarantine_original_state "
            f"FROM scan_detections d LEFT JOIN quarantine_items q ON q.id = d.quarantine_id {clause} "
            "ORDER BY d.id DESC LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
        for it in items:
            it["actions"] = self.actions_for(it)
        return {"total": total, "items": items}

    @staticmethod
    def actions_for(d: dict) -> list[str]:
        s = d["status"]
        if s == "active":
            return ["quarantine", "remove", "allow", "dismiss"]
        if s == "quarantined":
            return ["restore", "delete"]
        if s in ("restored", "dismissed", "resolved"):
            return ["allow"] if d.get("sha256") else []
        return []

    def get(self, det_id: int) -> dict:
        d = self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))
        if not d:
            raise QuarantineError(404, "Detection not found")
        d["events"] = self.db.fetchall(
            "SELECT * FROM threat_events WHERE detection_id=? OR (quarantine_id IS NOT NULL AND quarantine_id=? "
            "AND detection_id IS NULL) ORDER BY ts, id", (det_id, d["quarantine_id"]))
        d["quarantine_item"] = self.q.public(self.db.fetchone("SELECT * FROM quarantine_items WHERE id=?",
                                                              (d["quarantine_id"],))) if d["quarantine_id"] else None
        entry = self.allow.match(d["sha256"], d["threat_name"])
        d["allowed_entry"] = self.allow.get(entry) if entry is not None else None
        d["same_file_detections"] = self.db.fetchone(
            "SELECT COUNT(*) AS n FROM scan_detections WHERE sha256=? AND id != ?", (d["sha256"], det_id))["n"] \
            if d["sha256"] else 0
        d["file_exists"] = os.path.lexists(d["path"])
        d["actions"] = self.actions_for(d)
        return d

    def allow_detection(self, det_id: int, username: str, note: str | None = None) -> dict:
        d = self.db.fetchone("SELECT * FROM scan_detections WHERE id=?", (det_id,))
        if not d:
            raise QuarantineError(404, "Detection not found")
        if d["status"] == "quarantined":
            raise QuarantineError(409, "Restore it from quarantine with allow=true instead")
        if not d["sha256"]:
            raise QuarantineError(422, "This detection has no SHA-256 to allow")
        entry, created = self.allow.add("sha256", d["sha256"], username, d["threat_name"],
                                        note or f"Allowed from detection {det_id}")
        changed = self.db.fetchall("SELECT id FROM scan_detections WHERE sha256=? AND status='active'", (d["sha256"],))
        for r in changed:
            self.db.execute("UPDATE scan_detections SET status='allowed', status_changed_at=?, status_by=? WHERE id=?",
                            (_now(), username, r["id"]))
            threat_event(self.db, "allowed", r["id"], None, username, "SHA-256 added to allowed threats")
        if d["status"] not in ("active", "allowed"):          # e.g. restored / dismissed earlier
            threat_event(self.db, "allowed", det_id, None, username, "SHA-256 added to allowed threats")
        self.q.activity.record("threat", f"Threat allowed: {d['threat_name']}", d["path"], severity="medium",
                               source="quarantine")
        return {"entry": entry, "created": created, "detections_allowed": [r["id"] for r in changed]}

    def unallow(self, entry_id: int, username: str) -> dict:
        row = self.allow.remove(entry_id)
        if not row:
            raise QuarantineError(404, "Allowed entry not found")
        if row["kind"] == "sha256":
            for d in self.db.fetchall("SELECT id FROM scan_detections WHERE sha256=? AND status='allowed'",
                                      (row["value"],)):
                threat_event(self.db, "unallowed", d["id"], None, username, "removed from allowed threats")
        self.q.activity.record("threat", "Allowed threat removed", f"{row['threat_name'] or row['value']} - "
                               "scans will report it again", severity="low", source="quarantine")
        return row

    def summary(self, days: int = 30) -> dict:
        by = {s: 0 for s in DETECTION_STATES}
        for r in self.db.fetchall("SELECT status, COUNT(*) AS n FROM scan_detections GROUP BY status"):
            by[r["status"]] = r["n"]
        active_sev = {s: 0 for s in SEVERITY_ORDER}
        for r in self.db.fetchall("SELECT severity, COUNT(*) AS n FROM scan_detections WHERE status='active' "
                                  "GROUP BY severity"):
            active_sev[r["severity"]] = r["n"]
        since = f"-{days} days"
        per_day: dict[str, dict] = {}
        for r in self.db.fetchall(
                "SELECT substr(ts,1,10) AS day, action, COUNT(*) AS n FROM threat_events "
                "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) AND action IN "
                "('detected','quarantined','restored','removed','purged','allowed') GROUP BY day, action ORDER BY day",
                (since,)):
            row = per_day.setdefault(r["day"], {"day": r["day"], "detected": 0, "quarantined": 0, "restored": 0,
                                                "removed": 0, "allowed": 0})
            row["removed" if r["action"] == "purged" else r["action"]] += r["n"]
        top = self.db.fetchall(
            "SELECT threat_name, severity, COUNT(*) AS n FROM scan_detections WHERE status != 'superseded' "
            "AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) GROUP BY threat_name ORDER BY n DESC LIMIT 8",
            (since,))
        folders: dict[str, int] = {}
        for r in self.db.fetchall("SELECT path FROM scan_detections WHERE status != 'superseded' "
                                  "AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?)", (since,)):
            f = os.path.dirname(r["path"])
            folders[f] = folders.get(f, 0) + 1
        methods = {r["method"]: r["n"] for r in self.db.fetchall(
            "SELECT method, COUNT(*) AS n FROM scan_detections WHERE status != 'superseded' GROUP BY method")}
        active = by["active"]
        handled = sum(by[s] for s in ("quarantined", "removed", "allowed", "dismissed", "resolved", "restored"))
        return {
            "days": days, "active_threats": active, "active_by_severity": active_sev, "by_status": by,
            "handled": handled, "handled_percent": round(handled * 100 / (handled + active), 1) if handled + active else 100.0,
            "by_day": list(per_day.values()), "top_threats": top,
            "top_locations": [{"folder": k, "n": v} for k, v in sorted(folders.items(), key=lambda kv: -kv[1])[:8]],
            "by_method": methods, "quarantine": self.q.stats(),
            "recommendation": (f"Quarantine {active} active threat(s)" if active else "No action needed"),
        }

    def export_csv(self, status: str = "history", severity: str | None = None, search: str | None = None,
                   days: int | None = None) -> str:
        clause, params = self._filters(status, severity, search, days)
        rows = self.db.fetchall(
            "SELECT d.id, d.detected_at, d.threat_name, d.severity, d.status, d.method, d.path, d.archive_member, "
            "d.size, d.sha256, d.md5, d.job_id, d.status_changed_at, d.status_by, d.quarantine_id "
            f"FROM scan_detections d {clause} ORDER BY d.id DESC LIMIT 100000", tuple(params))
        buf = io.StringIO()
        cols = ["id", "detected_at", "threat_name", "severity", "status", "method", "path", "archive_member", "size",
                "sha256", "md5", "job_id", "status_changed_at", "status_by", "quarantine_id"]
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow(["'" + v if isinstance(v, str) and v[:1] in "=+-@" else v    # CSV formula-injection guard
                        for v in (r[c] for c in cols)])
        return buf.getvalue()

    def clear(self, username: str, older_than_days: int = 0) -> dict:
        """Forget finished history (never active or quarantined threats, never allowed entries)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).strftime("%Y-%m-%dT%H:%M:%S.99Z")
        done = ("restored", "removed", "allowed", "dismissed", "resolved", "superseded")
        ids = [r["id"] for r in self.db.fetchall(
            f"SELECT id FROM scan_detections WHERE status IN ({','.join('?' * len(done))}) AND detected_at <= ?",
            done + (cutoff,))]
        with self.db.tx() as c:
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                ph = ",".join("?" * len(part))
                c.execute(f"DELETE FROM threat_events WHERE detection_id IN ({ph})", part)
                c.execute(f"DELETE FROM scan_detections WHERE id IN ({ph})", part)
            q = [r["id"] for r in c.execute("SELECT id FROM quarantine_items WHERE status IN ('restored','deleted') "
                                            "AND quarantined_at <= ?", (cutoff,)).fetchall()]
            for qid in q:
                c.execute("DELETE FROM threat_events WHERE quarantine_id=? AND detection_id IS NULL", (qid,))
                c.execute("DELETE FROM quarantine_items WHERE id=?", (qid,))
        self.q.activity.record("threat", "Protection history cleared",
                               f"{len(ids)} detection(s), {len(q)} quarantine record(s)", severity="low",
                               source="quarantine")
        return {"detections_deleted": len(ids), "quarantine_records_deleted": len(q)}
