"""
Cyber Hub Backend - Notification center + desktop toasts (Part 17)
Developed by Syed Muhammad Tayyab

One inbox for everything the other parts report. Nothing in Parts 1-16 was changed for this: a collector reads
the rows each module already writes and turns the important ones into notifications.

Sources
    * the module event tables: firewall_events, network_events, posture_events, pv_events, dp_events, web_events,
      intel_events, platform_events (per-user rows stay per-user; rows without a user are shown to everyone)
    * the activity log for the modules that have no event table of their own: scans, threats / quarantine,
      real-time protection, USB drives, sign-in security, startup items, resource alerts
    * notify(...) for Parts 17-19 themselves (scheduled jobs, score drops, reports, backups)

Each source keeps a cursor (notify_state), so a notification is created exactly once - also across restarts - and
the first start after an upgrade begins at "now" instead of replaying months of history.

Toasts
    Windows: a toast through Windows' own notification API (PowerShell, title / text passed in environment
             variables, never in the script). Cyber Hub registers its own name for them under HKCU.
    Linux:   notify-send when it exists.  Tests / headless: an in-memory list (CYBERHUB_TOAST_BACKEND=memory).
    A toast is shown when toasts are on, the severity reaches notify_toast_min_severity, the source isn't muted,
    it is not quiet hours (critical may pass) and fewer than notify_toast_max_per_minute were shown this minute.
    Everything else still lands in the center, marked with the reason it stayed silent.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

from ..database import Database
from ..logger import get_logger
from .platform_tools import IS_WINDOWS, powershell_exe, run_cmd_full

log = get_logger("notify")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SOURCES = {
    "threat": "Virus & threat protection", "realtime": "Real-time protection", "firewall": "Firewall",
    "network": "Network", "device": "Device security", "passwords": "Password vault", "data": "Data protection",
    "web": "Website scanner", "intel": "Threat intelligence", "platforms": "Accounts & platforms",
    "monitor": "System monitor", "account": "Cyber Hub account", "startup": "Startup & processes",
    "scheduler": "Scheduler", "reports": "Reports & backup", "system": "Cyber Hub",
}
# event table -> (source, UI page, has user_id column)
EVENT_TABLES: dict[str, tuple[str, str, bool]] = {
    "firewall_events": ("firewall", "firewall", False),
    "network_events": ("network", "network", False),
    "posture_events": ("device", "device", False),
    "pv_events": ("passwords", "passwords", True),
    "dp_events": ("data", "data", True),
    "web_events": ("web", "web", True),
    "intel_events": ("intel", "intel", True),
    "platform_events": ("platforms", "platforms", True),
}
# activity-log category -> (source, UI page) for modules without an event table
ACTIVITY_MAP: dict[str, tuple[str, str]] = {
    "scan": ("threat", "protection"), "threat": ("threat", "protection"), "rules": ("threat", "protection"),
    "realtime": ("realtime", "protection"), "device": ("realtime", "protection"),
    "account": ("account", "account"), "startup": ("startup", "processes"), "process": ("startup", "processes"),
    "system": ("monitor", "monitor"),
}
_ACT_SKIP_SOURCES = {"ui", "scheduler", "notifications", "reports", "backup", "score"}


def _iso(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sev_index(s: str | None) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def in_quiet_hours(start: str, end: str, now: datetime | None = None) -> bool:
    """True when local time `now` lies in [start, end). Handles ranges that cross midnight (22:00 -> 07:00)."""
    now = now or datetime.now()
    cur = now.hour * 60 + now.minute
    s = int(start[:2]) * 60 + int(start[3:5])
    e = int(end[:2]) * 60 + int(end[3:5])
    if s == e:
        return False
    return s <= cur < e if s < e else (cur >= s or cur < e)


# ====================================================================== toast backends
_TOAST_PS = r"""
$ErrorActionPreference = 'Stop'
$appId = 'CyberHub.SecurityCenter'
$key = "HKCU:\Software\Classes\AppUserModelId\$appId"
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
Set-ItemProperty -Path $key -Name DisplayName -Value 'Cyber Hub' -Type String
if ($env:CH_ICON -and (Test-Path -LiteralPath $env:CH_ICON)) {
    Set-ItemProperty -Path $key -Name IconUri -Value $env:CH_ICON -Type String
}
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$t = [System.Security.SecurityElement]::Escape($env:CH_TITLE)
$b = [System.Security.SecurityElement]::Escape($env:CH_BODY)
$a = [System.Security.SecurityElement]::Escape($env:CH_ATTR)
$scenario = ''
if ($env:CH_URGENT -eq '1') { $scenario = ' scenario="urgent"' }
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast$scenario><visual><binding template=`"ToastGeneric`"><text>$t</text><text>$b</text><text placement=`"attribution`">$a</text></binding></visual></toast>")
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
$toast.Tag = $env:CH_TAG
$toast.Group = 'cyberhub'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
'ok'
"""


class Toaster:
    name = "none"
    available = False
    reason: str | None = "Desktop notifications aren't available on this system"

    def show(self, title: str, body: str, severity: str, tag: str) -> bool:    # pragma: no cover - interface
        return False

    def info(self) -> dict:
        return {"backend": self.name, "available": self.available, "reason": None if self.available else self.reason}


class WindowsToaster(Toaster):                                      # pragma: no cover - Windows only
    name = "windows"

    def __init__(self, icon: str | None = None):
        self.exe = shutil.which("powershell") or powershell_exe()
        self.available = bool(self.exe)
        self.reason = None if self.available else "PowerShell was not found"
        self.icon = icon or ""

    def show(self, title: str, body: str, severity: str, tag: str) -> bool:
        if not self.exe:
            return False
        rc, out, err = run_cmd_full(
            [self.exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _TOAST_PS],
            timeout=15, env={"CH_TITLE": title[:120], "CH_BODY": body[:300], "CH_TAG": tag[:60],
                             "CH_ATTR": f"Cyber Hub - {severity}", "CH_ICON": self.icon,
                             "CH_URGENT": "1" if severity == "critical" else "0"})
        if rc != 0 or "ok" not in out:
            log.debug("Toast failed: %s", (err or out).strip()[:300])
            return False
        return True


class LinuxToaster(Toaster):
    name = "notify-send"

    def __init__(self):
        self.exe = shutil.which("notify-send")
        self.available = bool(self.exe) and bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        self.reason = None if self.available else "notify-send (or a desktop session) was not found"

    def show(self, title: str, body: str, severity: str, tag: str) -> bool:
        if not self.available:
            return False
        urgency = "critical" if severity in ("high", "critical") else "normal"
        rc, _, _ = run_cmd_full([self.exe, "-a", "Cyber Hub", "-u", urgency, title[:120], body[:300]], timeout=5)
        return rc == 0


class MemoryToaster(Toaster):
    """Tests / demos: remembers what would have been shown."""
    name = "memory"
    available = True
    reason = None

    def __init__(self):
        self.shown: list[dict] = []
        self.fail = False

    def show(self, title: str, body: str, severity: str, tag: str) -> bool:
        if self.fail:
            return False
        self.shown.append({"title": title, "body": body, "severity": severity, "tag": tag})
        return True


def default_toaster(icon: str | None = None) -> Toaster:
    forced = os.environ.get("CYBERHUB_TOAST_BACKEND", "").lower()
    if forced == "memory":
        return MemoryToaster()
    if forced in ("off", "none"):
        return Toaster()
    if IS_WINDOWS:                                                  # pragma: no cover
        return WindowsToaster(icon)
    return LinuxToaster()


# ====================================================================== the center
class NotifyError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class NotificationCenter:
    def __init__(self, db: Database, settings, activity=None, toaster: Toaster | None = None,
                 icon: str | None = None):
        self.db, self.settings, self.activity = db, settings, activity
        self.toaster = toaster or default_toaster(icon)
        self._lock = threading.RLock()
        self._toast_times: deque[float] = deque(maxlen=120)
        self._toast_queue: list[tuple] = []
        self._toast_thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.on_toast: Callable[[dict], bool] | None = None        # Part 20: the tray icon can show toasts itself
        self._baseline()

    # ------------------------------------------------------------------ small helpers
    def _g(self, key: str) -> Any:
        return self.settings.get(key)

    def _state(self, key: str, value: Any = ...) -> Any:
        if value is ...:
            r = self.db.fetchone("SELECT value FROM notify_state WHERE key=?", (key,))
            return json.loads(r["value"]) if r else None
        self.db.execute("INSERT INTO notify_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))
        return value

    def _table_exists(self, name: str) -> bool:
        return bool(self.db.fetchone("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name=?", (name,)))

    def _max_id(self, table: str) -> int:
        return self.db.fetchone(f"SELECT COALESCE(MAX(id),0) AS m FROM {table}")["m"]

    def _baseline(self) -> None:
        """First start with Part 17: begin at the newest existing row of every source (no replay of old history)."""
        for table in list(EVENT_TABLES) + ["activity_log"]:
            if self._state(f"cursor:{table}") is None and self._table_exists(table):
                self._state(f"cursor:{table}", self._max_id(table))

    @staticmethod
    def _uid(cu) -> int:
        return cu.user["id"]

    @staticmethod
    def _is_admin(cu) -> bool:
        return cu is None or cu.user.get("role") == "admin"

    @staticmethod
    def _public(r: dict) -> dict:
        out = dict(r)
        out["read"] = bool(r["read_at"])
        out["dismissed"] = bool(r["dismissed_at"])
        out["source_name"] = SOURCES.get(r["source"], r["source"])
        out["shared"] = r["user_id"] is None
        return out

    # ------------------------------------------------------------------ creating
    def notify(self, source: str, severity: str, title: str, detail: str | None = None, *, kind: str | None = None,
               user_id: int | None = None, link: str | None = None, source_table: str | None = None,
               source_id: int | None = None, toast: bool = True, ts: str | None = None) -> dict | None:
        """Create one notification (and maybe a toast). Returns the row, or None when it was filtered out /
        already exists. Safe to call from any thread."""
        if source not in SOURCES:
            raise ValueError(f"Unknown notification source '{source}'")
        if severity not in SEVERITIES:
            raise ValueError(f"Unknown severity '{severity}'")
        if _sev_index(severity) < _sev_index(self._g("notify_center_min_severity")):
            return None
        with self._lock:
            try:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO notifications(ts, user_id, source, kind, severity, title, detail, link, "
                    "source_table, source_id) VALUES (COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')),?,?,?,?,?,?,?,?,?)",
                    (ts, user_id, source, kind, severity, title[:300], (detail or None) and detail[:2000],
                     link or source, source_table, source_id))
            except Exception as e:                                   # e.g. the user was deleted meanwhile
                log.debug("Notification not stored: %s", e)
                return None
            if not cur.rowcount:
                return None
            nid = cur.lastrowid
            state = self._toast_decision(source, severity) if toast else "none"
            if state == "show":
                self._toast_times.append(time.monotonic())
                self._toast_queue.append((nid, title, detail or "", severity))
                state = "pending"
                self._start_toast_thread()
            self.db.execute("UPDATE notifications SET toast=? WHERE id=?", (state, nid))
            return self._public(self.db.fetchone("SELECT * FROM notifications WHERE id=?", (nid,)))

    def _toast_decision(self, source: str, severity: str) -> str:
        if not self._g("notifications_enabled") or not self._g("notify_toasts"):
            return "off"
        if not self.toaster.available and self.on_toast is None:
            return "off"
        if _sev_index(severity) < _sev_index(self._g("notify_toast_min_severity")):
            return "none"
        if source in set(self._g("notify_muted_sources")):
            return "muted"
        if self._g("notify_quiet_hours") and in_quiet_hours(self._g("notify_quiet_start"), self._g("notify_quiet_end")):
            if not (severity == "critical" and self._g("notify_quiet_allow_critical")):
                return "quiet"
        limit = int(self._g("notify_toast_max_per_minute"))
        cutoff = time.monotonic() - 60
        if sum(1 for t in self._toast_times if t >= cutoff) >= limit:
            return "rate"
        return "show"

    def _start_toast_thread(self) -> None:
        if self._toast_thread and self._toast_thread.is_alive():
            return
        self._toast_thread = threading.Thread(target=self._toast_worker, name="cyberhub-toasts", daemon=True)
        self._toast_thread.start()

    def _toast_worker(self) -> None:
        while not self._stopping.is_set():
            with self._lock:
                if not self._toast_queue:
                    self._toast_thread = None
                    return
                nid, title, body, severity = self._toast_queue.pop(0)
            ok = False
            try:
                if self.on_toast is not None:
                    ok = bool(self.on_toast({"id": nid, "title": title, "body": body, "severity": severity}))
                if not ok:
                    ok = self.toaster.show(title, body, severity, f"n{nid}")
            except Exception as e:                                   # pragma: no cover
                log.debug("Toast error: %s", e)
            try:
                self.db.execute("UPDATE notifications SET toast=? WHERE id=?", ("shown" if ok else "failed", nid))
            except Exception:                                        # DB closed during shutdown
                return

    def flush_toasts(self, timeout: float = 5.0) -> None:
        """Wait until queued toasts were handed to the desktop (tests, shutdown)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self._lock:
                idle = not self._toast_queue and not (self._toast_thread and self._toast_thread.is_alive())
            if idle:
                return
            time.sleep(0.02)

    # ------------------------------------------------------------------ collecting from Parts 1-16
    def collect(self) -> int:
        """Read new rows of every source and create notifications. Returns how many were created."""
        made = 0
        floor = _sev_index(self._g("notify_center_min_severity"))
        with self._lock:
            for table, (source, link, has_user) in EVENT_TABLES.items():
                if not self._table_exists(table):
                    continue
                cur = self._state(f"cursor:{table}") or 0
                rows = self.db.fetchall(f"SELECT * FROM {table} WHERE id > ? ORDER BY id LIMIT 500", (cur,))
                for r in rows:
                    cur = r["id"]
                    if _sev_index(r["severity"]) < max(floor, 1):
                        continue
                    if self.notify(source, r["severity"], r["title"], r.get("detail"), kind=r.get("kind"),
                                   user_id=r.get("user_id") if has_user else None, link=link,
                                   source_table=table, source_id=r["id"], ts=r["ts"]):
                        made += 1
                if rows:
                    self._state(f"cursor:{table}", cur)
            cur = self._state("cursor:activity_log") or 0
            rows = self.db.fetchall("SELECT * FROM activity_log WHERE id > ? ORDER BY id LIMIT 1000", (cur,))
            for r in rows:
                cur = r["id"]
                m = ACTIVITY_MAP.get(r["category"])
                if not m or r["source"] in _ACT_SKIP_SOURCES or _sev_index(r["severity"]) < max(floor, 1):
                    continue
                if self.notify(m[0], r["severity"], r["title"], r.get("detail"), kind=r["category"], link=m[1],
                               source_table="activity_log", source_id=r["id"], ts=r["ts"]):
                    made += 1
            if rows:
                self._state("cursor:activity_log", cur)
        return made

    def cleanup(self) -> int:
        days = int(self._g("notify_retention_days"))
        return self.db.execute("DELETE FROM notifications WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)",
                               (f"-{days} days",)).rowcount

    # ------------------------------------------------------------------ reading
    def _scope(self, cu) -> tuple[str, list]:
        return "(user_id IS ? OR user_id IS NULL)", [self._uid(cu)]

    def list(self, cu, status: str = "open", source: str | None = None, severity: str | None = None,
             min_severity: str | None = None, after_id: int = 0, search: str | None = None,
             limit: int = 50, offset: int = 0) -> dict:
        scope, params = self._scope(cu)
        where = [scope]
        if status == "unread":
            where.append("read_at IS NULL AND dismissed_at IS NULL")
        elif status == "open":
            where.append("dismissed_at IS NULL")
        elif status == "dismissed":
            where.append("dismissed_at IS NOT NULL")
        elif status != "all":
            raise NotifyError(422, "status must be unread, open, dismissed or all")
        if source:
            if source not in SOURCES:
                raise NotifyError(422, "Unknown source")
            where.append("source=?"); params.append(source)
        if severity:
            where.append("severity=?"); params.append(severity)
        if min_severity:
            ok = SEVERITIES[_sev_index(min_severity):]
            where.append(f"severity IN ({','.join('?' * len(ok))})"); params += ok
        if after_id:
            where.append("id > ?"); params.append(after_id)
        if search:
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"); params += [like, like]
        clause = " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM notifications WHERE {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM notifications WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        return {"items": [self._public(r) for r in rows], "total": total, "unread": self.unread(cu),
                "last_id": self._max_id("notifications"), "limit": limit, "offset": offset}

    def get(self, cu, nid: int) -> dict:
        scope, params = self._scope(cu)
        r = self.db.fetchone(f"SELECT * FROM notifications WHERE id=? AND {scope}", (nid, *params))
        if not r:
            raise NotifyError(404, "Notification not found")
        return self._public(r)

    def unread(self, cu) -> int:
        scope, params = self._scope(cu)
        return self.db.fetchone(f"SELECT COUNT(*) AS n FROM notifications WHERE {scope} AND read_at IS NULL "
                                "AND dismissed_at IS NULL", tuple(params))["n"]

    def summary(self, cu, days: int = 14) -> dict:
        scope, params = self._scope(cu)
        since = f"-{days} days"
        base = f"FROM notifications WHERE {scope} AND ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)"
        p = tuple(params) + (since,)
        by_sev = {s: 0 for s in SEVERITIES}
        for r in self.db.fetchall(f"SELECT severity, COUNT(*) AS n {base} GROUP BY severity", p):
            by_sev[r["severity"]] = r["n"]
        unread_sev = {s: 0 for s in SEVERITIES}
        for r in self.db.fetchall(f"SELECT severity, COUNT(*) AS n FROM notifications WHERE {scope} AND read_at IS "
                                  "NULL AND dismissed_at IS NULL GROUP BY severity", tuple(params)):
            unread_sev[r["severity"]] = r["n"]
        by_source = self.db.fetchall(f"SELECT source, COUNT(*) AS n {base} GROUP BY source ORDER BY n DESC", p)
        for r in by_source:
            r["name"] = SOURCES.get(r["source"], r["source"])
        by_day = self.db.fetchall(f"SELECT substr(ts,1,10) AS day, COUNT(*) AS n, SUM(severity IN ('high','critical')) "
                                  f"AS serious {base} GROUP BY day ORDER BY day", p)
        toasts = {r["toast"]: r["n"] for r in self.db.fetchall(f"SELECT toast, COUNT(*) AS n {base} GROUP BY toast", p)}
        return {"days": days, "unread": sum(unread_sev.values()), "unread_by_severity": unread_sev,
                "worst_unread": next((s for s in reversed(SEVERITIES) if unread_sev[s]), None),
                "by_severity": by_sev, "by_source": by_source, "by_day": by_day, "toasts": toasts}

    # ------------------------------------------------------------------ changing
    def _mark(self, cu, column: str, ids: list[int] | None, extra: str = "") -> int:
        scope, params = self._scope(cu)
        now = _iso()
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE notifications SET {column}=COALESCE({column}, ?){extra} WHERE id IN ({q}) "
                                   f"AND {scope}", (now, *ids, *params)).rowcount
        return self.db.execute(f"UPDATE notifications SET {column}=?{extra} WHERE {column} IS NULL AND {scope}",
                               (now, *params)).rowcount

    def mark_read(self, cu, ids: list[int] | None = None) -> int:
        return self._mark(cu, "read_at", ids)

    def mark_unread(self, cu, ids: list[int]) -> int:
        scope, params = self._scope(cu)
        q = ",".join("?" * len(ids))
        return self.db.execute(f"UPDATE notifications SET read_at=NULL WHERE id IN ({q}) AND {scope}",
                               (*ids, *params)).rowcount

    def dismiss(self, cu, ids: list[int] | None = None) -> int:
        n = self._mark(cu, "dismissed_at", ids)
        scope, params = self._scope(cu)
        self.db.execute(f"UPDATE notifications SET read_at=COALESCE(read_at, dismissed_at) WHERE dismissed_at IS NOT "
                        f"NULL AND read_at IS NULL AND {scope}", tuple(params))
        return n

    def clear(self, cu, dismissed_only: bool = False) -> int:
        """Delete notifications. Shared (this-PC) ones can only be deleted by an administrator."""
        where = ["user_id IS ?"] if not self._is_admin(cu) else ["(user_id IS ? OR user_id IS NULL)"]
        if dismissed_only:
            where.append("dismissed_at IS NOT NULL")
        return self.db.execute(f"DELETE FROM notifications WHERE {' AND '.join(where)}", (self._uid(cu),)).rowcount

    # ------------------------------------------------------------------ status / test
    def status(self, cu) -> dict:
        keys = ["notifications_enabled", "notify_center_min_severity", "notify_toasts", "notify_toast_min_severity",
                "notify_toast_max_per_minute", "notify_quiet_hours", "notify_quiet_start", "notify_quiet_end",
                "notify_quiet_allow_critical", "notify_muted_sources", "notify_retention_days"]
        quiet = bool(self._g("notify_quiet_hours")) and in_quiet_hours(self._g("notify_quiet_start"),
                                                                       self._g("notify_quiet_end"))
        info = self.toaster.info()
        if self.on_toast is not None:
            info = {"backend": "tray", "available": True, "reason": None, "fallback": info["backend"]}
        return {"unread": self.unread(cu), "toasts": info, "quiet_now": quiet,
                "sources": [{"id": k, "name": v, "muted": k in set(self._g("notify_muted_sources"))}
                            for k, v in SOURCES.items()],
                "severities": SEVERITIES[1:], "settings": {k: self._g(k) for k in keys}}

    def test(self, cu) -> dict:
        """Send a test toast right now, ignoring quiet hours / limits, so the user can check that toasts work."""
        cur = self.db.execute("INSERT INTO notifications(user_id, source, kind, severity, title, detail, link) "
                              "VALUES (?,?,?,?,?,?,?)",
                              (self._uid(cu), "system", "test", "low", "Cyber Hub notifications are working",
                               "This is a test notification - you asked for it from Settings.", "notifications"))
        nid = cur.lastrowid
        ok = False
        reason = None
        payload = {"id": nid, "title": "Cyber Hub notifications are working",
                   "body": "This is a test notification.", "severity": "low"}
        try:
            if self.on_toast is not None:
                ok = bool(self.on_toast(payload))
            if not ok and self.toaster.available:
                ok = self.toaster.show(payload["title"], payload["body"], "low", f"n{nid}")
            if not ok:
                reason = self.toaster.reason or "Windows did not accept the toast (check Focus assist / notification settings)"
        except Exception as e:                                       # pragma: no cover
            reason = str(e)
        self.db.execute("UPDATE notifications SET toast=? WHERE id=?", ("shown" if ok else "failed", nid))
        return {"shown": ok, "reason": reason, "notification": self.get(cu, nid), "backend": self.toaster.info()}

    def shutdown(self) -> None:
        self._stopping.set()
        t = self._toast_thread
        if t and t.is_alive():
            t.join(timeout=3)


# ---------------------------------------------------------------------- worker
async def notification_loop(center: NotificationCenter, settings, every_seconds: float = 3.0) -> None:
    import asyncio
    ticks = 0
    while True:
        await asyncio.sleep(every_seconds)
        try:
            await asyncio.to_thread(center.collect)
            ticks += 1
            if ticks % 1200 == 0:                                    # about hourly
                await asyncio.to_thread(center.cleanup)
        except Exception as e:                                       # pragma: no cover
            log.warning("Notification collector failed: %s", e)


__all__ = ["NotificationCenter", "NotifyError", "Toaster", "MemoryToaster", "default_toaster", "in_quiet_hours",
           "notification_loop", "SOURCES", "SEVERITIES"]
