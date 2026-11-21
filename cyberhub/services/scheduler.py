"""
Cyber Hub Backend - Scheduler (Part 17)
Developed by Syed Muhammad Tayyab

Runs the other parts' work at planned times: scans (Part 5), posture / firewall / network checks (Parts 9-11),
threat-feed refresh (15), monitored-site re-scans (14), breach-list refresh + extension audit (16), privacy
clean-up + sensitive-file search (13), security reports and backups (19).

A schedule is one of
    interval   every N minutes (5 minutes .. 30 days)
    daily      every day at HH:MM
    weekly     on chosen weekdays at HH:MM          (Monday = 0)
    monthly    on a day of the month at HH:MM       (31 -> the month's last day)
    once       at one date and time
Times are the PC's local time (what the user sees on the clock); they are stored as UTC and re-computed after
each run, so daylight-saving changes are followed.

Rules
    * A schedule never overlaps itself; a run that is still going makes the next one "skipped".
    * PC was off / asleep at the planned time: with catch_up the job runs once after start-up, without it the
      run is recorded as skipped. Nothing ever runs twice to "make up" for several missed days.
    * scheduler_skip_on_battery postpones the heavy jobs (full scan, clean-up, file search) by 30 minutes at a
      time while a laptop runs on battery.
    * Every run is recorded (schedule_runs) with its outcome and the facts behind it, and failed runs raise a
      notification.
    * Per-user jobs (clean-up, file search, report) run as the schedule's user, or the PC's owner account.
"""
from __future__ import annotations

import calendar
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..database import Database
from ..logger import get_logger

log = get_logger("scheduler")

KINDS = ("interval", "daily", "weekly", "monthly", "once")
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
GRACE_SECONDS = 600            # a run this late still counts as "on time"
MAX_SCHEDULES = 100
WAIT_LIMIT = 6 * 3600          # longest a run waits for the job it started


class SchedulerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class _RunAs:
    """Minimal stand-in for security.CurrentUser so per-user services can be called from a schedule."""
    def __init__(self, user: dict):
        self.user = user
        self.session = {"id": None}


def _iso(dt: datetime | None = None) -> str:
    dt = (dt or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return d if d.tzinfo else d.astimezone()
        except ValueError:
            return None


def _hhmm(v: Any) -> tuple[int, int]:
    if not isinstance(v, str):
        raise SchedulerError(422, "Time must look like 14:30")
    p = v.split(":")
    if len(p) != 2 or not all(x.isdigit() and len(x) == 2 for x in p) or int(p[0]) > 23 or int(p[1]) > 59:
        raise SchedulerError(422, "Time must look like 14:30")
    return int(p[0]), int(p[1])


def _local(dt: datetime) -> datetime:
    """UTC-aware -> naive local wall-clock time."""
    return dt.astimezone().replace(tzinfo=None)


def _from_local(naive: datetime) -> datetime:
    """Naive local wall-clock time -> UTC-aware (the OS decides the offset valid on that date)."""
    return naive.astimezone().astimezone(timezone.utc)


def next_run(spec: dict, after: datetime) -> datetime | None:
    """The first planned time strictly after `after` (UTC-aware). None = never again (a finished 'once')."""
    kind = spec["kind"]
    if kind == "interval":
        return after + timedelta(minutes=int(spec["every_minutes"]))
    if kind == "once":
        at = _parse(spec.get("run_at"))
        return at if at and at > after else None
    h, m = _hhmm(spec["at_time"])
    now_l = _local(after)
    if kind == "daily":
        cand = now_l.replace(hour=h, minute=m, second=0, microsecond=0)
        if cand <= now_l:
            cand += timedelta(days=1)
        return _from_local(cand)
    if kind == "weekly":
        days = sorted({int(x) for x in str(spec["weekdays"]).split(",") if x != ""})
        for add in range(0, 8):
            cand = (now_l + timedelta(days=add)).replace(hour=h, minute=m, second=0, microsecond=0)
            if cand.weekday() in days and cand > now_l:
                return _from_local(cand)
        return None                                                  # pragma: no cover - days is never empty
    if kind == "monthly":
        day = int(spec["month_day"])
        y, mo = now_l.year, now_l.month
        for _ in range(14):
            last = calendar.monthrange(y, mo)[1]
            cand = datetime(y, mo, min(day, last), h, m)
            if cand > now_l:
                return _from_local(cand)
            mo += 1
            if mo > 12:
                y, mo = y + 1, 1
    return None                                                      # pragma: no cover


def describe(spec: dict) -> str:
    kind = spec["kind"]
    if kind == "interval":
        n = int(spec["every_minutes"])
        if n % 1440 == 0:
            return f"Every {n // 1440} day(s)" if n != 1440 else "Every day"
        if n % 60 == 0:
            return f"Every {n // 60} hour(s)" if n != 60 else "Every hour"
        return f"Every {n} minutes"
    if kind == "once":
        at = _parse(spec.get("run_at"))
        return "Once, " + (_local(at).strftime("%d %b %Y at %H:%M") if at else "?")
    t = spec["at_time"]
    if kind == "daily":
        return f"Every day at {t}"
    if kind == "weekly":
        days = sorted({int(x) for x in str(spec["weekdays"]).split(",") if x != ""})
        if days == list(range(7)):
            return f"Every day at {t}"
        if days == [0, 1, 2, 3, 4]:
            return f"Weekdays at {t}"
        return "Every " + ", ".join(WEEKDAYS[d] for d in days) + f" at {t}"
    d = int(spec["month_day"])
    suffix = "th" if 10 <= d % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(d % 10, "th")
    return f"Monthly on the {d}{suffix} at {t}"


# ====================================================================== actions
# key -> label, description, group, heavy (postponed on battery), per_user, admin (who may schedule it), params
ACTIONS: dict[str, dict] = {
    "scan_quick": {"label": "Quick scan", "group": "Antivirus", "heavy": False,
                   "description": "Running programs, startup items and the usual hiding places"},
    "scan_full": {"label": "Full scan", "group": "Antivirus", "heavy": True,
                  "description": "Every file on every local drive (can take hours)"},
    "scan_custom": {"label": "Custom scan", "group": "Antivirus", "heavy": True,
                    "description": "The folders you choose", "params": {"paths": "list of full folder / file paths"}},
    "posture_check": {"label": "Windows security check", "group": "Device security", "heavy": False,
                      "description": "Re-check Defender, UAC, BitLocker, updates and the other device settings"},
    "windows_update_check": {"label": "Look for Windows updates", "group": "Device security", "heavy": False,
                             "description": "Ask Windows Update whether updates are waiting"},
    "firewall_check": {"label": "Firewall health check", "group": "Firewall & network", "heavy": False,
                       "description": "Re-read the firewall profiles and rules and score them"},
    "network_check": {"label": "Network health check", "group": "Firewall & network", "heavy": False,
                      "description": "Connections, listening ports and Wi-Fi safety"},
    "lan_scan": {"label": "Scan my network for devices", "group": "Firewall & network", "heavy": False,
                 "description": "Find the devices on the home / office network you are connected to"},
    "intel_update": {"label": "Update threat feeds", "group": "Threat intelligence", "heavy": False,
                     "description": "Download the newest lists of malicious addresses, sites and file hashes"},
    "web_rescan": {"label": "Re-scan monitored websites", "group": "Website scanner", "heavy": False,
                   "description": "Run the due scans of saved sites / projects that have monitoring on"},
    "breach_list_update": {"label": "Update the breach list", "group": "Accounts & platforms", "heavy": False,
                           "description": "Download the public list of breached sites (no personal data is sent)"},
    "extensions_audit": {"label": "Audit browser / editor extensions", "group": "Accounts & platforms",
                         "heavy": False, "description": "Look for new risky browser and code-editor extensions"},
    "privacy_clean": {"label": "Privacy clean-up", "group": "Data protection", "heavy": True, "per_user": True,
                      "description": "Delete temporary files and other junk (only the categories you pick)",
                      "params": {"categories": "cleaner category ids - default: temporary files only"}},
    "sensitive_scan": {"label": "Search for sensitive files", "group": "Data protection", "heavy": True,
                       "per_user": True,
                       "description": "Look for keys, password lists, card numbers and CNICs left in your folders"},
    "security_report": {"label": "Create a security report", "group": "Reports & backup", "heavy": False,
                        "per_user": True, "description": "Save a report of this PC's security state",
                        "params": {"type": "summary | threats | device | network | accounts | activity | full",
                                   "format": "pdf | html | csv | json", "days": "period covered"}},
    "backup": {"label": "Back up Cyber Hub", "group": "Reports & backup", "heavy": False,
               "description": "Encrypted backup of settings, history and vaults for this PC "
                              "(restorable on this Windows account)"},
}


class SchedulerService:
    def __init__(self, db: Database, settings, activity, *, notifications=None, accounts=None, scanner=None,
                 posture=None, firewall=None, network=None, intel=None, web=None, platforms=None,
                 data_protection=None, reports=None, backup=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.notifications, self.accounts = notifications, accounts
        self.scanner, self.posture, self.firewall, self.network = scanner, posture, firewall, network
        self.intel, self.web, self.platforms, self.data_protection = intel, web, platforms, data_protection
        self.reports, self.backup = reports, backup
        self._lock = threading.RLock()
        self._running: dict[int, threading.Thread] = {}              # schedule id -> worker
        self._manual: set[threading.Thread] = set()
        self._stopping = threading.Event()
        self.clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)   # tests move time
        self.on_battery: Callable[[], bool] = _on_battery
        self._recover()
        self._seed_defaults()

    # ------------------------------------------------------------------ helpers
    def _g(self, key: str) -> Any:
        return self.settings.get(key)

    def _row(self, sid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM schedules WHERE id=?", (sid,))
        if not r:
            raise SchedulerError(404, "Schedule not found")
        return r

    def _public(self, r: dict) -> dict:
        a = ACTIONS.get(r["action"], {})
        out = {k: r[k] for k in ("id", "name", "action", "kind", "every_minutes", "at_time", "month_day", "run_at",
                                 "builtin", "created_by", "created_at", "next_run_at", "last_run_at", "last_status",
                                 "last_detail", "user_id")}
        out["params"] = json.loads(r["params"] or "{}")
        out["weekdays"] = [int(x) for x in (r["weekdays"] or "").split(",") if x != ""]
        out["enabled"], out["catch_up"] = bool(r["enabled"]), bool(r["catch_up"])
        out["action_label"], out["group"] = a.get("label", r["action"]), a.get("group", "Other")
        out["available"] = self._available(r["action"]) is None
        out["when"] = describe(r)
        out["running"] = r["id"] in self._running and self._running[r["id"]].is_alive()
        return out

    def _available(self, action: str) -> str | None:
        """None when the action can run here, otherwise why not."""
        need = {"scan_quick": self.scanner, "scan_full": self.scanner, "scan_custom": self.scanner,
                "posture_check": self.posture, "windows_update_check": self.posture,
                "firewall_check": self.firewall, "network_check": self.network, "lan_scan": self.network,
                "intel_update": self.intel, "web_rescan": self.web, "breach_list_update": self.platforms,
                "extensions_audit": self.platforms, "privacy_clean": self.data_protection,
                "sensitive_scan": self.data_protection, "security_report": self.reports, "backup": self.backup}
        if action not in ACTIONS:
            return "Unknown action"
        return None if need.get(action) is not None else "This module isn't loaded"

    def _owner(self, user_id: int | None) -> dict | None:
        if user_id is not None:
            u = self.db.fetchone("SELECT * FROM users WHERE id=?", (user_id,))
            if u:
                return u
        return self.db.fetchone("SELECT * FROM users WHERE role='admin' ORDER BY id LIMIT 1")

    def _recover(self) -> None:
        n = self.db.execute("UPDATE schedule_runs SET status='interrupted', finished_at=?, "
                            "detail='Cyber Hub was closed while this was running' WHERE status='running'",
                            (_iso(),)).rowcount
        if n:
            log.info("%s scheduled run(s) were interrupted by the last shutdown", n)

    def _seed_defaults(self) -> None:
        """Sensible schedules on first start. Created once; the user can change or delete them freely."""
        defaults = [
            ("quick_scan_daily", "Daily quick scan", "scan_quick", {}, "daily", "13:00", None, None, 1),
            ("full_scan_weekly", "Weekly full scan", "scan_full", {}, "weekly", "11:00", "6", None, 0),
            ("report_weekly", "Weekly security report", "security_report",
             {"type": "summary", "format": "pdf", "days": 7}, "weekly", "09:00", "0", None, 1),
            ("backup_weekly", "Weekly backup", "backup", {}, "weekly", "20:00", "6", None, 0),
            ("clean_weekly", "Weekly privacy clean-up", "privacy_clean", {"categories": ["temp"]}, "weekly",
             "18:00", "4", None, 0),
            ("finder_monthly", "Monthly sensitive-file search", "sensitive_scan", {}, "monthly", "15:00", None, 1, 0),
        ]
        now = self.clock()
        for key, name, action, params, kind, at, weekdays, mday, enabled in defaults:
            if self.db.fetchone("SELECT 1 AS x FROM notify_state WHERE key=?", (f"seeded:{key}",)):
                continue
            spec = {"kind": kind, "at_time": at, "weekdays": weekdays, "month_day": mday}
            nxt = next_run(spec, now)
            self.db.execute("INSERT OR IGNORE INTO schedules(name, action, params, kind, at_time, weekdays, month_day, "
                            "enabled, catch_up, builtin, next_run_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (name, action, json.dumps(params), kind, at, weekdays, mday, enabled,
                             1 if action in ("scan_quick", "security_report", "backup") else 0, key,
                             _iso(nxt) if nxt else None))
            self.db.execute("INSERT OR REPLACE INTO notify_state(key, value) VALUES (?, '1')", (f"seeded:{key}",))

    # ------------------------------------------------------------------ validation
    def _validate(self, body: dict, existing: dict | None = None) -> dict:
        cur = dict(existing or {})
        spec: dict[str, Any] = {
            "name": body.get("name", cur.get("name")),
            "action": body.get("action", cur.get("action")),
            "kind": body.get("kind", cur.get("kind")),
            "every_minutes": body.get("every_minutes", cur.get("every_minutes")),
            "at_time": body.get("at_time", cur.get("at_time")),
            "month_day": body.get("month_day", cur.get("month_day")),
            "run_at": body.get("run_at", cur.get("run_at")),
            "enabled": body.get("enabled", bool(cur.get("enabled", 1))),
            "catch_up": body.get("catch_up", bool(cur.get("catch_up", 1))),
        }
        wd = body.get("weekdays", None)
        if wd is None:
            wd = [int(x) for x in (cur.get("weekdays") or "").split(",") if x != ""]
        params = body.get("params")
        if params is None:
            params = json.loads(cur["params"]) if cur.get("params") else {}
        name = (spec["name"] or "").strip()
        if not 1 <= len(name) <= 80:
            raise SchedulerError(422, "Give the schedule a name (up to 80 characters)")
        spec["name"] = name
        if spec["action"] not in ACTIONS:
            raise SchedulerError(422, "Unknown action - see GET /api/scheduler/actions")
        why = self._available(spec["action"])
        if why:
            raise SchedulerError(501, f"{ACTIONS[spec['action']]['label']}: {why}")
        if spec["kind"] not in KINDS:
            raise SchedulerError(422, "kind must be interval, daily, weekly, monthly or once")
        k = spec["kind"]
        clean = {"every_minutes": None, "at_time": None, "weekdays": None, "month_day": None, "run_at": None}
        if k == "interval":
            n = spec["every_minutes"]
            if not isinstance(n, int) or isinstance(n, bool) or not 5 <= n <= 43200:
                raise SchedulerError(422, "every_minutes must be between 5 and 43200 (30 days)")
            if ACTIONS[spec["action"]].get("heavy") and n < 60:
                raise SchedulerError(422, f"{ACTIONS[spec['action']]['label']} can't run more often than hourly")
            clean["every_minutes"] = n
        elif k == "once":
            at = _parse(spec["run_at"]) if isinstance(spec["run_at"], str) else None
            if not at:
                raise SchedulerError(422, "run_at must be a date and time, e.g. 2026-12-01T14:30:00")
            if existing is None and at <= self.clock():
                raise SchedulerError(422, "run_at must be in the future")
            clean["run_at"] = _iso(at)
        else:
            _hhmm(spec["at_time"])
            clean["at_time"] = spec["at_time"]
            if k == "weekly":
                if (not isinstance(wd, list) or not wd or len(wd) > 7
                        or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in wd)):
                    raise SchedulerError(422, "weekdays must be a list of days, Monday = 0 ... Sunday = 6")
                clean["weekdays"] = ",".join(str(d) for d in sorted(set(wd)))
            if k == "monthly":
                d = spec["month_day"]
                if not isinstance(d, int) or isinstance(d, bool) or not 1 <= d <= 31:
                    raise SchedulerError(422, "month_day must be between 1 and 31")
                clean["month_day"] = d
        if not isinstance(params, dict):
            raise SchedulerError(422, "params must be an object")
        params = self._check_params(spec["action"], params)
        if not isinstance(spec["enabled"], bool) or not isinstance(spec["catch_up"], bool):
            raise SchedulerError(422, "enabled and catch_up must be true or false")
        return {**spec, **clean, "params": params}

    def _check_params(self, action: str, p: dict) -> dict:
        if len(json.dumps(p)) > 8000:
            raise SchedulerError(422, "params are too large")
        if action == "scan_custom":
            paths = p.get("paths")
            if (not isinstance(paths, list) or not paths or len(paths) > 50
                    or not all(isinstance(x, str) and 0 < len(x) <= 1024 for x in paths)):
                raise SchedulerError(422, "A custom scan needs params.paths: 1-50 full folder / file paths")
            return {"paths": paths}
        if action == "privacy_clean":
            cats = p.get("categories") or ["temp"]
            if not isinstance(cats, list) or len(cats) > 60 or not all(isinstance(x, str) and len(x) <= 80 for x in cats):
                raise SchedulerError(422, "params.categories must be a list of cleaner category ids")
            if self.data_protection is not None:
                known = {c.id: c for c in self.data_protection.cleaner.categories(
                    self.settings.get("dp_cleaner_temp_min_age_hours"))}
                risky = [known[c].label for c in cats if c in known and known[c].needs_confirm]
                if risky:
                    raise SchedulerError(422, f"{', '.join(risky)} can't be cleaned automatically - these sign you "
                                              "out of websites or delete history, so they always need a click")
            return {"categories": cats}
        if action == "security_report":
            out = {"type": p.get("type", "summary"), "format": p.get("format") or self._g("report_default_format"),
                   "days": p.get("days", 7)}
            if self.reports is not None:
                try:
                    self.reports.check_request(out["type"], out["format"], out["days"])
                except Exception as e:
                    raise SchedulerError(422, getattr(e, "message", str(e)))
            return out
        return {}

    # ------------------------------------------------------------------ CRUD
    def list(self) -> dict:
        rows = self.db.fetchall("SELECT * FROM schedules ORDER BY enabled DESC, next_run_at IS NULL, next_run_at, id")
        return {"items": [self._public(r) for r in rows], "enabled": bool(self._g("scheduler_enabled")),
                "now": _iso(self.clock())}

    def get(self, sid: int) -> dict:
        out = self._public(self._row(sid))
        out["runs"] = self.runs(schedule_id=sid, limit=10)["items"]
        return out

    def create(self, cu, body: dict) -> dict:
        if self.db.fetchone("SELECT COUNT(*) AS n FROM schedules")["n"] >= MAX_SCHEDULES:
            raise SchedulerError(413, f"At most {MAX_SCHEDULES} schedules")
        s = self._validate(body)
        nxt = next_run(s, self.clock()) if s["enabled"] else None
        cur = self.db.execute(
            "INSERT INTO schedules(name, action, params, kind, every_minutes, at_time, weekdays, month_day, run_at, "
            "enabled, catch_up, user_id, created_by, next_run_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (s["name"], s["action"], json.dumps(s["params"]), s["kind"], s["every_minutes"], s["at_time"],
             s["weekdays"], s["month_day"], s["run_at"], int(s["enabled"]), int(s["catch_up"]), cu.user["id"],
             cu.user["username"], _iso(nxt) if nxt else None))
        self.activity.record("scheduler", f"Schedule created: {s['name']}", describe(s), source="scheduler")
        return self._public(self._row(cur.lastrowid))

    def update(self, cu, sid: int, body: dict) -> dict:
        row = self._row(sid)
        s = self._validate(body, row)
        nxt = next_run(s, self.clock()) if s["enabled"] else None
        self.db.execute(
            "UPDATE schedules SET name=?, action=?, params=?, kind=?, every_minutes=?, at_time=?, weekdays=?, "
            "month_day=?, run_at=?, enabled=?, catch_up=?, next_run_at=? WHERE id=?",
            (s["name"], s["action"], json.dumps(s["params"]), s["kind"], s["every_minutes"], s["at_time"],
             s["weekdays"], s["month_day"], s["run_at"], int(s["enabled"]), int(s["catch_up"]),
             _iso(nxt) if nxt else None, sid))
        self.activity.record("scheduler", f"Schedule changed: {s['name']}",
                             f"{describe(s)} - {'on' if s['enabled'] else 'off'} (by {cu.user['username']})",
                             source="scheduler")
        return self._public(self._row(sid))

    def delete(self, cu, sid: int) -> dict:
        row = self._row(sid)
        self.db.execute("DELETE FROM schedules WHERE id=?", (sid,))
        self.activity.record("scheduler", f"Schedule deleted: {row['name']}", f"by {cu.user['username']}",
                             severity="low", source="scheduler")
        return {"deleted": True, "id": sid}

    def actions(self) -> list[dict]:
        out = []
        for key, a in ACTIONS.items():
            why = self._available(key)
            out.append({"id": key, "label": a["label"], "group": a["group"], "description": a["description"],
                        "heavy": bool(a.get("heavy")), "per_user": bool(a.get("per_user")),
                        "params": a.get("params", {}), "available": why is None, "reason": why})
        return out

    def upcoming(self, hours: int = 168, limit: int = 60) -> list[dict]:
        """Planned runs in the next `hours` - for a calendar / timeline view."""
        now = self.clock()
        end = now + timedelta(hours=hours)
        out: list[dict] = []
        for r in self.db.fetchall("SELECT * FROM schedules WHERE enabled=1"):
            t = _parse(r["next_run_at"]) or next_run(r, now)
            n = 0
            while t and t <= end and n < 40:
                out.append({"schedule_id": r["id"], "name": r["name"], "action": r["action"],
                            "action_label": ACTIONS.get(r["action"], {}).get("label", r["action"]), "at": _iso(t)})
                t, n = next_run(r, t), n + 1
        out.sort(key=lambda x: x["at"])
        return out[:limit]

    def runs(self, schedule_id: int | None = None, status: str | None = None, limit: int = 50,
             offset: int = 0) -> dict:
        where, params = [], []
        if schedule_id is not None:
            where.append("schedule_id=?"); params.append(schedule_id)
        if status:
            where.append("status=?"); params.append(status)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM schedule_runs {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM schedule_runs {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        for r in rows:
            r["result"] = json.loads(r["result"]) if r.get("result") else None
            r["action_label"] = ACTIONS.get(r["action"], {}).get("label", r["action"])
            st, fi = _parse(r["started_at"]), _parse(r["finished_at"])
            r["duration_seconds"] = round((fi - st).total_seconds(), 1) if st and fi else None
        return {"items": rows, "total": total, "limit": limit, "offset": offset}

    def status(self) -> dict:
        rows = self.db.fetchall("SELECT * FROM schedules")
        nxt = min((r["next_run_at"] for r in rows if r["enabled"] and r["next_run_at"]), default=None)
        nxt_row = next((r for r in rows if r["enabled"] and r["next_run_at"] == nxt), None) if nxt else None
        since = _iso(self.clock() - timedelta(days=7))
        st = {r["status"]: r["n"] for r in self.db.fetchall(
            "SELECT status, COUNT(*) AS n FROM schedule_runs WHERE started_at >= ? GROUP BY status", (since,))}
        by_day = self.db.fetchall("SELECT substr(started_at,1,10) AS day, COUNT(*) AS runs, SUM(status='failed') AS "
                                  "failed FROM schedule_runs WHERE started_at >= ? GROUP BY day ORDER BY day",
                                  (_iso(self.clock() - timedelta(days=30)),))
        last = self.db.fetchone("SELECT * FROM schedule_runs ORDER BY id DESC LIMIT 1")
        return {"enabled": bool(self._g("scheduler_enabled")), "schedules": len(rows),
                "active": sum(1 for r in rows if r["enabled"]),
                "running": [self._public(r)["name"] for r in rows if r["id"] in self._running
                            and self._running[r["id"]].is_alive()],
                "next": {"at": nxt, "name": nxt_row["name"], "schedule_id": nxt_row["id"]} if nxt_row else None,
                "last_run": {k: last[k] for k in ("id", "name", "status", "started_at", "detail")} if last else None,
                "runs_7_days": st, "by_day": by_day, "on_battery": self._battery(),
                "skip_on_battery": bool(self._g("scheduler_skip_on_battery")),
                "timezone": time.strftime("%Z"), "now": _iso(self.clock()), "weekdays": WEEKDAYS}

    def _battery(self) -> bool:
        try:
            return bool(self.on_battery())
        except Exception:                                            # pragma: no cover
            return False

    # ------------------------------------------------------------------ running
    def run_now(self, cu, sid: int, wait: bool = False) -> dict:
        row = self._row(sid)
        with self._lock:
            t = self._running.get(sid)
            if t and t.is_alive():
                raise SchedulerError(409, f"'{row['name']}' is already running")
            run_id = self._begin(row, "manual", None, cu.user["username"])
            t = threading.Thread(target=self._execute, args=(row, run_id, cu.user), daemon=True,
                                 name=f"cyberhub-sched-{sid}")
            self._running[sid] = t
            t.start()
        if wait:
            t.join()
        return self.db.fetchone("SELECT * FROM schedule_runs WHERE id=?", (run_id,))

    def _begin(self, row: dict, trigger: str, planned: str | None, by: str) -> int:
        return self.db.execute("INSERT INTO schedule_runs(schedule_id, name, action, trigger, planned_at, started_by) "
                               "VALUES (?,?,?,?,?,?)", (row["id"], row["name"], row["action"], trigger, planned,
                                                        by)).lastrowid

    def _record_skip(self, row: dict, planned: str | None, why: str) -> None:
        self.db.execute("INSERT INTO schedule_runs(schedule_id, name, action, trigger, status, planned_at, "
                        "finished_at, detail, started_by) VALUES (?,?,?,?,?,?,?,?,?)",
                        (row["id"], row["name"], row["action"], "schedule", "skipped", planned, _iso(), why, "system"))
        self.db.execute("UPDATE schedules SET last_status='skipped', last_detail=? WHERE id=?", (why, row["id"]))

    def tick(self) -> dict:
        """Called every few seconds: start whatever is due. Returns what happened (used by the tests)."""
        out = {"started": [], "skipped": [], "postponed": []}
        if self._stopping.is_set() or not self._g("scheduler_enabled"):
            return out
        now = self.clock()
        due = self.db.fetchall("SELECT * FROM schedules WHERE enabled=1 AND next_run_at IS NOT NULL AND "
                               "next_run_at <= ? ORDER BY next_run_at", (_iso(now),))
        for row in due:
            planned = _parse(row["next_run_at"]) or now
            late = (now - planned).total_seconds()
            nxt = next_run(row, now)
            with self._lock:
                t = self._running.get(row["id"])
                busy = bool(t and t.is_alive())
                if busy:
                    self._record_skip(row, row["next_run_at"], "The previous run was still going")
                    out["skipped"].append(row["id"])
                elif late > GRACE_SECONDS and not row["catch_up"]:
                    self._record_skip(row, row["next_run_at"], "The PC was off or asleep at the planned time")
                    out["skipped"].append(row["id"])
                elif ACTIONS.get(row["action"], {}).get("heavy") and self._g("scheduler_skip_on_battery") \
                        and self._battery():
                    nxt = now + timedelta(minutes=30)
                    self.db.execute("UPDATE schedules SET last_detail=? WHERE id=?",
                                    ("Waiting for mains power (on battery)", row["id"]))
                    out["postponed"].append(row["id"])
                else:
                    run_id = self._begin(row, "catch_up" if late > GRACE_SECONDS else "schedule", row["next_run_at"],
                                         "system")
                    t = threading.Thread(target=self._execute, args=(row, run_id, None), daemon=True,
                                         name=f"cyberhub-sched-{row['id']}")
                    self._running[row["id"]] = t
                    t.start()
                    out["started"].append(row["id"])
                if row["kind"] == "once" and row["id"] not in out["postponed"]:
                    self.db.execute("UPDATE schedules SET enabled=0, next_run_at=NULL WHERE id=?", (row["id"],))
                else:
                    self.db.execute("UPDATE schedules SET next_run_at=? WHERE id=?",
                                    (_iso(nxt) if nxt else None, row["id"]))
        return out

    def wait_idle(self, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self._lock:
                alive = [t for t in self._running.values() if t.is_alive()]
            if not alive:
                return True
            time.sleep(0.02)
        return False

    def _execute(self, row: dict, run_id: int, by_user: dict | None) -> None:
        status, detail, result = "ok", "", None
        try:
            why = self._available(row["action"])
            if why:
                raise SchedulerError(501, why)
            user = by_user if (by_user and ACTIONS[row["action"]].get("per_user")) else self._owner(row["user_id"])
            detail, result = self._do(row["action"], json.loads(row["params"] or "{}"), user,
                                      by_user["username"] if by_user else "scheduler")
        except Exception as e:
            status = "failed"
            detail = (getattr(e, "message", None) or str(e) or type(e).__name__)[:500]
            if not hasattr(e, "status"):
                log.exception("Scheduled job '%s' failed", row["name"])
        try:
            self.db.execute("UPDATE schedule_runs SET status=?, finished_at=?, detail=?, result=? WHERE id=?",
                            (status, _iso(), detail, json.dumps(result, default=str) if result is not None else None,
                             run_id))
            self.db.execute("UPDATE schedules SET last_run_at=?, last_status=?, last_detail=? WHERE id=?",
                            (_iso(), status, detail, row["id"]))
            sev = "medium" if status == "failed" else "info"
            self.activity.record("scheduler", f"{row['name']}: {'failed' if status == 'failed' else 'done'}", detail,
                                 severity=sev, source="scheduler")
            if status == "failed" and self.notifications is not None:
                self.notifications.notify("scheduler", "medium", f"Scheduled job failed: {row['name']}", detail,
                                          kind="run_failed", link="scheduler")
        except Exception:                                            # DB closed during shutdown
            pass

    # ---- what each action does. Returns (one-line outcome, facts dict)
    def _do(self, action: str, p: dict, user: dict | None, by: str) -> tuple[str, dict | None]:
        if action in ("scan_quick", "scan_full", "scan_custom"):
            kind = action.split("_", 1)[1]
            job = self.scanner.start(kind, by, p.get("paths"))
            j = self._wait(lambda: self.scanner.get(job["id"]),
                           lambda j: j["status"] not in ("queued", "running", "paused"))
            if j["status"] != "completed":
                raise SchedulerError(500, f"Scan {j['status']}" + (f": {j.get('message')}" if j.get("message") else ""))
            return (f"{j['files_scanned']:,} files scanned, {j['threats_found']} threat(s) found",
                    {"job_id": j["id"], "files_scanned": j["files_scanned"], "threats_found": j["threats_found"],
                     "files_skipped": j["files_skipped"]})
        if action == "posture_check":
            a = self.posture.analyze(refresh=True)
            return (f"Score {a['score']} ({a['grade']}), {a['totals']['failed']} issue(s) of {a['totals']['checks']} "
                    f"checks", {"score": a["score"], "grade": a["grade"], "failed": a["totals"]["failed"]})
        if action == "windows_update_check":
            r = self.posture.start_update_search(by)
            return "Looking for Windows updates", {"state": r.get("state") if isinstance(r, dict) else None}
        if action == "firewall_check":
            a = self.firewall.analyze(refresh=True)
            return (f"Score {a['score']} ({a['grade']}), {len(a['findings'])} finding(s)",
                    {"score": a["score"], "grade": a["grade"], "findings": len(a["findings"])})
        if action == "network_check":
            a = self.network.analyze(refresh=True)
            return (f"Score {a['score']}, {len(a.get('findings', []))} finding(s)",
                    {"score": a["score"], "findings": len(a.get("findings", []))})
        if action == "lan_scan":
            r = self.network.start_scan(by)
            return "Network device scan started", {"state": r.get("state") if isinstance(r, dict) else None}
        if action == "intel_update":
            r = self.intel.refresh(None, force=False, wait=True)
            if r.get("status") == "failed":
                raise SchedulerError(500, r.get("error") or "Feed update failed")
            res = r.get("result") or {}
            facts = {k: v for k, v in res.items() if isinstance(v, (int, str, bool))}
            done = r.get("progress", {}).get("done", 0)
            return (f"{done} threat feed(s) checked" + (" (still running)" if r.get("status") == "running" else ""),
                    {"job_id": r.get("id"), "status": r.get("status"), **facts})
        if action == "web_rescan":
            r = self.web.watch_once()
            return f"{len(r.get('started', []))} monitored target(s) re-scanned", r
        if action == "breach_list_update":
            r = self.platforms.refresh_catalog(force=False)
            if r.get("error"):
                raise SchedulerError(502, f"Breach list download failed: {r['error']}")
            return (f"{r.get('breaches', 0)} known breaches, {r.get('added', 0)} new",
                    {"breaches": r.get("breaches"), "added": r.get("added"), "changed": r.get("changed")})
        if action == "extensions_audit":
            n = self.platforms.watch_extensions()
            return f"{n} new risky extension(s)", {"new_risky": n}
        if action in ("privacy_clean", "sensitive_scan"):
            if not user:
                raise SchedulerError(409, "No Cyber Hub account exists yet")
            cu = _RunAs(user)
            dp = self.data_protection
            if action == "privacy_clean":
                job = dp.start_clean(cu, p.get("categories") or ["temp"], confirm=False)
            else:
                job = dp.start_finder(cu)
            j = self._wait(lambda: dp.job(cu, job["id"]), lambda j: j["status"] not in ("queued", "running"))
            if j["status"] != "done":
                raise SchedulerError(500, f"Job {j['status']}" + (f": {j.get('error')}" if j.get("error") else ""))
            res = j.get("result") or {}
            if action == "privacy_clean":
                return f"Freed {res.get('size', '0 B')} ({res.get('files', 0)} item(s))", \
                    {"job_id": j["id"], "bytes": res.get("bytes", 0), "files": res.get("files", 0)}
            return (f"{res.get('new', res.get('found', 0))} new sensitive file(s) found",
                    {"job_id": j["id"], **{k: v for k, v in res.items() if isinstance(v, (int, str))}})
        if action == "security_report":
            if not user:
                raise SchedulerError(409, "No Cyber Hub account exists yet")
            r = self.reports.generate(_RunAs(user), p.get("type", "summary"), p.get("format") or "pdf",
                                      int(p.get("days", 7)), source="schedule")
            return f"Report saved: {r['file_name']}", {"report_id": r["id"], "file_name": r["file_name"]}
        if action == "backup":
            r = self.backup.create(_RunAs(user) if user else None, mode="device", source="schedule")
            return f"Backup saved: {r['file_name']} ({r['size_text']})", {"backup_id": r["id"],
                                                                          "file_name": r["file_name"]}
        raise SchedulerError(422, "Unknown action")                  # pragma: no cover

    def _wait(self, poll: Callable[[], dict], done: Callable[[dict], bool]) -> dict:
        end = time.monotonic() + WAIT_LIMIT
        delay = 0.05
        while True:
            j = poll()
            if done(j):
                return j
            if self._stopping.is_set():
                raise SchedulerError(503, "Cyber Hub is closing")
            if time.monotonic() > end:
                raise SchedulerError(504, "The job did not finish in time")
            time.sleep(delay)
            delay = min(delay * 1.5, 2.0)

    # ------------------------------------------------------------------ housekeeping
    def cleanup(self) -> int:
        days = int(self._g("scheduler_history_days"))
        n = self.db.execute("DELETE FROM schedule_runs WHERE started_at < ? AND status != 'running'",
                            (_iso(self.clock() - timedelta(days=days)),)).rowcount
        with self._lock:
            for sid in [s for s, t in self._running.items() if not t.is_alive()]:
                self._running.pop(sid, None)
        return n

    def shutdown(self, timeout: float = 3.0) -> None:
        self._stopping.set()
        with self._lock:
            threads = list(self._running.values())
        for t in threads:
            t.join(timeout=timeout)


def _on_battery() -> bool:
    import psutil
    b = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    return bool(b and b.power_plugged is False)


async def scheduler_loop(svc: SchedulerService, every_seconds: float = 15.0) -> None:
    import asyncio
    ticks = 0
    await asyncio.sleep(5)
    while True:
        try:
            await asyncio.to_thread(svc.tick)
            ticks += 1
            if ticks % 240 == 0:                                     # hourly
                await asyncio.to_thread(svc.cleanup)
        except Exception as e:                                       # pragma: no cover
            log.warning("Scheduler tick failed: %s", e)
        await asyncio.sleep(every_seconds)
