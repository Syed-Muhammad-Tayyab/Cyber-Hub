"""
Cyber Hub Backend - Resource alert engine (Part 3)
Developed by Syed Muhammad Tayyab

Watches CPU, memory, disk space, GPU and CPU temperature against the
thresholds in Settings.

  * An alert opens only after a value stays over its threshold for
    `alert_sustain_seconds` (a 2-second CPU spike is not an alert).
  * It closes once the value falls a margin below the threshold
    (hysteresis), so it does not flap open/closed around the line.
  * Severity: medium when over the threshold, high when far over it.
  * Every open/close is written to the activity log, which feeds the
    dashboard timeline, and is stored in `resource_alerts` for the
    alert list on the Live Monitor page.
"""
from __future__ import annotations

import asyncio
import threading
import time

from ..database import Database
from ..logger import get_logger
from .activity import ActivityService
from .settings_store import SettingsStore

METRICS: dict[str, dict] = {
    "cpu":         {"setting": "alert_cpu_percent",    "label": "CPU usage",       "unit": "%",  "margin": 10},
    "memory":      {"setting": "alert_memory_percent", "label": "Memory usage",    "unit": "%",  "margin": 5},
    "disk_space":  {"setting": "alert_disk_percent",   "label": "Disk space used", "unit": "%",  "margin": 2},
    "gpu":         {"setting": "alert_gpu_percent",    "label": "GPU usage",       "unit": "%",  "margin": 10},
    "temperature": {"setting": "alert_temperature_c",  "label": "CPU temperature", "unit": "°C", "margin": 5},
}

THRESHOLD_KEYS = [m["setting"] for m in METRICS.values()] + ["alert_sustain_seconds", "monitor_alerts_enabled"]


def severity_for(metric: str, value: float, threshold: float) -> str:
    if metric == "temperature":
        return "high" if value >= threshold + 10 else "medium"
    # "far over": halfway between the threshold and 100 %, e.g. 90 -> 95, 80 -> 90
    return "high" if value >= threshold + (100 - threshold) / 2 else "medium"


class AlertEngine:
    def __init__(self, db: Database, settings: SettingsStore, activity: ActivityService):
        self.db, self.settings, self.activity = db, settings, activity
        self._since: dict[tuple[str, str], float] = {}     # (metric, target) -> first time over threshold
        self._lock = threading.Lock()

    def thresholds(self) -> dict:
        return {k: self.settings.get(k) for k in THRESHOLD_KEYS}

    def _active(self, metric: str, target: str) -> dict | None:
        return self.db.fetchone(
            "SELECT * FROM resource_alerts WHERE metric=? AND target=? AND status='active'", (metric, target))

    def evaluate(self, readings: list[tuple[str, str, float | None]], now: float | None = None) -> list[dict]:
        """Feed current readings; returns the list of open/escalate/resolve events it caused."""
        if not self.settings.get("monitor_alerts_enabled"):
            return []
        now = time.monotonic() if now is None else now
        sustain = self.settings.get("alert_sustain_seconds")
        events: list[dict] = []
        with self._lock:
            for metric, target, value in readings:
                if value is None or metric not in METRICS:
                    continue
                m = METRICS[metric]
                threshold = self.settings.get(m["setting"])
                key = (metric, target)
                active = self._active(metric, target)
                if value >= threshold:
                    first = self._since.setdefault(key, now)
                    if active:
                        events += self._update(active, metric, value, threshold)
                    elif now - first >= sustain:
                        events.append(self._open(metric, target, value, threshold, int(now - first)))
                else:
                    self._since.pop(key, None)
                    if active:
                        if value <= threshold - m["margin"]:
                            events.append(self._resolve(active, value))
                        else:
                            self.db.execute("UPDATE resource_alerts SET value=? WHERE id=?", (value, active["id"]))
        return events

    # ------------------------------------------------------------ transitions
    @staticmethod
    def _what(metric: str, target: str) -> str:
        label = METRICS[metric]["label"]
        return f"{label} on {target}" if metric == "disk_space" else label

    def _open(self, metric, target, value, threshold, held) -> dict:
        unit = METRICS[metric]["unit"]
        sev = severity_for(metric, value, threshold)
        msg = f"{self._what(metric, target)} is {value:.0f}{unit} (limit {threshold}{unit})"
        if held:
            msg += f" for {held}s"
        cur = self.db.execute(
            "INSERT INTO resource_alerts(metric, target, severity, threshold, value, peak, message) "
            "VALUES (?,?,?,?,?,?,?)", (metric, target, sev, threshold, value, value, msg))
        self.activity.record("system", f"High {self._what(metric, target).lower()}", msg, severity=sev,
                             source="monitor")
        return {"event": "opened", "alert": self.get(cur.lastrowid)}

    def _update(self, active, metric, value, threshold) -> list[dict]:
        peak = max(active["peak"], value)
        sev = severity_for(metric, peak, threshold)
        escalated = sev == "high" and active["severity"] != "high"
        self.db.execute("UPDATE resource_alerts SET value=?, peak=?, severity=? WHERE id=?",
                        (value, peak, sev, active["id"]))
        if escalated:
            unit = METRICS[metric]["unit"]
            self.activity.record("system", f"{self._what(metric, active['target'])} critical",
                                 f"Reached {value:.0f}{unit}", severity="high", source="monitor")
            return [{"event": "escalated", "alert": self.get(active["id"])}]
        return []

    def _resolve(self, active, value) -> dict:
        self.db.execute(
            "UPDATE resource_alerts SET status='resolved', value=?, "
            "resolved_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (value, active["id"]))
        unit = METRICS[active["metric"]]["unit"]
        self.activity.record("system", f"{self._what(active['metric'], active['target'])} back to normal",
                             f"Now {value:.0f}{unit} (peak {active['peak']:.0f}{unit})", source="monitor")
        return {"event": "resolved", "alert": self.get(active["id"])}

    # ------------------------------------------------------------ queries / actions
    def get(self, alert_id: int) -> dict | None:
        return self.db.fetchone("SELECT * FROM resource_alerts WHERE id=?", (alert_id,))

    def list(self, status: str = "all", limit: int = 50) -> list[dict]:
        clause, params = "", ()
        if status in ("active", "resolved"):
            clause, params = "WHERE status=?", (status,)
        elif status == "unacknowledged":
            clause = "WHERE acknowledged_at IS NULL"
        return self.db.fetchall(f"SELECT * FROM resource_alerts {clause} ORDER BY id DESC LIMIT ?",
                                params + (limit,))

    def summary(self, days: int = 7) -> dict:
        active = self.db.fetchall("SELECT severity, COUNT(*) n FROM resource_alerts WHERE status='active' "
                                  "GROUP BY severity")
        by_metric = self.db.fetchall(
            "SELECT metric, COUNT(*) n FROM resource_alerts WHERE started_at >= "
            "strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) GROUP BY metric ORDER BY n DESC", (f"-{days} days",))
        by_day = self.db.fetchall(
            "SELECT substr(started_at,1,10) day, COUNT(*) n FROM resource_alerts WHERE started_at >= "
            "strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) GROUP BY day ORDER BY day", (f"-{days} days",))
        unack = self.db.fetchone("SELECT COUNT(*) n FROM resource_alerts WHERE acknowledged_at IS NULL")["n"]
        sev = {"medium": 0, "high": 0}
        sev.update({r["severity"]: r["n"] for r in active})
        return {"days": days, "active": sum(sev.values()), "active_by_severity": sev,
                "unacknowledged": unack, "by_metric": by_metric, "by_day": by_day}

    def acknowledge(self, alert_id: int | None = None) -> int:
        sql = "UPDATE resource_alerts SET acknowledged_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') " \
              "WHERE acknowledged_at IS NULL"
        if alert_id is not None:
            return self.db.execute(sql + " AND id=?", (alert_id,)).rowcount
        return self.db.execute(sql).rowcount

    def clear_resolved(self) -> int:
        return self.db.execute("DELETE FROM resource_alerts WHERE status='resolved'").rowcount


log = get_logger("alerts")


def check_now(engine: AlertEngine) -> list[dict]:
    from . import hardware, monitor
    s = monitor.SAMPLER.sample()
    return engine.evaluate(monitor.readings(s, hardware.gpu_info(), hardware.temperatures()))


async def alert_loop(engine: AlertEngine, settings: SettingsStore) -> None:
    log.info("Resource alert engine started")
    while True:
        try:
            if settings.get("monitor_alerts_enabled"):
                await asyncio.to_thread(check_now, engine)
        except Exception as e:                       # never let the loop die
            log.warning("Alert check failed: %s", e)
        await asyncio.sleep(settings.get("monitor_check_interval_seconds"))
