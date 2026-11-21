"""
Cyber Hub Backend - Activity / event log service
Developed by Syed Muhammad Tayyab

Every module (scanner, firewall, accounts, ...) records events here.
The UI's "Recent activity" list and the threat timeline graph read from it.
"""
from __future__ import annotations

from ..database import Database

CATEGORIES = {"system", "account", "scan", "threat", "network", "firewall", "privacy",
              "data", "web", "intel", "platform", "scheduler", "report", "settings",
              "process", "startup", "realtime", "device", "rules", "posture", "passwords"}
SEVERITIES = ["info", "low", "medium", "high", "critical"]


class ActivityService:
    def __init__(self, db: Database):
        self.db = db

    def record(self, category: str, title: str, detail: str | None = None,
               severity: str = "info", source: str = "backend") -> dict:
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category '{category}'")
        if severity not in SEVERITIES:
            raise ValueError(f"Unknown severity '{severity}'")
        cur = self.db.execute(
            "INSERT INTO activity_log(category, severity, title, detail, source) VALUES (?,?,?,?,?)",
            (category, severity, title, detail, source),
        )
        return self.db.fetchone("SELECT * FROM activity_log WHERE id=?", (cur.lastrowid,))

    def list(self, limit: int = 50, offset: int = 0, category: str | None = None,
             severity: str | None = None) -> dict:
        where, params = [], []
        if category:
            where.append("category=?"); params.append(category)
        if severity:
            where.append("severity=?"); params.append(severity)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM activity_log {clause}", tuple(params))["n"]
        items = self.db.fetchall(
            f"SELECT * FROM activity_log {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset),
        )
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    def summary(self, days: int = 7) -> dict:
        """Counts per severity and per day - feeds the donut + bar charts."""
        by_sev = self.db.fetchall(
            "SELECT severity, COUNT(*) AS n FROM activity_log "
            "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) GROUP BY severity",
            (f"-{days} days",),
        )
        by_day = self.db.fetchall(
            "SELECT substr(ts,1,10) AS day, COUNT(*) AS n FROM activity_log "
            "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) GROUP BY day ORDER BY day",
            (f"-{days} days",),
        )
        by_cat = self.db.fetchall(
            "SELECT category, COUNT(*) AS n FROM activity_log "
            "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) GROUP BY category ORDER BY n DESC",
            (f"-{days} days",),
        )
        sev = {s: 0 for s in SEVERITIES}
        sev.update({r["severity"]: r["n"] for r in by_sev})
        return {"days": days, "by_severity": sev, "by_day": by_day, "by_category": by_cat}

    def clear(self, older_than_days: int | None = None) -> int:
        if older_than_days is None:
            return self.db.execute("DELETE FROM activity_log").rowcount
        return self.db.execute(
            "DELETE FROM activity_log WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)",
            (f"-{older_than_days} days",),
        ).rowcount
