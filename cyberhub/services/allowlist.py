"""
Cyber Hub Backend - Allowed threats + threat history events (Part 6)
Developed by Syed Muhammad Tayyab

Allowed threats work like Windows Security's "Allow on device": a file whose
SHA-256 is allowed (or any file matching an allowed threat name) is no longer
reported by any scan. Removing the entry makes scans report it again.

threat_event() writes one line of a detection's / quarantine item's timeline
(detected -> quarantined -> restored ...). The scanner (Part 5) and the
quarantine service both call it.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from ..database import Database

KINDS = ("sha256", "threat_name")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def threat_event(db: Database, action: str, detection_id: int | None = None, quarantine_id: str | None = None,
                 username: str | None = None, detail: str | None = None) -> None:
    db.execute("INSERT INTO threat_events(ts, detection_id, quarantine_id, action, username, detail) "
               "VALUES (?,?,?,?,?,?)", (_now(), detection_id, quarantine_id, action, username, detail))


class AllowList:
    def __init__(self, db: Database):
        self.db = db
        self._lock = threading.Lock()
        self._sha: dict[str, int] = {}
        self._names: dict[str, int] = {}
        self.reload()

    def reload(self) -> None:
        rows = self.db.fetchall("SELECT id, kind, value FROM allowed_threats")
        with self._lock:
            self._sha = {r["value"].lower(): r["id"] for r in rows if r["kind"] == "sha256"}
            self._names = {r["value"].lower(): r["id"] for r in rows if r["kind"] == "threat_name"}

    def match(self, sha256: str | None, threat_name: str | None) -> int | None:
        """Allowed-entry id if this file / threat is allowed, else None. Called for every detection."""
        with self._lock:
            if sha256 and sha256.lower() in self._sha:
                return self._sha[sha256.lower()]
            if threat_name and threat_name.lower() in self._names:
                return self._names[threat_name.lower()]
        return None

    def hit(self, entry_id: int) -> None:
        self.db.execute("UPDATE allowed_threats SET hits=hits+1, last_hit_at=? WHERE id=?", (_now(), entry_id))

    def count(self) -> int:
        return self.db.fetchone("SELECT COUNT(*) AS n FROM allowed_threats")["n"]

    def list(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM allowed_threats ORDER BY id DESC")

    def get(self, entry_id: int) -> dict | None:
        return self.db.fetchone("SELECT * FROM allowed_threats WHERE id=?", (entry_id,))

    def add(self, kind: str, value: str, username: str, threat_name: str | None = None,
            note: str | None = None) -> tuple[dict, bool]:
        """Returns (entry, created). Adding an existing value just returns it."""
        if kind not in KINDS:
            raise ValueError("kind must be sha256 or threat_name")
        value = value.strip()
        if kind == "sha256":
            value = value.lower()
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Not a SHA-256 hash")
        elif not 1 <= len(value) <= 200:
            raise ValueError("Threat name must be 1-200 characters")
        existing = self.db.fetchone("SELECT * FROM allowed_threats WHERE kind=? AND value=?", (kind, value))
        if existing:
            return existing, False
        cur = self.db.execute("INSERT INTO allowed_threats(kind, value, threat_name, note, added_by) VALUES (?,?,?,?,?)",
                              (kind, value, threat_name or (value if kind == "threat_name" else None), note, username))
        self.reload()
        return self.get(cur.lastrowid), True

    def remove(self, entry_id: int) -> dict | None:
        row = self.get(entry_id)
        if row:
            self.db.execute("DELETE FROM allowed_threats WHERE id=?", (entry_id,))
            self.reload()
        return row
