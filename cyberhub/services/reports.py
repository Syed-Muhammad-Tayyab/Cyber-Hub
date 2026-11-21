"""
Cyber Hub Backend - Reports & exports (Part 19)
Developed by Syed Muhammad Tayyab

Builds a report from what Parts 1-18 already know and saves it as PDF, HTML, CSV or JSON.

    type        contents
    summary     overall score, protection areas, what to fix first, threats / firewall / device at a glance, PC info
    threats     detections, quarantine, scans, real-time protection
    device      every Windows security check with its result (Part 11) - a hardening checklist
    network     firewall profiles + findings + blocks, connections, listening ports, Wi-Fi, devices on the network
    accounts    password-vault health (counts only) and platform accounts: 2FA, issues, breached e-mails
    activity    the activity log of the period
    full        everything above in one document

One neutral document model (sections -> text / key-values / tables / bars / charts) is rendered by four small
writers, so every format carries the same facts. PDF comes from the built-in writer (pdf_writer.py, no extra
package). CSV exports the tables: one .csv when the report has a single table, otherwise a .zip of .csv files;
every cell is guarded against spreadsheet formula injection.

Never in a report: passwords, vault contents, API keys, session tokens, full e-mail addresses of monitored
accounts (they stay masked like in the UI). Reports are per user (administrators see everyone's), stored in the
data folder's reports/ directory and pruned to report_keep per user.

The same service writes the diagnostics bundle (log export): rotated log files, activity log as CSV, app + module
versions and non-secret settings in one .zip for troubleshooting.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import platform
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..config import APP_NAME, APP_VERSION
from ..database import Database
from ..logger import get_logger
from . import pdf_writer as pw

log = get_logger("reports")

AUTHOR = "Syed Muhammad Tayyab"
TYPES = {
    "summary": "Security summary", "threats": "Threat report", "device": "Device security report",
    "network": "Network & firewall report", "accounts": "Accounts & passwords report",
    "activity": "Activity log", "full": "Full security report",
}
FORMATS = {"pdf": "application/pdf", "html": "text/html; charset=utf-8", "csv": "text/csv; charset=utf-8",
           "json": "application/json", "zip": "application/zip"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SECRET_KEY = re.compile(r"(key|token|secret|password)", re.I)


class ReportError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _iso(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _when(ts: str | None) -> str:
    """UTC ISO text -> short local date/time for people."""
    if not ts:
        return "-"
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone().strftime("%d %b %Y %H:%M")
    except ValueError:
        return str(ts)[:16]


def _size(n: int | float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "0 B"                                                     # pragma: no cover


def csv_safe(v: Any) -> Any:
    return "'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v       # CSV formula-injection guard


# ---- document model helpers
def text(s: str, muted: bool = False) -> dict:
    return {"type": "text", "text": s, "muted": muted}


def kv(pairs: list[tuple[str, Any]]) -> dict:
    return {"type": "kv", "pairs": [[k, "-" if v in (None, "") else v] for k, v in pairs]}


def table(name: str, columns: list[dict], rows: list[list], empty: str = "Nothing to show",
          total: int | None = None) -> dict:
    return {"type": "table", "name": name, "columns": columns, "rows": rows, "empty": empty,
            "total": total if total is not None else len(rows)}


def bars(items: list[tuple[str, float | None, str]], maximum: float = 100) -> dict:
    return {"type": "bars", "items": [list(i) for i in items], "max": maximum}


def chart(title: str, points: list[tuple[str, float]]) -> dict:
    return {"type": "chart", "title": title, "points": [list(p) for p in points]}


def col(title: str, width: float = 1, **kw) -> dict:
    return {"title": title, "width": width, **kw}


class ReportService:
    def __init__(self, db: Database, settings, activity, data_dir: Path, *, score=None, scanner=None,
                 threat_history=None, quarantine=None, realtime=None, firewall=None, network=None, posture=None,
                 passwords=None, data_protection=None, web=None, intel=None, platforms=None, scheduler=None,
                 notifications=None, log_dir: Path | None = None):
        self.db, self.settings, self.activity = db, settings, activity
        self.dir = Path(data_dir) / "reports"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(log_dir) if log_dir else Path(data_dir) / "logs"
        self.score, self.scanner, self.threat_history, self.quarantine = score, scanner, threat_history, quarantine
        self.realtime, self.firewall, self.network, self.posture = realtime, firewall, network, posture
        self.passwords, self.data_protection, self.web, self.intel = passwords, data_protection, web, intel
        self.platforms, self.scheduler, self.notifications = platforms, scheduler, notifications

    def _g(self, key: str) -> Any:
        return self.settings.get(key)

    # ================================================================== requests
    def check_request(self, type_: str, fmt: str, days: Any) -> None:
        if type_ not in TYPES:
            raise ReportError(422, f"Unknown report type - use one of: {', '.join(TYPES)}")
        if fmt not in ("pdf", "html", "csv", "json"):
            raise ReportError(422, "format must be pdf, html, csv or json")
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 365:
            raise ReportError(422, "days must be between 1 and 365")

    def types(self) -> list[dict]:
        desc = {
            "summary": "Score, protection areas, what to fix first and the key numbers - two or three pages",
            "threats": "Detections, quarantine, scans and real-time protection",
            "device": "Every Windows security check with its result",
            "network": "Firewall, connections, open ports, Wi-Fi and devices on your network",
            "accounts": "Password health (counts only) and how well your online accounts are protected",
            "activity": "Everything Cyber Hub logged in the period",
            "full": "All of the above in one document",
        }
        return [{"id": k, "name": v, "description": desc[k]} for k, v in TYPES.items()]

    # ================================================================== sections
    def _section(self, title: str, fn: Callable[[], list[dict]], level: int = 1) -> dict:
        try:
            blocks = fn()
        except Exception as e:
            msg = getattr(e, "message", None) or f"{type(e).__name__}: {e}"
            if not hasattr(e, "status"):
                log.warning("Report section '%s' failed: %s", title, msg)
            blocks = [text(f"This section could not be read: {str(msg)[:300]}", muted=True)]
        return {"title": title, "level": level, "blocks": blocks}

    def _s_overview(self, cu, days: int, s: dict | None) -> list[dict]:
        if not s:
            return [text("The security score is not available.", True)]
        out: list[dict] = [{"type": "score", "score": s["score"], "grade": s["grade"], "label": s["status_text"],
                            "note": s["headline"]}]
        if s.get("caps"):
            out.append(text("Score limited to " + ", ".join(f"{c['limit']} because {c['reason']}" for c in s["caps"])
                            + ".", True))
        out.append(bars([(c["name"], c["score"], str(c["score"]) if c["score"] is not None else c["status_text"])
                         for c in s["categories"]]))
        hist = self.score.history(cu.user["id"], days) if self.score else {"by_day": []}
        if len(hist["by_day"]) > 1:
            out.append(chart("Score per day", [(d["day"][5:], d["score"]) for d in hist["by_day"][-31:]]))
        return out

    def _s_recommendations(self, s: dict | None, limit: int) -> list[dict]:
        recs = (s or {}).get("recommendations", [])
        names = {c["id"]: c["name"] for c in (s or {}).get("categories", [])}
        rows = [[r["severity"], r["title"] + (f" - {r['detail']}" if r.get("detail") else ""),
                 names.get(r["category"], r["category"].title())] for r in recs[:limit]]
        return [table("recommendations", [col("Severity", 1, severity=True), col("What to do", 5.2), col("Area", 1.8)],
                      rows, "Nothing needs fixing - well done.", (s or {}).get("recommendations_total"))]

    def _s_threats(self, days: int, full: bool) -> list[dict]:
        out: list[dict] = []
        ts = self.threat_history.summary(days)
        sc = self.scanner.summary(min(days, 90))
        rt = self.realtime.status() if self.realtime else {}
        last = sc.get("last_scan") or {}
        out.append(kv([
            ("Active threats", ts["active_threats"]), ("In quarantine", ts["quarantine"]["items"]),
            ("Handled", f"{ts['handled_percent']} %"), ("Real-time protection", "On" if rt.get("enabled") else "Off"),
            ("Last scan", f"{last.get('kind', '?')} - {_when(last.get('finished_at') or last.get('created_at'))}"
             if last else "never"),
            ("Scans in period", sc["totals"]["scans"]), ("Files scanned", f"{sc['totals']['files']:,}"),
            ("Known-bad signatures", f"{sc['signatures']['enabled']:,}")]))
        if ts["by_day"]:
            out.append(chart(f"Detections per day (last {days} days)",
                             [(d["day"][5:], d.get("detected", d.get("n", 0))) for d in ts["by_day"][-31:]]))
        if not full:
            return out
        det = self.threat_history.list(status="all", days=days, limit=500)
        out.append({"type": "subheading", "text": "Detections"})
        out.append(table("detections", [col("When", 1.5), col("Threat", 2.2), col("Severity", 1, severity=True),
                                        col("Status", 1.1), col("How", 0.9), col("File", 4)],
                         [[_when(d["detected_at"]), d["threat_name"], d["severity"], d["status"], d["method"],
                           d["path"] + (f" > {d['archive_member']}" if d.get("archive_member") else "")]
                          for d in det["items"]], "No threats were found in this period.", det["total"]))
        q = self.quarantine.list(status="quarantined", limit=300)
        out.append({"type": "subheading", "text": "Quarantine"})
        out.append(table("quarantine", [col("Since", 1.5), col("Threat", 2.2), col("Severity", 1, severity=True),
                                        col("Size", 0.9, align="right"), col("Original location", 4)],
                         [[_when(i["quarantined_at"]), i["threat_name"], i["severity"], _size(i["size"]),
                           i["original_path"]] for i in q["items"]], "The quarantine is empty.", q["total"]))
        jobs = self.scanner.history(limit=40)
        out.append({"type": "subheading", "text": "Scans"})
        out.append(table("scans", [col("Started", 1.5), col("Type", 0.9), col("Status", 1.1),
                                   col("Files", 1, align="right"), col("Threats", 0.9, align="right"),
                                   col("Time", 0.9, align="right"), col("By", 1.1)],
                         [[_when(j.get("started_at") or j.get("created_at")), j["kind"], j["status"],
                           f"{j['files_scanned']:,}", j["threats_found"], f"{j['duration_seconds']:.0f} s",
                           j.get("started_by") or "-"] for j in jobs], "No scans yet."))
        return out

    def _s_device(self, full: bool) -> list[dict]:
        a = self.posture.analyze()
        out: list[dict] = [{"type": "score", "score": a["score"], "grade": None, "label": a["grade"],
                            "note": f"{a['totals']['passed']} of {a['totals']['checks']} checks passed, "
                                    f"{a['totals']['failed']} to fix"}]
        out.append(bars([(c["name"], c["score"], f"{c['passed']}/{c['total']}") for c in a["categories"]]))
        failed = [c for c in a["checks"] if c["status"] == "fail" and not c.get("ignored")]
        out.append({"type": "subheading", "text": "To fix"})
        out.append(table("device_issues", [col("Severity", 1, severity=True), col("Check", 2.6), col("Now", 1.6),
                                           col("Why it matters", 4.4)],
                         [[c["severity"], c["title"], c.get("value") or "-", c.get("why") or c.get("detail") or ""]
                          for c in failed], "Every check passed."))
        if full:
            rest = [c for c in a["checks"] if c not in failed]
            out.append({"type": "subheading", "text": "Passed, unknown and ignored checks"})
            out.append(table("device_checks", [col("Result", 1), col("Section", 2), col("Check", 3), col("Now", 2.4)],
                             [["ignored" if c.get("ignored") else c["status"], c.get("category_name") or c["category"],
                               c["title"], c.get("value") or "-"] for c in rest]))
        return out

    def _s_network(self, full: bool) -> list[dict]:
        out: list[dict] = []
        if self.firewall is not None:
            st = self.firewall.status()
            out.append({"type": "subheading", "text": "Firewall"})
            out.append(kv([("Firewall", str(st.get("state", "?")).upper()), ("Score", st.get("score")),
                           ("Health", st.get("grade")), ("Rules", (st.get("rules") or {}).get("total")),
                           ("Cyber Hub blocks", (st.get("blocks") or {}).get("active")),
                           ("Block all incoming", "On" if st.get("shields_up") else "Off"),
                           ("Engine", st["backend"]["label"])]))
            out.append(table("firewall_profiles", [col("Profile", 1.2), col("State", 1), col("In use", 1),
                                                   col("Incoming", 1.2), col("Outgoing", 1.2)],
                             [[p["name"].capitalize(), "On" if p["enabled"] else "OFF", "yes" if p.get("active") else "",
                               p["default_inbound"], p["default_outbound"]] for p in st.get("profiles", [])]))
            fa = self.firewall.analyze()
            real = [f for f in fa["findings"] if f["severity"] != "info"]
            out.append(table("firewall_findings", [col("Severity", 1, severity=True), col("Finding", 3.5),
                                                   col("Detail", 4.5)],
                             [[f["severity"], f["title"], f.get("detail") or ""] for f in real],
                             "No firewall problems found."))
            if full:
                bl = self.firewall.blocks(None, None, 200, 0)
                out.append(table("firewall_blocks", [col("Since", 1.5), col("Kind", 0.8), col("Target", 3.6),
                                                     col("Direction", 1), col("Status", 1)],
                                 [[_when(b.get("created_at")), b.get("kind"),
                                   b.get("label") or b.get("target") or b.get("program") or b.get("remote") or "-",
                                   b.get("direction"), b.get("status")] for b in bl.get("items", [])],
                                 "Cyber Hub is not blocking anything in the firewall."))
        if self.network is not None:
            ns = self.network.status()
            c, w, lan = ns.get("connections") or {}, ns.get("wifi") or {}, ns.get("lan") or {}
            out.append({"type": "subheading", "text": "Network"})
            out.append(kv([("Score", ns.get("score")), ("Health", ns.get("grade")),
                           ("Connections", c.get("total")), ("To the internet", c.get("internet")),
                           ("Flagged", c.get("flagged")), ("Programs online", c.get("processes")),
                           ("Wi-Fi", w.get("ssid") if w.get("connected") else "not connected"),
                           ("Wi-Fi security", str(w.get("auth") or "-").upper()),
                           ("Network", lan.get("subnet")), ("Router", (lan.get("gateway") or {}).get("ip"))]))
            na = self.network.analyze()
            real = [f for f in na.get("findings", []) if f["severity"] != "info"]
            out.append(table("network_findings", [col("Severity", 1, severity=True), col("Finding", 3.5),
                                                  col("Detail", 4.5)],
                             [[f["severity"], f["title"], f.get("detail") or ""] for f in real],
                             "No network problems found."))
            if full:
                ls = self.network.listening()
                out.append({"type": "subheading", "text": "Programs accepting connections"})
                out.append(table("listening_ports", [col("Port", 0.8), col("Protocol", 0.8), col("Program", 2.4),
                                                     col("Reachable from", 1.6), col("Firewall", 1.6)],
                                 [[i.get("port"), str(i.get("proto", "")).upper(), i.get("process") or i.get("program")
                                   or "-", i.get("exposure") or i.get("scope") or "-",
                                   (i.get("firewall") or {}).get("verdict") if isinstance(i.get("firewall"), dict)
                                   else i.get("firewall") or "-"] for i in ls.get("items", [])][:200]))
                try:
                    ld = self.network.lan()
                    out.append({"type": "subheading", "text": "Devices on this network"})
                    out.append(table("lan_devices", [col("Address", 1.4), col("Name", 2), col("Maker", 1.8),
                                                     col("Type", 1.6), col("Trusted", 0.8), col("Flags", 2)],
                                     [[d.get("ip"), d.get("label") or d.get("hostname") or d.get("nb_name") or "-",
                                       d.get("vendor") or "-", d.get("device_type") or "-",
                                       "yes" if d.get("trusted") else "no",
                                       ", ".join(f if isinstance(f, str) else str(f.get("title") or f.get("id"))
                                                 for f in d.get("flags", []))] for d in ld.get("devices", [])]))
                except Exception as e:
                    out.append(text(f"Devices could not be listed: {getattr(e, 'message', e)}", True))
        return out or [text("Firewall and network modules are not loaded.", True)]

    def _s_accounts(self, cu, full: bool) -> list[dict]:
        out: list[dict] = []
        uid = cu.user["id"]
        if self.passwords is not None:
            h = self.passwords.health(uid)
            out.append({"type": "subheading", "text": "Password vault"})
            if h:
                c = h.get("counts", {})
                out.append(kv([("Score", h.get("score")), ("Grade", h.get("grade")), ("Saved items", h.get("total")),
                               ("Logins", h.get("logins")), ("In known breaches", c.get("breached", 0)),
                               ("Reused", c.get("reused", 0)), ("Weak", c.get("weak", 0)), ("Old", c.get("old", 0)),
                               ("Audited", _when(h.get("checked_at"))),
                               ("Breach check", _when(h.get("breach_checked_at")))]))
                out.append(text("Only counts are shown here. Passwords and the names of saved items never leave the "
                                "vault.", True))
            else:
                out.append(text("No password-vault audit yet (create or unlock the vault once).", True))
        if self.platforms is not None:
            h = self.platforms.health(uid)
            out.append({"type": "subheading", "text": "Online accounts"})
            out.append(kv([("Score", h.get("score")), ("Grade", h.get("grade")), ("Accounts", h.get("accounts")),
                           ("2FA coverage", f"{h['two_fa_coverage']} %" if h.get("two_fa_coverage") is not None else "-"),
                           ("Key accounts without 2FA", h.get("critical_without_2fa")),
                           ("E-mails monitored", h.get("emails_monitored")),
                           ("E-mails in breaches", h.get("breached_emails")),
                           ("Risky extensions", h.get("risky_extensions"))]))
            lst = self.platforms.list_accounts(cu)
            out.append(table("accounts", [col("Account", 2.2), col("Importance", 1.1), col("Score", 0.8, align="right"),
                                          col("Two-step verification", 1.8), col("Issues", 4)],
                             [[a["name"] + (f" ({a['label']})" if a.get("label") else ""), a["importance"],
                               a["score"] if a["score"] is not None else "-",
                               {"done": "On", "not_done": "OFF", "unknown": "Not confirmed", "none_offered": "Not offered",
                                "not_applicable": "n/a"}.get(str(a.get("two_factor")), str(a.get("two_factor") or "-")),
                               "; ".join(str(i.get("text") or i.get("title") or i.get("code")) for i in a.get("issues", [])) or "none"]
                              for a in lst["items"]], "No accounts added yet.", lst["total"]))
        return out or [text("Password and platform modules are not loaded.", True)]

    def _s_data_intel_web(self, cu) -> list[dict]:
        uid = cu.user["id"]
        out: list[dict] = []
        if self.data_protection is not None:
            h = self.data_protection.health(uid)
            out.append({"type": "subheading", "text": "Data protection"})
            out.append(kv([("Score", h["score"]), ("Unprotected sensitive files", h["open_findings"]),
                           ("Critical / high", f"{h['by_severity']['critical']} / {h['by_severity']['high']}"),
                           ("Files encrypted by Cyber Hub", h["encrypted_files"]),
                           ("Folders searched", "yes" if h["searched"] else "not yet"),
                           ("Cleanable junk", h.get("junk_size"))]))
        if self.intel is not None:
            h = self.intel.health(uid)
            out.append({"type": "subheading", "text": "Threat intelligence"})
            out.append(kv([("Score", h["score"]), ("Known-bad indicators", f"{h['iocs']:,}"),
                           ("Feeds working", f"{h['feeds_ok']} of {h['feeds_enabled']}"),
                           ("Last update", _when(h["last_update"])),
                           ("Open alerts", sum(h["open_alerts"].values())),
                           ("Connection matching", "On" if h["watch_connections"] else "Off")]))
        if self.web is not None:
            h = self.web.health(uid)
            out.append({"type": "subheading", "text": "Websites & code"})
            out.append(kv([("Score", h["score"] if h["score"] is not None else "not scanned"), ("Grade", h.get("grade")),
                           ("Sites", h["sites"]), ("Projects", h["projects"]),
                           ("Critical / high problems", f"{h['open']['critical']} / {h['open']['high']}"),
                           ("Vulnerable packages", h.get("vulnerable_packages")),
                           ("Dev servers exposed", h.get("dev_servers_exposed"))]))
        return out

    def _s_activity(self, days: int, limit: int) -> list[dict]:
        rows = self.db.fetchall("SELECT ts, category, severity, title, detail, source FROM activity_log WHERE ts >= "
                                "strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) ORDER BY id DESC LIMIT ?",
                                (f"-{days} days", limit))
        total = self.db.fetchone("SELECT COUNT(*) AS n FROM activity_log WHERE ts >= "
                                 "strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)", (f"-{days} days",))["n"]
        sm = self.activity.summary(days)
        out: list[dict] = [kv([(k.capitalize(), v) for k, v in sm["by_severity"].items()])]
        if sm["by_day"]:
            out.append(chart("Events per day", [(d["day"][5:], d["n"]) for d in sm["by_day"][-31:]]))
        out.append(table("activity", [col("When", 1.5), col("Area", 1), col("Severity", 0.9, severity=True),
                                      col("Event", 3.2), col("Detail", 4)],
                         [[_when(r["ts"]), r["category"], r["severity"], r["title"], r["detail"] or ""] for r in rows],
                         "Nothing was logged in this period.", total))
        return out

    def _s_system(self) -> list[dict]:
        from . import system_info
        i = system_info.device_info()
        osd = i.get("os") or {}
        disks = i.get("disks") or []
        out = [kv([("Computer", i.get("hostname")), ("Signed-in Windows user", i.get("user")),
                   ("System", " ".join(str(x) for x in (osd.get("system"), osd.get("release"), osd.get("edition")) if x)),
                   ("Architecture", osd.get("architecture")), ("Processor", (i.get("cpu") or {}).get("model")),
                   ("Memory", f"{(i.get('memory') or {}).get('total_gb')} GB"), ("Last start", _when(i.get("boot_time"))),
                   ("Cyber Hub", f"v{APP_VERSION}")])]
        if disks:
            out.append(table("disks", [col("Drive", 1.5), col("File system", 1), col("Size", 1, align="right"),
                                       col("Used", 1, align="right"), col("Free", 1, align="right")],
                             [[d.get("mountpoint") or d.get("device"), d.get("fstype") or "-",
                               f"{d.get('total_gb', '?')} GB", f"{d.get('percent', '?')} %",
                               f"{d.get('free_gb', '?')} GB"] for d in disks[:12]]))
        return out

    def _s_schedule(self) -> list[dict]:
        if self.scheduler is None:
            return [text("Scheduler not loaded.", True)]
        items = self.scheduler.list()["items"]
        return [table("schedules", [col("Job", 2.6), col("When", 2.6), col("On", 0.6), col("Last run", 1.5),
                                    col("Result", 3)],
                      [[s["name"], s["when"], "yes" if s["enabled"] else "no", _when(s["last_run_at"]),
                        f"{s['last_status'] or '-'}" + (f": {s['last_detail']}" if s.get("last_detail") else "")]
                       for s in items])]

    # ================================================================== build
    def build(self, cu, type_: str, days: int) -> dict:
        from . import system_info
        host = system_info.device_info().get("hostname") or platform.node() or "this PC"
        s = None
        if self.score is not None:
            try:
                s = self.score.compute(cu.user["id"], refresh=True)
            except Exception as e:                                   # pragma: no cover
                log.warning("Score for the report failed: %s", e)
        doc = {"app": APP_NAME, "version": APP_VERSION, "author": AUTHOR, "type": type_, "title": TYPES[type_],
               "subtitle": f"{host} - last {days} day{'s' if days != 1 else ''}", "generated_at": _iso(), "days": days,
               "score": s["score"] if s else None,
               "meta": [["Computer", host], ["Prepared for", cu.user.get("display_name") or cu.user["username"]],
                        ["Period", f"last {days} day{'s' if days != 1 else ''}"],
                        ["Generated", datetime.now().strftime("%d %b %Y %H:%M")],
                        ["Cyber Hub", f"v{APP_VERSION} - developed by {AUTHOR}"]],
               "sections": []}
        add = doc["sections"].append
        full = type_ == "full"
        if type_ in ("summary", "full"):
            add(self._section("Overall security", lambda: self._s_overview(cu, days, s)))
            add(self._section("What to fix first", lambda: self._s_recommendations(s, 60 if full else 15)))
        if type_ in ("summary", "threats", "full"):
            add(self._section("Virus & threat protection", lambda: self._s_threats(days, type_ != "summary")))
        if type_ in ("device", "full"):
            add(self._section("Device security", lambda: self._s_device(True)))
        if type_ in ("summary",):
            add(self._section("Device security", lambda: self._s_device(False)[:2]))
        if type_ in ("summary", "network", "full"):
            add(self._section("Firewall & network", lambda: self._s_network(type_ != "summary")))
        if type_ in ("accounts", "full"):
            add(self._section("Passwords & accounts", lambda: self._s_accounts(cu, True)))
        if type_ in ("summary", "full"):
            add(self._section("Data, threat intelligence & websites", lambda: self._s_data_intel_web(cu)))
        if type_ in ("activity", "full"):
            add(self._section("Activity log", lambda: self._s_activity(days, 5000 if type_ == "activity" else 300)))
        if type_ == "full":
            add(self._section("Scheduled jobs", self._s_schedule))
        if type_ in ("summary", "full", "device"):
            add(self._section("This computer", self._s_system))
        return doc

    # ================================================================== renderers
    @staticmethod
    def render_pdf(doc: dict, table_rows: int = 400) -> bytes:
        p = pw.PDF(doc["title"], doc["subtitle"], author=doc["author"])
        p.cover([(k, str(v)) for k, v in doc["meta"]])
        for sec in doc["sections"]:
            p.heading(sec["title"], sec.get("level", 1))
            for b in sec["blocks"]:
                t = b["type"]
                if t == "text":
                    p.paragraph(b["text"], 9 if b.get("muted") else 9.5, pw.MUTED if b.get("muted") else pw.INK)
                elif t == "subheading":
                    p.heading(b["text"], 2)
                elif t == "kv":
                    p.key_values([(k, v) for k, v in b["pairs"]])
                elif t == "score":
                    p.score_banner(b["score"], b.get("grade"), b["label"], b.get("note") or "")
                elif t == "bars":
                    p.bars([(i[0], i[1], str(i[2])) for i in b["items"]], b.get("max", 100))
                elif t == "chart":
                    p.column_chart([(str(a), float(v or 0)) for a, v in b["points"]], title=b.get("title", ""))
                elif t == "table":
                    rows = b["rows"][:table_rows]
                    p.table(b["columns"], rows, empty=b.get("empty", "Nothing to show"))
                    if b.get("total", len(rows)) > len(rows):
                        p.paragraph(f"Showing {len(rows):,} of {b['total']:,} rows - the CSV export has more.", 8.5,
                                    pw.MUTED)
        return p.render()

    @staticmethod
    def render_html(doc: dict) -> bytes:
        e = html.escape
        sev = {"critical": "#c81e1e", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#64748b"}

        def color(score) -> str:
            return "#64748b" if score is None else "#16a34a" if score >= 90 else "#65a30d" if score >= 70 \
                else "#ca8a04" if score >= 50 else "#c81e1e"

        out = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
               f"<title>{e(doc['title'])} - Cyber Hub</title>",
               "<meta name='viewport' content='width=device-width, initial-scale=1'>",
               "<meta name='author' content='Syed Muhammad Tayyab'>",
               "<style>body{font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;color:#1e2638;margin:0;background:#f4f6fa}"
               "header{background:#0f1a33;color:#fff;padding:14px 32px;display:flex;justify-content:space-between;"
               "align-items:center}header b{letter-spacing:.08em}header span{color:#bcd0f5;font-size:12px}"
               "main{max-width:980px;margin:0 auto;padding:24px 32px 48px;background:#fff}"
               "h1{font-size:28px;margin:8px 0 0}h2{font-size:18px;border-left:4px solid #1d4ed8;padding-left:10px;"
               "margin:34px 0 12px}h3{font-size:14px;color:#33415c;margin:22px 0 8px}.sub{color:#6b7689}"
               "table{border-collapse:collapse;width:100%;font-size:12.5px;margin:6px 0 14px}"
               "th{background:#e8edf7;text-align:left;padding:6px 8px;color:#404d6b}"
               "td{padding:6px 8px;border-bottom:1px solid #e3e8f0;vertical-align:top;word-break:break-word}"
               "tr:nth-child(even) td{background:#f7f9fc}.r{text-align:right}"
               ".kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px 24px;margin:6px 0 14px}"
               ".kv div{display:flex;gap:10px}.kv span{color:#6b7689;min-width:150px}.kv b{font-weight:600}"
               ".score{display:flex;gap:28px;align-items:center;background:#f4f6fa;border-left:6px solid;"
               "padding:14px 20px;margin:8px 0 16px}.score .n{font-size:44px;font-weight:700;line-height:1}"
               ".bar{display:grid;grid-template-columns:220px 1fr 90px;gap:10px;align-items:center;margin:5px 0}"
               ".bar i{display:block;height:9px;background:#dfe5ee;border-radius:5px;overflow:hidden}"
               ".bar i u{display:block;height:100%}.chart{display:flex;align-items:flex-end;gap:3px;height:120px;"
               "border-bottom:1px solid #dfe5ee;margin:8px 0 26px}.chart div{flex:1;background:#1d4ed8;position:relative;"
               "min-height:1px}.chart div span{position:absolute;bottom:-18px;left:0;right:0;text-align:center;"
               "font-size:9px;color:#6b7689}.muted{color:#6b7689;font-size:13px}"
               "footer{max-width:980px;margin:0 auto;padding:14px 32px;color:#6b7689;font-size:12px}"
               "@media print{body{background:#fff}main{padding:0 12px}h2{break-after:avoid}tr{break-inside:avoid}}"
               "</style></head><body>",
               f"<header><b>CYBER HUB</b><span>Developed by {e(doc['author'])}</span></header><main>",
               f"<h1>{e(doc['title'])}</h1><div class='sub'>{e(doc['subtitle'])}</div><div class='kv' "
               "style='margin-top:14px'>"]
        out += [f"<div><span>{e(str(k))}</span><b>{e(str(v))}</b></div>" for k, v in doc["meta"]]
        out.append("</div>")
        for sec in doc["sections"]:
            out.append(f"<h2>{e(sec['title'])}</h2>")
            for b in sec["blocks"]:
                t = b["type"]
                if t == "text":
                    out.append(f"<p class='{'muted' if b.get('muted') else ''}'>{e(b['text'])}</p>")
                elif t == "subheading":
                    out.append(f"<h3>{e(b['text'])}</h3>")
                elif t == "kv":
                    out.append("<div class='kv'>" + "".join(f"<div><span>{e(str(k))}</span><b>{e(str(v))}</b></div>"
                                                              for k, v in b["pairs"]) + "</div>")
                elif t == "score":
                    c = color(b["score"])
                    out.append(f"<div class='score' style='border-color:{c}'><div class='n' style='color:{c}'>"
                               f"{'-' if b['score'] is None else b['score']}<small style='font-size:14px;color:#6b7689'>"
                               f" / 100</small></div><div><b style='font-size:17px'>{e(str(b['label']))}</b> "
                               f"<b style='color:{c}'>{'Grade ' + e(str(b['grade'])) if b.get('grade') else ''}</b>"
                               f"<div class='muted'>{e(b.get('note') or '')}</div></div></div>")
                elif t == "bars":
                    mx = b.get("max", 100) or 100
                    for label, value, shown in b["items"]:
                        wpc = 0 if value is None else max(1, min(100, round(value * 100 / mx)))
                        out.append(f"<div class='bar'><span>{e(str(label))}</span><i><u style='width:{wpc}%;"
                                   f"background:{color(value) if mx == 100 else '#1d4ed8'}'></u></i><b>{e(str(shown))}"
                                   "</b></div>")
                elif t == "chart":
                    pts = b["points"]
                    top = max((float(v or 0) for _, v in pts), default=0) or 1
                    step = max(1, len(pts) // 12)
                    out.append(f"<h3>{e(b.get('title', ''))}</h3><div class='chart'>" + "".join(
                        f"<div style='height:{max(1, round(float(v or 0) * 100 / top))}%' title='{e(str(k))}: {e(str(v))}'>"
                        f"<span>{e(str(k)) if i % step == 0 else ''}</span></div>" for i, (k, v) in enumerate(pts))
                        + "</div>")
                elif t == "table":
                    if not b["rows"]:
                        out.append(f"<p class='muted'>{e(b.get('empty', 'Nothing to show'))}</p>")
                        continue
                    out.append("<table><thead><tr>" + "".join(
                        f"<th class='{'r' if c.get('align') == 'right' else ''}'>{e(c['title'])}</th>"
                        for c in b["columns"]) + "</tr></thead><tbody>")
                    for row in b["rows"][:2000]:
                        tds = []
                        for c, v in zip(b["columns"], row):
                            style = f" style='color:{sev.get(str(v).lower(), '#1e2638')};font-weight:600'" \
                                if c.get("severity") else ""
                            tds.append(f"<td class='{'r' if c.get('align') == 'right' else ''}'{style}>"
                                       f"{e('' if v is None else str(v))}</td>")
                        out.append("<tr>" + "".join(tds) + "</tr>")
                    out.append("</tbody></table>")
                    if b.get("total", 0) > min(len(b["rows"]), 2000):
                        out.append(f"<p class='muted'>Showing {min(len(b['rows']), 2000):,} of {b['total']:,} rows.</p>")
        out.append(f"</main><footer>Cyber Hub v{e(doc['version'])} - Developed by {e(doc['author'])} - generated "
                   f"{e(_when(doc['generated_at']))}</footer></body></html>")
        return "".join(out).encode("utf-8")

    @staticmethod
    def _tables(doc: dict) -> list[dict]:
        return [b for s in doc["sections"] for b in s["blocks"] if b["type"] == "table"]

    @classmethod
    def render_csv(cls, doc: dict) -> tuple[bytes, str]:
        """Returns (bytes, extension): one .csv for a single table, otherwise a .zip of .csv files."""
        def one(t: dict) -> bytes:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow([c["title"] for c in t["columns"]])
            for row in t["rows"]:
                w.writerow([csv_safe("" if v is None else v) for v in row])
            return ("﻿" + buf.getvalue()).encode("utf-8")       # BOM: Excel opens it as UTF-8

        tables = cls._tables(doc)
        facts = io.StringIO()
        fw = csv.writer(facts)
        fw.writerow(["Section", "Item", "Value"])
        for k, v in doc["meta"]:
            fw.writerow(["Report", csv_safe(str(k)), csv_safe(str(v))])
        for s in doc["sections"]:
            for b in s["blocks"]:
                if b["type"] == "kv":
                    for k, v in b["pairs"]:
                        fw.writerow([csv_safe(s["title"]), csv_safe(str(k)), csv_safe(v if isinstance(v, (int, float))
                                                                                       else str(v))])
                elif b["type"] == "score":
                    fw.writerow([csv_safe(s["title"]), csv_safe(str(b["label"])) + " score", b["score"]])
                elif b["type"] == "bars":
                    for label, value, shown in b["items"]:
                        fw.writerow([csv_safe(s["title"]), csv_safe(str(label)), value if value is not None
                                     else csv_safe(str(shown))])
        if len(tables) == 1 and doc["type"] == "activity":
            return one(tables[0]), "csv"
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("summary.csv", ("﻿" + facts.getvalue()).encode("utf-8"))
            used: set[str] = set()
            for t in tables:
                name = t["name"]
                while name in used:
                    name += "_2"
                used.add(name)
                zf.writestr(f"{name}.csv", one(t))
        return z.getvalue(), "zip"

    @staticmethod
    def render_json(doc: dict) -> bytes:
        return json.dumps(doc, indent=1, default=str, ensure_ascii=False).encode("utf-8")

    # ================================================================== generate / store
    def generate(self, cu, type_: str = "summary", fmt: str | None = None, days: int | None = None,
                 source: str = "manual") -> dict:
        fmt = fmt or self._g("report_default_format")
        days = int(self._g("report_default_days")) if days is None else days
        self.check_request(type_, fmt, days)
        doc = self.build(cu, type_, days)
        if fmt == "pdf":
            data, ext = self.render_pdf(doc), "pdf"
        elif fmt == "html":
            data, ext = self.render_html(doc), "html"
        elif fmt == "csv":
            data, ext = self.render_csv(doc)
        else:
            data, ext = self.render_json(doc), "json"
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        fname = f"CyberHub_{type_}_{stamp}.{ext}"
        n = 1
        while (self.dir / fname).exists():
            n += 1
            fname = f"CyberHub_{type_}_{stamp}_{n}.{ext}"
        tmp = self.dir / (fname + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, self.dir / fname)
        cur = self.db.execute(
            "INSERT INTO reports(user_id, type, format, title, file_name, size, sha256, days, score, source, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (cu.user["id"], type_, fmt, doc["title"], fname, len(data), hashlib.sha256(data).hexdigest(), days,
             doc["score"], source, cu.user["username"] if source == "manual" else "scheduler"))
        self.activity.record("report", f"Report created: {doc['title']}", f"{fname} ({_size(len(data))})",
                             source="reports")
        if source == "schedule" and self.notifications is not None:
            self.notifications.notify("reports", "low", f"Your {doc['title'].lower()} is ready", fname,
                                      kind="report_ready", user_id=cu.user["id"], link="reports", toast=False)
        self._prune(cu.user["id"])
        return self._public(self.db.fetchone("SELECT * FROM reports WHERE id=?", (cur.lastrowid,)))

    def preview(self, cu, type_: str = "summary", days: int | None = None) -> dict:
        days = int(self._g("report_default_days")) if days is None else days
        self.check_request(type_, "json", days)
        return self.build(cu, type_, days)

    def _public(self, r: dict) -> dict:
        out = dict(r)
        out["size_text"] = _size(r["size"])
        out["type_name"] = TYPES.get(r["type"], r["type"])
        out["exists"] = (self.dir / r["file_name"]).is_file()
        out["extension"] = r["file_name"].rsplit(".", 1)[-1]
        return out

    def _row(self, cu, rid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM reports WHERE id=?", (rid,))
        if not r or (cu.user["role"] != "admin" and r["user_id"] != cu.user["id"]):
            raise ReportError(404, "Report not found")
        return r

    def list(self, cu, limit: int = 50, offset: int = 0, type_: str | None = None) -> dict:
        where, params = [], []
        if cu.user["role"] != "admin":
            where.append("user_id IS ?"); params.append(cu.user["id"])
        if type_:
            where.append("type=?"); params.append(type_)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM reports {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM reports {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        used = self.db.fetchone(f"SELECT COALESCE(SUM(size),0) AS s FROM reports {clause}", tuple(params))["s"]
        return {"items": [self._public(r) for r in rows], "total": total, "bytes": used, "size_text": _size(used),
                "folder": str(self.dir)}

    def get(self, cu, rid: int) -> dict:
        return self._public(self._row(cu, rid))

    def file(self, cu, rid: int) -> tuple[Path, str, str]:
        r = self._row(cu, rid)
        p = self.dir / r["file_name"]
        if not p.is_file() or p.parent.resolve() != self.dir.resolve():
            raise ReportError(410, "The report file no longer exists")
        ext = r["file_name"].rsplit(".", 1)[-1]
        return p, r["file_name"], FORMATS.get(ext, "application/octet-stream")

    def delete(self, cu, rid: int) -> dict:
        r = self._row(cu, rid)
        try:
            (self.dir / r["file_name"]).unlink(missing_ok=True)
        except OSError as e:
            raise ReportError(409, f"The file is in use: {e}")
        self.db.execute("DELETE FROM reports WHERE id=?", (rid,))
        return {"deleted": True, "id": rid}

    def _prune(self, uid: int) -> int:
        keep = int(self._g("report_keep"))
        old = self.db.fetchall("SELECT id, file_name FROM reports WHERE user_id IS ? ORDER BY id DESC LIMIT -1 OFFSET ?",
                               (uid, keep))
        for r in old:
            try:
                (self.dir / r["file_name"]).unlink(missing_ok=True)
            except OSError:
                continue
            self.db.execute("DELETE FROM reports WHERE id=?", (r["id"],))
        return len(old)

    def status(self, cu) -> dict:
        lst = self.list(cu, limit=1)
        return {"types": self.types(), "formats": ["pdf", "html", "csv", "json"], "reports": lst["total"],
                "size_text": lst["size_text"], "folder": lst["folder"], "latest": lst["items"][0] if lst["items"] else None,
                "settings": {k: self._g(k) for k in ("report_default_format", "report_default_days", "report_keep")}}

    # ================================================================== diagnostics bundle (log export)
    def export_logs(self, cu, days: int = 7) -> tuple[bytes, str]:
        from . import system_info
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            if self.log_dir.is_dir():
                for f in sorted(self.log_dir.glob("cyberhub.log*"))[:8]:
                    try:
                        zf.writestr(f"logs/{f.name}", f.read_bytes()[-5_000_000:])
                    except OSError:
                        continue
            rows = self.db.fetchall("SELECT ts, category, severity, title, detail, source FROM activity_log WHERE "
                                    "ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) ORDER BY id DESC LIMIT 20000",
                                    (f"-{days} days",))
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["ts", "category", "severity", "title", "detail", "source"])
            for r in rows:
                w.writerow([csv_safe(r[k]) for k in ("ts", "category", "severity", "title", "detail", "source")])
            zf.writestr("activity.csv", ("﻿" + buf.getvalue()).encode("utf-8"))
            settings = {k: ("<hidden>" if _SECRET_KEY.search(k) else v) for k, v in self.settings.all().items()}
            info = system_info.device_info()
            tables = {r["name"]: self.db.fetchone(f"SELECT COUNT(*) AS n FROM \"{r['name']}\"")["n"]
                      for r in self.db.fetchall("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                                                "'sqlite_%' ORDER BY name")}
            zf.writestr("diagnostics.json", json.dumps({
                "app": APP_NAME, "version": APP_VERSION, "schema_version": self.db.schema_version(),
                "generated_at": _iso(), "generated_by": cu.user["username"], "python": platform.python_version(),
                "os": info.get("os"), "cpu": info.get("cpu"), "memory": info.get("memory"),
                "settings": settings, "table_rows": tables,
                "migrations": self.db.fetchall("SELECT version, description, applied_at FROM schema_version"),
            }, indent=1, default=str))
            zf.writestr("README.txt", "Cyber Hub diagnostics bundle - developed by Syed Muhammad Tayyab\n\n"
                        "Contains: the engine's log files, the activity log of the chosen period, version and "
                        "settings.\nNot included: passwords, vault contents, keys, tokens, quarantined files.\n")
        self.activity.record("report", "Diagnostics bundle exported", f"by {cu.user['username']}", source="reports")
        return z.getvalue(), f"CyberHub_diagnostics_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.zip"
