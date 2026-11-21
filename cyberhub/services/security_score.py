"""
Cyber Hub Backend - Overall security score + dashboard feed (Part 18)
Developed by Syed Muhammad Tayyab

One number for "how safe is this PC and my accounts", built only from what Parts 5-16 already measure:

    category                weight   comes from
    Virus & threats           22     Part 5 scans + Part 6 threat history + Part 7 real-time + Part 8 engines
    Device security           16     Part 11 posture.analyze()
    Firewall                  12     Part 9 firewall.analyze()
    Network                   10     Part 10 network.analyze()
    Passwords                 10     Part 12 passwords.health(user)        (only once a vault was audited)
    Accounts & platforms      10     Part 16 platforms.health(user)        (only once accounts were added)
    Data protection            8     Part 13 data_protection.health(user)
    Threat intelligence        7     Part 15 intel.health(user)
    Websites & code            5     Part 14 web.health(user)              (only once something was scanned)

* overall = weighted average of the categories that have a score (a module you don't use neither helps nor hurts)
* a category "at risk" (below 50 - that is what one critical problem does in every module) caps the overall
  score at 59; a category below 70 caps it at 89. One open critical problem can't hide behind eight good areas.
* every category that can't be read (module error, not supported on this PC) is listed as unavailable with the
  reason instead of silently counting as 100 or 0.

The same pass collects the recommendations ("what should I fix first") with the page that fixes each one and,
where the module has a one-click fix, the exact API call. /api/dashboard returns score + categories +
recommendations + the numbers behind every front-page graph in one request.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from ..database import Database
from ..logger import get_logger

log = get_logger("score")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
GRADES = [(95, "A+"), (90, "A"), (80, "B"), (70, "C"), (55, "D"), (40, "E"), (0, "F")]
CATEGORIES: list[tuple[str, str, int, str]] = [            # id, name, weight, UI page
    ("protection", "Virus & threat protection", 22, "protection"),
    ("device", "Device security", 16, "device"),
    ("firewall", "Firewall", 12, "firewall"),
    ("network", "Network", 10, "network"),
    ("passwords", "Passwords", 10, "passwords"),
    ("accounts", "Accounts & platforms", 10, "platforms"),
    ("data", "Data protection", 8, "data"),
    ("intel", "Threat intelligence", 7, "intel"),
    ("web", "Websites & code", 5, "web"),
]
CACHE_TTL = 8.0


def grade_of(score: int) -> str:
    return next(g for lim, g in GRADES if score >= lim)


def status_of(score: int | None) -> str:
    if score is None:
        return "not_set_up"
    return "protected" if score >= 90 else "good" if score >= 70 else "attention" if score >= 50 else "at_risk"


STATUS_TEXT = {"protected": "Protected", "good": "Good", "attention": "Needs attention", "at_risk": "At risk",
               "not_set_up": "Not set up", "unavailable": "Unavailable"}


def _iso(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _rec(rid: str, category: str, severity: str, title: str, detail: str | None, link: str,
         action: dict | None = None) -> dict:
    return {"id": rid, "category": category, "severity": severity, "title": title, "detail": detail, "link": link,
            "action": action}


def _act(label: str, method: str, path: str, body: dict | None = None, admin: bool = False) -> dict:
    return {"label": label, "method": method, "path": path, "body": body, "admin": admin}


class ScoreService:
    def __init__(self, db: Database, settings, activity, *, scanner=None, threat_history=None, realtime=None,
                 quarantine=None, rules=None, firewall=None, network=None, posture=None, passwords=None,
                 data_protection=None, web=None, intel=None, platforms=None, accounts=None, notifications=None,
                 scheduler=None, vault=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.scanner, self.threat_history, self.realtime, self.quarantine = scanner, threat_history, realtime, quarantine
        self.rules, self.firewall, self.network, self.posture = rules, firewall, network, posture
        self.passwords, self.data_protection, self.web, self.intel = passwords, data_protection, web, intel
        self.platforms, self.accounts, self.notifications = platforms, accounts, notifications
        self.scheduler, self.vault = scheduler, vault
        self._lock = threading.Lock()
        self._cache: dict[int, tuple[float, dict]] = {}

    def _g(self, key: str) -> Any:
        return self.settings.get(key)

    # ================================================================== category builders
    # each returns (score | None, facts, recommendations, note)
    def _protection(self, uid: int) -> tuple[int | None, dict, list[dict], str | None]:
        recs: list[dict] = []
        penalty, cap = 0, 100
        s = self.scanner.summary(14)
        act = s["active_by_severity"]
        n_active = s["active_threats"]
        if n_active:
            worst = next(x for x in ("critical", "high", "medium", "low") if act.get(x))
            penalty += 60 * act.get("critical", 0) + 35 * act.get("high", 0) + 15 * act.get("medium", 0) \
                + 5 * act.get("low", 0)
            # an unhandled detection is always worth a look: serious ones put the area "at risk"
            cap = min(cap, {"critical": 49, "high": 49, "medium": 69, "low": 84}[worst])
            recs.append(_rec("protection:active_threats", "protection",
                             {"critical": "critical", "high": "critical", "medium": "high", "low": "medium"}[worst],
                             f"{n_active} threat(s) found and not dealt with yet",
                             "Quarantine or remove them so they can't run.", "protection",
                             _act("Quarantine all", "POST", "/api/threats/actions", {"action": "quarantine"})))
        rt = self.realtime.status() if self.realtime is not None else None
        rt_on = bool(rt and rt["enabled"])
        if rt is not None:
            if not rt_on:
                penalty += 45
                cap = min(cap, 84)
                recs.append(_rec("protection:realtime_off", "protection", "high", "Real-time protection is off",
                                 "New files are not checked when they arrive.", "protection",
                                 _act("Turn on", "POST", "/api/realtime/enable", admin=False)))
            elif rt.get("snoozed_until"):
                penalty += 10
                recs.append(_rec("protection:realtime_paused", "protection", "medium",
                                 "Real-time protection is paused", f"It resumes at {rt['snoozed_until']}.",
                                 "protection", _act("Resume now", "POST", "/api/realtime/resume")))
            elif rt.get("error"):
                penalty += 25
                recs.append(_rec("protection:realtime_error", "protection", "high",
                                 "Real-time protection could not start", str(rt["error"])[:300], "protection"))
        days = s.get("days_since_last_scan")
        if s["status"] == "never_scanned" or days is None:
            penalty += 15
            recs.append(_rec("protection:never_scanned", "protection", "medium", "No scan has been run yet",
                             "A quick scan checks running programs and startup items in a few minutes.", "protection",
                             _act("Run a quick scan", "POST", "/api/scan/quick")))
        elif days > 14:
            penalty += 10
            recs.append(_rec("protection:scan_old", "protection", "low", f"Last scan was {int(days)} days ago",
                             "Run a quick scan, or let the scheduler do it every day.", "protection",
                             _act("Run a quick scan", "POST", "/api/scan/quick")))
        if not self._g("yara_enabled"):
            penalty += 8
            recs.append(_rec("protection:yara_off", "protection", "low", "Rule-based detection (YARA) is switched off",
                             "Only exact known-bad files are caught.", "settings"))
        if not self._g("heuristics_enabled"):
            penalty += 8
            recs.append(_rec("protection:heuristics_off", "protection", "low", "Heuristic detection is switched off",
                             "Suspicious-looking new files are not flagged.", "settings"))
        if self.vault is not None and not self.vault.available:
            penalty += 20
            recs.append(_rec("protection:vault_key", "protection", "high", "The quarantine vault key can't be opened",
                             "Threats can't be quarantined until this is fixed.", "protection"))
        score = min(cap, round(100 * 100 / (100 + penalty)))
        facts = {"active_threats": n_active, "active_by_severity": act, "realtime": "on" if rt_on else "off",
                 "realtime_state": rt.get("state") if rt else None, "last_scan": s.get("last_scan"),
                 "days_since_last_scan": days, "signatures": s["signatures"]["enabled"],
                 "auto_quarantine": self._g("scan_auto_quarantine"), "running_scans": len(s.get("running", []))}
        return score, facts, recs, None

    def _firewall(self, uid: int):
        a = self.firewall.analyze()
        recs = [_rec(f"firewall:{f['id']}", "firewall", f["severity"], f["title"], f.get("detail"), "firewall",
                     _act(f.get("fix_label") or "Fix", "POST", f"/api/firewall/findings/{_q(f['id'])}/fix",
                          admin=bool(f.get("fix_requires_admin"))) if f.get("fix") else None)
                for f in a["findings"] if f["severity"] != "info"]
        return a["score"], {"label": a["grade"], "findings": a["counts"], "rules_checked": a.get("rules_checked"),
                            "backend": self.firewall.backend.label}, recs, None

    def _network(self, uid: int):
        a = self.network.analyze()
        recs = [_rec(f"network:{f['id']}", "network", f["severity"], f["title"], f.get("detail"), "network",
                     _act(f.get("fix_label") or "Fix", "POST", f"/api/network/findings/{_q(f['id'])}/fix")
                     if f.get("fix") else None)
                for f in a.get("findings", []) if f["severity"] != "info"]
        return a["score"], {"label": a.get("grade"), "findings": a.get("counts"),
                            "wifi": (a.get("wifi") or {}).get("ssid") if isinstance(a.get("wifi"), dict) else None}, \
            recs, None

    def _device(self, uid: int):
        a = self.posture.analyze()
        recs = []
        for c in a["checks"]:
            if c["status"] != "fail" or c.get("ignored"):
                continue
            fix = c.get("fix")
            action = None
            if fix and not fix.get("blocked"):
                action = _act(fix.get("label") or "Fix", "POST", f"/api/posture/checks/{_q(c['id'])}/fix",
                              {"confirm": False}, admin=bool(fix.get("admin_only")))
            title = f"{c['title']}: {c['value']}" if c.get("value") else c["title"]
            recs.append(_rec(f"device:{c['id']}", "device", c["severity"], title,
                             c.get("why") or c.get("detail"), "device", action))
        return a["score"], {"grade": a["grade"], "totals": a["totals"], "counts": a["counts"],
                            "sections": [{k: c[k] for k in ("id", "name", "score", "failed")} for c in a["categories"]],
                            "platform": a.get("platform")}, recs, None

    def _passwords(self, uid: int):
        h = self.passwords.health(uid)
        if not h:
            exists = bool(self.db.fetchone("SELECT 1 AS x FROM pv_vaults WHERE user_id=?", (uid,)))
            note = ("Unlock your password vault once so its health can be checked" if exists
                    else "Create a password vault to store and check your passwords")
            return None, {"vault": exists}, [_rec("passwords:setup", "passwords", "low", note, None, "passwords")], note
        c = h.get("counts", {})
        recs = []
        for key, sev, text, tip in (
                ("breached", "critical", "password(s) appeared in known data breaches", "Change them now."),
                ("reused", "high", "password(s) are used for more than one account",
                 "One leak would open several accounts."),
                ("weak", "medium", "weak password(s)", "Replace them with generated ones."),
                ("old", "low", "password(s) have not been changed for a long time", None)):
            if c.get(key):
                recs.append(_rec(f"passwords:{key}", "passwords", sev, f"{c[key]} {text}", tip, "passwords"))
        if not h.get("breach_checked_at") and h.get("logins"):
            recs.append(_rec("passwords:breach_unchecked", "passwords", "low",
                             "Your saved passwords were never checked against known breaches",
                             "The check sends only 5 characters of a hash, never the password.", "passwords"))
        return h["score"], {"grade": h.get("grade"), "items": h.get("total"), "counts": c,
                            "checked_at": h.get("checked_at")}, recs, None

    def _accounts(self, uid: int):
        h = self.platforms.health(uid)
        recs = []
        if h["score"] is None:
            note = "Add the accounts you use (Google, Facebook, GitHub ...) to check how well they are protected"
            return None, {"accounts": 0}, [_rec("accounts:setup", "accounts", "low", note, None, "platforms")], note
        if h.get("critical_without_2fa"):
            recs.append(_rec("accounts:critical_no_2fa", "accounts", "critical",
                             f"{h['critical_without_2fa']} key account(s) have no two-step verification",
                             "These accounts can reset the passwords of your other accounts.", "platforms"))
        if h.get("breached_emails"):
            recs.append(_rec("accounts:breached_emails", "accounts", "high",
                             f"{h['breached_emails']} of your e-mail address(es) appear in data breaches",
                             "Change the password of the affected sites and switch on 2FA.", "platforms"))
        issues = h.get("issues") or {}
        open_issues = sum(v for v in issues.values() if isinstance(v, int)) if isinstance(issues, dict) else 0
        if open_issues and not recs:
            recs.append(_rec("accounts:issues", "accounts", "medium", f"{open_issues} account protection issue(s)",
                             "Open Accounts & platforms to see what each account is missing.", "platforms"))
        if h.get("risky_extensions"):
            recs.append(_rec("accounts:extensions", "accounts", "high",
                             f"{h['risky_extensions']} risky browser / editor extension(s)",
                             "Remove extensions you don't recognise.", "platforms"))
        if h.get("review_due"):
            recs.append(_rec("accounts:review_due", "accounts", "low", f"{h['review_due']} account review(s) are due",
                             "Check signed-in devices and connected apps.", "platforms"))
        return h["score"], {"grade": h.get("grade"), "accounts": h.get("accounts"),
                            "two_fa_coverage": h.get("two_fa_coverage"), "breached_emails": h.get("breached_emails"),
                            "emails_monitored": h.get("emails_monitored")}, recs, None

    def _data(self, uid: int):
        h = self.data_protection.health(uid)
        recs = []
        by = h["by_severity"]
        if h["open_findings"]:
            worst = next(s for s in ("critical", "high", "medium", "low") if by.get(s))
            recs.append(_rec("data:findings", "data", worst,
                             f"{h['open_findings']} file(s) with sensitive data are lying around unprotected",
                             "Encrypt them or shred the ones you no longer need.", "data"))
        if not h["searched"]:
            recs.append(_rec("data:never_searched", "data", "low", "Your folders were never searched for sensitive files",
                             "Find private keys, password lists, card numbers and CNICs left in Documents / Downloads.",
                             "data", _act("Search now", "POST", "/api/data/finder/scan", {})))
        if h.get("junk_bytes", 0) > 2 * 1024 ** 3:
            recs.append(_rec("data:junk", "data", "low", f"{h['junk_size']} of temporary files can be cleaned",
                             None, "data"))
        return h["score"], {"grade": h["grade"], "open_findings": h["open_findings"], "by_severity": by,
                            "encrypted_files": h["encrypted_files"], "searched": h["searched"],
                            "junk_size": h.get("junk_size")}, recs, None if h["searched"] else "Not searched yet"

    def _intel(self, uid: int):
        h = self.intel.health(uid)
        recs = []
        oa = h["open_alerts"]
        n = sum(oa.values())
        if n:
            worst = next(s for s in ("critical", "high", "medium", "low", "info") if oa.get(s))
            recs.append(_rec("intel:alerts", "intel", worst if worst != "info" else "low",
                             f"{n} threat-intelligence alert(s) need a look",
                             "This PC talked to, or holds files from, addresses on threat lists.", "intel"))
        if not h["iocs"]:
            recs.append(_rec("intel:no_feeds", "intel", "medium", "Threat feeds were never downloaded",
                             "Without them Cyber Hub can't recognise known-bad addresses.", "intel",
                             _act("Update now", "POST", "/api/intel/feeds/refresh", {})))
        elif h["feeds_stale"]:
            recs.append(_rec("intel:stale", "intel", "low", f"{len(h['feeds_stale'])} threat feed(s) are out of date",
                             ", ".join(h["feeds_stale"][:6]), "intel",
                             _act("Update now", "POST", "/api/intel/feeds/refresh", {})))
        if not h["watch_connections"]:
            recs.append(_rec("intel:watch_off", "intel", "medium", "Connection matching is switched off",
                             "Connections to known-bad addresses are not noticed.", "settings"))
        return h["score"], {"iocs": h["iocs"], "feeds_ok": h["feeds_ok"], "feeds_enabled": h["feeds_enabled"],
                            "last_update": h["last_update"], "open_alerts": oa}, recs, None

    def _web(self, uid: int):
        h = self.web.health(uid)
        recs = []
        if h["score"] is None:
            if h.get("dev_servers_exposed"):
                recs.append(_rec("web:dev_servers", "web", "high",
                                 f"{h['dev_servers_exposed']} development server(s) can be reached from the network",
                                 None, "web"))
            return None, {"sites": h["sites"], "projects": h["projects"]}, recs, \
                "Scan a website or a project folder to include it"
        o = h["open"]
        for sev in ("critical", "high"):
            if o.get(sev):
                recs.append(_rec(f"web:{sev}", "web", sev, f"{o[sev]} {sev} problem(s) in your websites / projects",
                                 f"Worst: {h['worst']['target']} (grade {h['worst']['grade']})" if h.get("worst") else None,
                                 "web"))
        for c in h.get("certs_expiring", [])[:3]:
            recs.append(_rec(f"web:cert:{c['target']}", "web", "high" if c["days_left"] <= 7 else "medium",
                             f"Certificate of {c['target']} expires in {c['days_left']} day(s)"
                             if c["days_left"] >= 0 else f"Certificate of {c['target']} has expired", None, "web"))
        if h.get("vulnerable_packages"):
            recs.append(_rec("web:packages", "web", "medium",
                             f"{h['vulnerable_packages']} package(s) with known vulnerabilities in your projects",
                             "Update them to the fixed versions listed in the scan.", "web"))
        if h.get("dev_servers_exposed"):
            recs.append(_rec("web:dev_servers", "web", "high",
                             f"{h['dev_servers_exposed']} development server(s) can be reached from the network",
                             None, "web"))
        return h["score"], {"grade": h["grade"], "sites": h["sites"], "projects": h["projects"], "open": o,
                            "worst": h.get("worst")}, recs, None

    def _app_recs(self, uid: int) -> list[dict]:
        """Cyber Hub's own account: not scored, but worth a nudge."""
        recs = []
        u = self.db.fetchone("SELECT * FROM users WHERE id=?", (uid,))
        if not u:
            return recs
        left = self.db.fetchone("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=? AND used_at IS NULL",
                                (uid,))["n"] if self._has_table("recovery_codes") else None
        if left == 0:
            recs.append(_rec("account:recovery_codes", "account", "low", "You have no Cyber Hub recovery codes",
                             "Without them a forgotten Cyber Hub password can't be reset.", "account"))
        if int(self._g("auto_lock_minutes")) == 0:
            recs.append(_rec("account:auto_lock", "account", "low", "Cyber Hub never locks itself",
                             "Anyone at this PC can open your vault and change protection.", "settings"))
        return recs

    def _has_table(self, name: str) -> bool:
        return bool(self.db.fetchone("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name=?", (name,)))

    # ================================================================== the score
    def compute(self, user_id: int, refresh: bool = False, record: bool = True) -> dict:
        with self._lock:
            hit = self._cache.get(user_id)
            if hit and not refresh and time.monotonic() - hit[0] < CACHE_TTL:
                return hit[1]
        builders: dict[str, tuple[Any, Callable]] = {
            "protection": (self.scanner, self._protection), "device": (self.posture, self._device),
            "firewall": (self.firewall, self._firewall), "network": (self.network, self._network),
            "passwords": (self.passwords, self._passwords), "accounts": (self.platforms, self._accounts),
            "data": (self.data_protection, self._data), "intel": (self.intel, self._intel),
            "web": (self.web, self._web)}
        cats, recs = [], []
        for cid, name, weight, link in CATEGORIES:
            svc, fn = builders[cid]
            entry = {"id": cid, "name": name, "weight": weight, "link": link, "score": None, "grade": None,
                     "status": "unavailable", "facts": {}, "note": None, "issues": 0, "worst": None}
            if svc is None:
                entry["note"] = "Module not loaded"
            else:
                try:
                    score, facts, crecs, note = fn(user_id)
                    entry.update(score=score, facts=facts, note=note, status=status_of(score),
                                 grade=grade_of(score) if score is not None else None)
                    real = [r for r in crecs if not r["id"].endswith(":setup")]
                    entry["issues"] = len(real)
                    entry["worst"] = max((r["severity"] for r in real), key=SEVERITIES.index, default=None)
                    recs += crecs
                except Exception as e:
                    msg = getattr(e, "message", None) or f"{type(e).__name__}: {e}"
                    entry["note"] = str(msg)[:300]
                    if not hasattr(e, "status"):
                        log.warning("Score category %s failed: %s", cid, msg)
            entry["status_text"] = STATUS_TEXT[entry["status"]]
            cats.append(entry)
        try:
            recs += self._app_recs(user_id)
        except Exception as e:                                       # pragma: no cover
            log.debug("Account recommendations failed: %s", e)

        scored = [c for c in cats if c["score"] is not None]
        if scored:
            raw = round(sum(c["score"] * c["weight"] for c in scored) / sum(c["weight"] for c in scored))
        else:
            raw = 0
        caps = []
        at_risk = [c["name"] for c in scored if c["score"] < 50]
        weak = [c["name"] for c in scored if 50 <= c["score"] < 70]
        score = raw
        if at_risk and score > 59:
            score = 59
            caps.append({"limit": 59, "reason": f"{', '.join(at_risk)} {'is' if len(at_risk) == 1 else 'are'} at risk"})
        elif weak and score > 89:
            score = 89
            caps.append({"limit": 89, "reason": f"{', '.join(weak)} need{'s' if len(weak) == 1 else ''} attention"})
        order = {c[0]: i for i, c in enumerate(CATEGORIES)}
        recs.sort(key=lambda r: (-SEVERITIES.index(r["severity"]), order.get(r["category"], 99), r["title"]))
        counts = {s: sum(1 for r in recs if r["severity"] == s) for s in SEVERITIES}
        out = {"score": score, "raw_score": raw, "grade": grade_of(score), "status": status_of(score) if scored
               else "unavailable", "caps": caps, "categories": cats, "recommendations": recs[:60],
               "recommendations_total": len(recs), "counts": counts,
               "scored_categories": len(scored), "computed_at": _iso(),
               "headline": self._headline(score, counts, bool(scored))}
        out["status_text"] = STATUS_TEXT[out["status"]]
        if record and scored:
            out["change"] = self._record(user_id, out)
        with self._lock:
            self._cache[user_id] = (time.monotonic(), out)
            if len(self._cache) > 64:
                self._cache.pop(next(iter(self._cache)))
        return out

    @staticmethod
    def _headline(score: int, counts: dict, any_scored: bool) -> str:
        if not any_scored:
            return "Security state can't be read right now"
        if counts["critical"]:
            return f"{counts['critical']} critical problem(s) need your attention now"
        if counts["high"]:
            return f"{counts['high']} important problem(s) to fix"
        if score >= 90:
            return "This PC is well protected"
        if counts["medium"]:
            return f"{counts['medium']} thing(s) could be improved"
        return "No urgent problems"

    def _record(self, uid: int, s: dict) -> dict | None:
        """Store a history point when the score changed or an hour passed. Returns the change vs. the last point."""
        last = self.db.fetchone("SELECT * FROM security_scores WHERE user_id IS ? ORDER BY id DESC LIMIT 1", (uid,))
        cats = {c["id"]: c["score"] for c in s["categories"] if c["score"] is not None}
        change = None
        if last:
            change = {"from": last["score"], "to": s["score"], "delta": s["score"] - last["score"], "since": last["ts"]}
            try:
                age = (datetime.now(timezone.utc) - datetime.strptime(last["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=timezone.utc)).total_seconds()
            except ValueError:                                       # pragma: no cover
                age = 1e9
            if last["score"] == s["score"] and json.loads(last["categories"]) == cats and age < 3600:
                return change
        self.db.execute("INSERT INTO security_scores(user_id, score, grade, status, issues, critical, high, categories) "
                        "VALUES (?,?,?,?,?,?,?,?)", (uid, s["score"], s["grade"], s["status"], s["recommendations_total"],
                                                     s["counts"]["critical"], s["counts"]["high"], json.dumps(cats)))
        drop = int(self._g("score_alert_drop"))
        if last and drop and last["score"] - s["score"] >= drop and self.notifications is not None:
            worst = next((r for r in s["recommendations"]), None)
            self.notifications.notify(
                "system", "high" if s["score"] < 50 else "medium",
                f"Security score fell from {last['score']} to {s['score']}",
                worst["title"] if worst else None, kind="score_drop", user_id=uid, link="dashboard")
        return change

    def history(self, user_id: int, days: int = 30) -> dict:
        rows = self.db.fetchall("SELECT ts, score, grade, status, issues, critical, high, categories FROM "
                                "security_scores WHERE user_id IS ? AND ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) "
                                "ORDER BY id", (user_id, f"-{days} days"))
        for r in rows:
            r["categories"] = json.loads(r["categories"])
        by_day: dict[str, dict] = {}
        for r in rows:                                               # last value of each day
            by_day[r["ts"][:10]] = {"day": r["ts"][:10], "score": r["score"], "issues": r["issues"]}
        scores = [r["score"] for r in rows]
        return {"days": days, "points": rows, "by_day": list(by_day.values()),
                "min": min(scores) if scores else None, "max": max(scores) if scores else None,
                "first": scores[0] if scores else None, "last": scores[-1] if scores else None,
                "trend": (scores[-1] - scores[0]) if len(scores) > 1 else 0}

    def cleanup(self) -> int:
        return self.db.execute("DELETE FROM security_scores WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)",
                               (f"-{int(self._g('score_history_days'))} days",)).rowcount

    def record_all(self) -> int:
        """Background: keep every user's history going even when the dashboard isn't open."""
        n = 0
        for u in self.db.fetchall("SELECT id FROM users"):
            try:
                self.compute(u["id"], refresh=True)
                n += 1
            except Exception as e:                                   # pragma: no cover
                log.debug("Score for user %s failed: %s", u["id"], e)
        return n

    # ================================================================== dashboard
    def dashboard(self, cu, days: int = 14, refresh: bool = False) -> dict:
        """Everything the front page shows, in one call. A failing module leaves its block as {'error': ...}."""
        uid = cu.user["id"]
        out: dict[str, Any] = {"generated_at": _iso(), "user": {k: cu.user.get(k) for k in
                                                               ("id", "username", "display_name", "role")}}

        def block(name: str, fn: Callable[[], Any]) -> None:
            try:
                out[name] = fn()
            except Exception as e:
                out[name] = {"error": (getattr(e, "message", None) or f"{type(e).__name__}: {e}")[:300]}
                if not hasattr(e, "status"):
                    log.debug("Dashboard block %s failed: %s", name, e)

        block("score", lambda: self.compute(uid, refresh))
        block("score_history", lambda: self.history(uid, 30))
        block("tiles", lambda: self._tiles(out.get("score") or {}))
        block("threats", lambda: self._threat_block(days))
        block("scans", self._scan_block)
        block("realtime", self._realtime_block)
        block("system", self._system_block)
        block("network", self._network_block)
        block("activity", lambda: self._activity_block(days))
        if self.notifications is not None:
            block("notifications", lambda: {"unread": self.notifications.unread(cu),
                                            "summary": self.notifications.summary(cu, days),
                                            "latest": self.notifications.list(cu, "open", limit=6)["items"]})
        if self.scheduler is not None:
            block("schedule", lambda: {"status": self.scheduler.status(), "upcoming": self.scheduler.upcoming(72, 5)})
        return out

    @staticmethod
    def _tiles(score: dict) -> list[dict]:
        return [{"id": c["id"], "name": c["name"], "link": c["link"], "score": c["score"], "grade": c["grade"],
                 "status": c["status"], "status_text": c["status_text"], "issues": c["issues"], "worst": c["worst"],
                 "note": c["note"]} for c in score.get("categories", [])]

    def _threat_block(self, days: int) -> dict:
        s = self.threat_history.summary(days)
        return {"days": days, "active": s["active_threats"], "active_by_severity": s["active_by_severity"],
                "by_status": s["by_status"], "handled_percent": s["handled_percent"], "by_day": s["by_day"],
                "top_threats": s["top_threats"][:5], "by_method": s["by_method"],
                "quarantined": s["quarantine"]["items"], "recommendation": s["recommendation"]}

    def _scan_block(self) -> dict:
        s = self.scanner.summary(14)
        return {"status": s["status"], "status_text": s["status_text"], "last_scan": s["last_scan"],
                "last_by_kind": s["last_by_kind"], "running": s["running"], "totals": s["totals"],
                "by_day": s["by_day"], "signatures": s["signatures"]["enabled"]}

    def _realtime_block(self) -> dict:
        r = self.realtime.status()
        return {"enabled": r["enabled"], "state": r["state"], "protected": r["protected"],
                "snoozed_until": r["snoozed_until"], "watching": r["watching"], "counters": r["counters"],
                "last_threat": r["last_threat"]}

    def _system_block(self) -> dict:
        from . import system_info
        stats = system_info.live_stats() if hasattr(system_info, "live_stats") else {}
        info = system_info.device_info() if hasattr(system_info, "device_info") else {}
        hist = self.db.fetchall("SELECT ts, cpu, memory, disk FROM metric_snapshots ORDER BY id DESC LIMIT 60")
        return {"stats": stats, "device": {"hostname": info.get("hostname"), "os": info.get("os"),
                                           "cpu": (info.get("cpu") or {}).get("model"),
                                           "memory_gb": (info.get("memory") or {}).get("total_gb"),
                                           "boot_time": info.get("boot_time")},
                "history": list(reversed(hist))}

    def _network_block(self) -> dict:
        out: dict[str, Any] = {}
        if self.firewall is not None:
            try:
                st = self.firewall.status()
                out["firewall"] = {"available": st.get("available", True), "score": st.get("score"),
                                   "grade": st.get("grade"), "profiles": [
                                       {"name": p.get("name"), "enabled": p.get("enabled"), "active": p.get("active")}
                                       for p in st.get("profiles", [])], "blocks": st.get("blocks")}
            except Exception as e:
                out["firewall"] = {"error": getattr(e, "message", str(e))[:200]}
        if self.network is not None:
            try:
                st = self.network.status()
                out["network"] = {k: st.get(k) for k in ("score", "grade", "connections", "listening", "wifi",
                                                         "lan", "unacknowledged", "findings") if k in st}
            except Exception as e:
                out["network"] = {"error": getattr(e, "message", str(e))[:200]}
        return out

    def _activity_block(self, days: int) -> dict:
        return {"summary": self.activity.summary(days), "latest": self.activity.list(limit=8)["items"]}


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(str(s), safe="")


async def score_loop(svc: ScoreService, every_seconds: float = 900.0) -> None:
    import asyncio
    await asyncio.sleep(60)
    ticks = 0
    while True:
        try:
            await asyncio.to_thread(svc.record_all)
            ticks += 1
            if ticks % 96 == 0:
                await asyncio.to_thread(svc.cleanup)
        except Exception as e:                                       # pragma: no cover
            log.warning("Score recording failed: %s", e)
        await asyncio.sleep(every_seconds)


__all__ = ["ScoreService", "score_loop", "grade_of", "status_of", "CATEGORIES"]
