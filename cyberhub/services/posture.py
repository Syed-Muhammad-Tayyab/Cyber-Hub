"""
Cyber Hub Backend - Windows Security Posture service (Part 11)
Developed by Syed Muhammad Tayyab

The "is this PC set up safely?" section - the same six areas as the Windows
Security app, each a list of explainable checks:

  * Virus & threat protection - an antivirus is on (Defender or another
    product registered with Security Center), real-time / behaviour / download
    / script scanning, Tamper Protection, cloud protection + sample submission,
    PUA blocking, network protection, controlled folder access, signature age,
    last quick scan, and DANGEROUS Defender exclusions (whole drives, Temp,
    Downloads, PowerShell, *.exe ... - a favourite malware trick).
  * Account protection - UAC on / prompt level / secure desktop, Guest account,
    built-in Administrator, accounts that may have a blank password, WDigest
    plaintext passwords in memory, LSA protection, screen lock.
  * Firewall & network protection - firewall on (read from Part 9, fixed
    through Part 9), Remote Desktop on + how exposed it is (Part 9's real
    inbound verdict), Network Level Authentication, Remote Assistance, SMBv1,
    LLMNR (Responder-style credential theft).
  * App & browser control - SmartScreen for apps / Edge / Store apps, Smart
    App Control, file extensions hidden, AutoPlay, PowerShell execution policy.
  * Device security - Secure Boot, TPM, Memory integrity, BitLocker on the
    Windows drive (laptops weigh more) + data drives, suspended BitLocker.
  * Windows Update & support - Windows version still supported (lifecycle
    table), last successful update, updates paused, update service disabled /
    turned off by policy, restart pending; on-demand search for missing updates.

Each check = pass / fail / unknown with severity, evidence, why it matters and
either a one-click fix (allow-listed changes only - see posture_backends) or
manual steps + a button that opens the right Windows settings page. Every fix
is verified by reading the setting back (Tamper Protection silently ignores
Defender changes - that is reported, not hidden), rolled back if a multi-step
fix half-fails, recorded with its previous values and can be undone. Checks
can be ignored (accepted risk, admin). 0-100 score + per-section scores,
score history, background watch that alerts when a setting gets weaker
(pass -> fail) or a new Defender exclusion appears.

Reusable later: analyze()["score"] / ["categories"] by Part 18, events by
Part 17, collect() facts by Part 19 reports.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..database import Database
from ..logger import get_logger
from .posture_backends import (EXCLUSION_KINDS, MP_PREFS, NEEDS_ADMIN, OPEN_TARGETS, REG_TARGETS, WU_PAUSE_TARGETS,
                               BackendError, PostureBackend, check_op, needs_elevation, pick_backend)

log = get_logger("posture")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
CATEGORIES = [
    ("virus", "Virus & threat protection"),
    ("account", "Account protection"),
    ("network", "Firewall & network protection"),
    ("app", "App & browser control"),
    ("device", "Device security"),
    ("updates", "Windows Update & support"),
]
CATEGORY_NAMES = dict(CATEGORIES)

# Windows 11 / 10 servicing - "End of updates" dates from Microsoft's release information pages
# (Home / Pro / Pro Education / Pro for Workstations, Enterprise / Education). Checked 2026-11-12.
WIN11 = {   # display version: (build, home_pro_end, enterprise_end)
    "21H2": (22000, "2023-10-10", "2024-10-08"),
    "22H2": (22621, "2024-10-08", "2025-10-14"),
    "23H2": (22631, "2025-11-11", "2026-11-10"),
    "24H2": (26100, "2026-10-13", "2027-10-12"),
    "25H2": (26200, "2027-10-12", "2028-10-10"),
    "26H1": (28000, "2028-03-14", "2028-03-14"),
    "26H2": (None, "2028-10-10", "2029-10-09"),
}
WIN10_END = "2025-10-14"            # Windows 10 22H2 (19045), all editions; consumer ESU possible
WIN10_LAST_BUILD = 19045
ENTERPRISE_EDITIONS = re.compile(r"^(enterprise|education|iotenterprise|serverrdsh)", re.I)
LTSC_EDITIONS = re.compile(r"^(enterprises|iotenterprises|enterprisesn)$", re.I)

PREF_FACT = {"DisableRealtimeMonitoring": "disable_realtime", "DisableBehaviorMonitoring": "disable_behavior",
             "DisableIOAVProtection": "disable_ioav", "DisableScriptScanning": "disable_script",
             "MAPSReporting": "maps", "SubmitSamplesConsent": "samples", "PUAProtection": "pua",
             "EnableNetworkProtection": "network_protection", "EnableControlledFolderAccess": "cfa"}

RISKY_EXCL_PROCS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "rundll32.exe", "regsvr32.exe", "explorer.exe", "svchost.exe", "msiexec.exe", "wmic.exe",
                    "certutil.exe", "bitsadmin.exe", "conhost.exe", "winword.exe", "excel.exe", "outlook.exe"}
RISKY_EXCL_EXTS = {"exe", "dll", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "scr", "com",
                   "msi", "lnk", "zip", "rar", "7z", "iso", "docm", "xlsm", "pptm", "jar", "sys"}
_RISKY_DIR_END = ("\\downloads", "\\desktop", "\\documents", "\\appdata", "\\appdata\\local",
                  "\\appdata\\roaming", "\\appdata\\local\\temp", "\\temp", "\\tmp", "\\users\\public")
_RISKY_DIR_EXACT = {"c:\\windows", "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\temp",
                    "c:\\users", "c:\\programdata", "c:\\program files", "c:\\program files (x86)", "c:\\temp",
                    "%temp%", "%tmp%", "%userprofile%", "%appdata%", "%localappdata%", "%programdata%",
                    "%windir%", "%systemroot%", "%public%", "*"}


class PostureError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat()


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _age_days(s: str | None, now: datetime) -> int | None:
    d = _parse(s)
    return None if d is None else max(0, (now - d).days)


def _boot_iso() -> str:
    """When this PC last started - fixes that need a restart and are newer than this are still waiting."""
    try:
        import psutil
        return datetime.fromtimestamp(psutil.boot_time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:                                                   # pragma: no cover
        return ""


def _sev_max(a: str, b: str) -> str:
    return a if SEVERITIES.index(a) >= SEVERITIES.index(b) else b


# ====================================================================== check builders
def check(cid: str, category: str, title: str, status: str, severity: str = "info", *, detail: str = "",
          value: str | None = None, why: str = "", evidence: dict | None = None, fix: dict | None = None,
          manual: dict | None = None, managed: bool = False) -> dict:
    return {"id": cid, "category": category, "category_name": CATEGORY_NAMES[category], "title": title,
            "status": status, "severity": severity if status == "fail" else "info", "value": value,
            "detail": detail, "why": why, "evidence": evidence or {}, "fix": fix, "manual": manual,
            "managed": managed, "ignored": None}


def fix(label: str, ops: list[dict], *, admin: bool = False, confirm: str | None = None,
        reboot: bool = False) -> dict:
    elev = any(o["op"] not in ("firewall_on",) and needs_elevation(o) for o in ops if o["op"] != "firewall_on")
    return {"label": label, "ops": ops, "admin": admin, "confirm": confirm, "reboot": reboot,
            "needs_elevation": elev, "reversible": all(o["op"] not in ("mp_update", "mp_scan") for o in ops)}


def manual(steps: list[str], open_target: str | None = None) -> dict:
    return {"steps": steps, "open": open_target if open_target in OPEN_TARGETS else None}


def reg(target: str, value: Any) -> dict:
    return {"op": "reg_set", "target": target, "value": value}


def mp(pref: str, value: Any) -> dict:
    return {"op": "mp_pref", "pref": pref, "value": value}


# ====================================================================== lifecycle
def windows_support(os_facts: dict, today: date) -> dict | None:
    """-> {version, end, days_left, edition_kind} or None (server / LTSC / unknown)."""
    build = os_facts.get("build") or 0
    if not build or (os_facts.get("product_type") or 1) != 1:
        return None
    ed = str(os_facts.get("edition_id") or "")
    if LTSC_EDITIONS.match(ed):
        return {"version": "LTSC", "end": None, "days_left": None, "edition_kind": "ltsc"}
    ent = bool(ENTERPRISE_EDITIONS.match(ed))
    if build < 22000:
        end = WIN10_END if build >= WIN10_LAST_BUILD else "2023-06-13"
        return {"version": f"Windows 10 (build {build})", "product": "Windows 10", "end": end,
                "days_left": (date.fromisoformat(end) - today).days, "edition_kind": "enterprise" if ent else "home_pro"}
    dv = str(os_facts.get("display_version") or "").upper()
    if dv not in WIN11:
        dv = next((v for v, (b, _, _) in WIN11.items() if b == build), "")
    if not dv:
        known = max(b for b, _, _ in WIN11.values() if b)
        if build > known:
            return {"version": f"Windows 11 build {build}", "product": "Windows 11", "end": None, "days_left": None,
                    "edition_kind": "enterprise" if ent else "home_pro", "newer": True}
        return None
    _, home, enterprise = WIN11[dv]
    end = enterprise if ent else home
    return {"version": f"Windows 11 {dv}", "product": "Windows 11", "end": end,
            "days_left": (date.fromisoformat(end) - today).days, "edition_kind": "enterprise" if ent else "home_pro"}


# ====================================================================== exclusions
def _norm_excl_path(p: str) -> str:
    return p.strip().strip('"').rstrip("\\/").replace("/", "\\").lower()


def exclusion_risk(kind: str, value: str, own_dirs: tuple[str, ...] = ()) -> str | None:
    """Why this Defender exclusion is dangerous, or None if it is a normal, narrow one."""
    v = value.strip()
    if kind == "path":
        p = _norm_excl_path(v)
        if any(p == d or p.startswith(d + "\\") for d in own_dirs):
            return None
        if re.fullmatch(r"[a-z]:|[a-z]:\\\*?|\*|[a-z]:\\\*\.\*", p):
            return "excludes a whole drive"
        if p in _RISKY_DIR_EXACT:
            return "excludes a system or shared folder malware writes to"
        if re.fullmatch(r"c:\\users\\[^\\]+", p):
            return "excludes a whole user profile"
        if p.endswith(_RISKY_DIR_END) or "\\appdata\\local\\temp" in p or p.startswith(("%temp%", "%tmp%")):
            return "excludes a download / temporary folder - exactly where malware lands"
        if "*" in p.split("\\")[0:2] or p.startswith("*"):
            return "wildcard at the top of the path"
        return None
    if kind == "process":
        name = re.split(r"[\\/]", v.lower())[-1]
        if name in RISKY_EXCL_PROCS:
            return f"excludes everything {name} opens - attackers run their code through it"
        if v.strip() in ("*", "*.*"):
            return "excludes every process"
        return None
    ext = v.lower().lstrip("*").lstrip(".")
    if ext in RISKY_EXCL_EXTS or ext in ("*", ""):
        return f"excludes every .{ext or '*'} file - a common malware file type"
    return None


# ====================================================================== evaluate
def evaluate(facts: dict, ctx: dict) -> list[dict]:
    """facts (from a backend) + ctx {now, signature_max_age, update_max_age, scan_max_age, firewall{...},
    rdp_verdict, smb_verdict, own_dirs} -> list of checks. Pure function: no I/O."""
    now: datetime = ctx.get("now") or _now()
    win = facts.get("platform") == "windows"
    out: list[dict] = []
    add = out.append
    o = facts.get("os") or {}
    portable = bool(o.get("portable"))

    # ------------------------------------------------------------ virus & threat protection
    av = facts.get("av")
    if win and av is not None:
        d, prefs, products = av.get("defender"), av.get("prefs"), av.get("products")
        third = [p for p in (products or []) if not p["is_defender"] and p["enabled"]]
        defender_on = bool(d and d.get("antivirus") and d.get("service") and not d.get("passive"))
        if defender_on:
            add(check("av_active", "virus", "Antivirus protection", "pass", value="Microsoft Defender Antivirus",
                      detail="Microsoft Defender Antivirus is protecting this PC.",
                      evidence={"products": products, "mode": d.get("mode")}))
        elif third:
            add(check("av_active", "virus", "Antivirus protection", "pass", value=third[0]["name"],
                      detail=f"Protected by {third[0]['name']} (Microsoft Defender steps back while another "
                             f"antivirus is active - that is normal).",
                      evidence={"products": products}))
            stale = [p["name"] for p in third if p["up_to_date"] is False]
            if stale:
                add(check("av_third_party_outdated", "virus", "Antivirus signatures", "fail", "high",
                          value="Out of date", detail=f"{', '.join(stale)} reports out-of-date signatures.",
                          why="An antivirus without current signatures misses new malware.",
                          manual=manual([f"Open {stale[0]} and run its update."])))
        elif products is None and (d is None or d.get("passive")):
            add(check("av_active", "virus", "Antivirus protection", "unknown", value="Could not read",
                      detail="Windows did not report any active antivirus: " + str(av.get("error") or
                                                                                   "Defender is in passive mode")[:160]))
        else:
            add(check("av_active", "virus", "Antivirus protection", "fail", "critical", value="No active antivirus",
                      detail="Neither Microsoft Defender nor another antivirus is turned on.",
                      why="Without an antivirus, malware that arrives by download, USB or e-mail runs freely.",
                      manual=manual(["Open Windows Security > Virus & threat protection.",
                                     "Under 'Virus & threat protection settings' turn Real-time protection on, "
                                     "or reinstall / re-enable your antivirus."], "virus_protection")))
        if defender_on and d:
            tamper = bool(d.get("tamper"))
            tamper_note = (" Tamper Protection is on, so only Windows Security itself can change this - use the "
                           "button to open it." if tamper else "")
            dfx = (lambda label, pref, val, **kw: None if tamper else fix(label, [mp(pref, val)], **kw))
            dman = (lambda: manual(["Open Windows Security > Virus & threat protection > Manage settings.",
                                    "Switch the setting on."], "defender_settings"))
            if d.get("realtime") is False:
                add(check("defender_realtime", "virus", "Real-time protection", "fail", "critical", value="Off",
                          detail="Defender only scans when you ask it to." + tamper_note,
                          why="Real-time protection stops malware the moment it is downloaded or started.",
                          fix=dfx("Turn real-time protection on", "DisableRealtimeMonitoring", False),
                          manual=dman()))
            else:
                add(check("defender_realtime", "virus", "Real-time protection", "pass", value="On"))
            for cid, key, title, why, pref in (
                    ("defender_behavior", "behavior", "Behaviour monitoring",
                     "Catches malware by what it does (injecting, encrypting files), not only by signature.",
                     "DisableBehaviorMonitoring"),
                    ("defender_downloads", "ioav", "Scan downloads and attachments",
                     "Files from the browser, e-mail and chat apps are scanned before they open.",
                     "DisableIOAVProtection")):
                if d.get(key) is False:
                    add(check(cid, "virus", title, "fail", "high", value="Off", why=why, detail=tamper_note.strip(),
                              fix=dfx(f"Turn {title.lower()} on", pref, False), manual=dman()))
                elif d.get(key) is True:
                    add(check(cid, "virus", title, "pass", value="On"))
            if prefs and prefs.get("disable_script"):
                add(check("defender_scripts", "virus", "Script scanning", "fail", "medium", value="Off",
                          why="PowerShell / JavaScript / VBScript malware is checked through AMSI before it runs.",
                          detail=tamper_note.strip(), fix=dfx("Turn script scanning on", "DisableScriptScanning",
                                                              False), manual=dman()))
            elif prefs:
                add(check("defender_scripts", "virus", "Script scanning", "pass", value="On"))
            if d.get("tamper") is False:
                add(check("defender_tamper", "virus", "Tamper Protection", "fail", "high", value="Off",
                          why="Stops malware (and scripts) from switching Defender off behind your back.",
                          detail="Windows only lets you switch this on yourself, in Windows Security.",
                          manual=manual(["Open Windows Security > Virus & threat protection > Manage settings.",
                                         "Turn 'Tamper Protection' on."], "defender_settings")))
            elif d.get("tamper") is True:
                add(check("defender_tamper", "virus", "Tamper Protection", "pass", value="On"))
            if prefs:
                maps = prefs.get("maps")
                if maps == 0:
                    add(check("defender_cloud", "virus", "Cloud-delivered protection", "fail", "medium", value="Off",
                              why="New malware is usually identified in the cloud within seconds - hours before a "
                                  "signature update reaches you.", detail=tamper_note.strip(),
                              fix=dfx("Turn cloud protection on", "MAPSReporting", 2), manual=dman()))
                elif maps is not None:
                    add(check("defender_cloud", "virus", "Cloud-delivered protection", "pass", value="On"))
                if prefs.get("samples") == 2:
                    add(check("defender_samples", "virus", "Automatic sample submission", "fail", "low",
                              value="Never send", why="Cloud protection can hold a suspicious file until a sample "
                                                      "is checked; with 'never send' it cannot.",
                              detail=tamper_note.strip(),
                              fix=dfx("Send safe samples automatically", "SubmitSamplesConsent", 1), manual=dman()))
                elif prefs.get("samples") is not None:
                    add(check("defender_samples", "virus", "Automatic sample submission", "pass", value="On"))
                if prefs.get("pua") in (0, None):
                    add(check("defender_pua", "virus", "Block potentially unwanted apps", "fail", "medium",
                              value="Off", why="Blocks adware, bundled toolbars, crypto miners and 'PC cleaners' "
                                               "that are not quite malware.",
                              fix=fix("Block unwanted apps", [mp("PUAProtection", 1)])))
                elif prefs.get("pua") == 2:
                    add(check("defender_pua", "virus", "Block potentially unwanted apps", "fail", "low",
                              value="Audit only", detail="Unwanted apps are only logged, not blocked.",
                              fix=fix("Block unwanted apps", [mp("PUAProtection", 1)])))
                else:
                    add(check("defender_pua", "virus", "Block potentially unwanted apps", "pass", value="On"))
                np_ = prefs.get("network_protection")
                if np_ in (0, 2):
                    add(check("defender_network_protection", "virus", "Network protection", "fail", "low",
                              value="Off" if np_ == 0 else "Audit only",
                              why="Stops any program (not only the browser) from reaching known phishing, scam "
                                  "and malware sites.",
                              fix=fix("Turn network protection on", [mp("EnableNetworkProtection", 1)])))
                elif np_ == 1:
                    add(check("defender_network_protection", "virus", "Network protection", "pass", value="On"))
                cfa = prefs.get("cfa")
                if cfa in (0, 2, 3, 4):
                    add(check("defender_cfa", "virus", "Ransomware protection (Controlled folder access)", "fail",
                              "info", value="Off" if cfa == 0 else "Audit / partial",
                              why="Only trusted apps may change files in Documents, Pictures, Desktop... - "
                                  "ransomware cannot encrypt them.",
                              detail="Optional: some programs need to be allowed once before they can save there.",
                              fix=fix("Turn on controlled folder access", [mp("EnableControlledFolderAccess", 1)],
                                      confirm="Programs Windows does not know yet (games, editors, dev tools) will "
                                              "be blocked from saving into Documents / Desktop / Pictures until "
                                              "you allow them in Windows Security.")))
                elif cfa == 1:
                    add(check("defender_cfa", "virus", "Ransomware protection (Controlled folder access)", "pass",
                              value="On"))
            age = d.get("signature_age_days")
            lim = int(ctx.get("signature_max_age", 3))
            if age is not None:
                if age > lim:
                    add(check("defender_signatures", "virus", "Virus definitions up to date", "fail",
                              "high" if age > 7 else "medium", value=f"{age} days old",
                              detail=f"Version {d.get('signature_version') or '?'}.",
                              why="Defender gets several definition updates a day; old definitions miss new "
                                  "malware.", evidence={"age_days": age, "version": d.get("signature_version")},
                              fix=fix("Update definitions now", [{"op": "mp_update"}])))
                else:
                    add(check("defender_signatures", "virus", "Virus definitions up to date", "pass",
                              value="Today" if age == 0 else f"{age} day(s) old",
                              evidence={"age_days": age, "version": d.get("signature_version")}))
            q = d.get("quick_scan_age_days")
            slim = int(ctx.get("scan_max_age", 14))
            if q is None or q > slim:
                add(check("defender_scan", "virus", "Recent Defender scan", "fail", "low",
                          value="Never" if q is None else f"{q} days ago",
                          why="A periodic quick scan catches anything that slipped past real-time protection.",
                          fix=fix("Start a quick scan", [{"op": "mp_scan", "type": "quick"}])))
            else:
                add(check("defender_scan", "virus", "Recent Defender scan", "pass",
                          value="Today" if q == 0 else f"{q} day(s) ago"))
        # exclusions (count even when another antivirus is active - Defender may come back)
        if prefs is not None:
            ex = prefs.get("exclusions") or {}
            if not ex.get("readable"):
                add(check("defender_exclusions", "virus", "Defender exclusions", "unknown", value="Hidden",
                          detail="Windows only shows exclusions to administrators - start Cyber Hub with "
                                 "start_cyberhub_admin.bat to check them."))
            else:
                items, risky = [], []
                for kind in ("path", "process", "extension"):
                    for v in ex.get(kind) or []:
                        r = exclusion_risk(kind, v, tuple(ctx.get("own_dirs") or ()))
                        items.append({"kind": kind, "value": v, "risk": r})
                        if r:
                            risky.append({"kind": kind, "value": v, "risk": r})
                if risky:
                    add(check("defender_exclusions", "virus", "Defender exclusions", "fail", "high",
                              value=f"{len(risky)} dangerous",
                              detail="; ".join(f"{x['value']} ({x['risk']})" for x in risky[:5]),
                              why="Anything inside an excluded location is never scanned. Malware often adds its "
                                  "own folder - and people exclude Downloads 'to make it faster'.",
                              evidence={"exclusions": items, "risky": risky},
                              fix=fix(f"Remove {len(risky)} dangerous exclusion(s)",
                                      [{"op": "mp_exclusion", "kind": x["kind"], "value": x["value"], "remove": True}
                                       for x in risky], admin=True,
                                      confirm="Defender will scan these locations again; a tool that needed the "
                                              "exclusion may get slower or be flagged.")))
                else:
                    add(check("defender_exclusions", "virus", "Defender exclusions", "pass",
                              value=f"{len(items)} (all narrow)" if items else "None", evidence={"exclusions": items}))

    # ------------------------------------------------------------ account protection
    uac = facts.get("uac")
    if win and uac is not None:
        lua, cons, sd = uac.get("enable_lua"), uac.get("consent_admin"), uac.get("secure_desktop")
        if lua == 0:
            add(check("uac_enabled", "account", "User Account Control", "fail", "critical", value="Off",
                      why="With UAC off every program you start runs with full administrator rights - malware "
                          "included.", fix=fix("Turn UAC on", [reg("uac_enable_lua", 1)], reboot=True)))
        else:
            add(check("uac_enabled", "account", "User Account Control", "pass", value="On"))
            if cons == 0:
                add(check("uac_prompt", "account", "UAC prompt level", "fail", "high", value="Never notify",
                          why="Programs silently get administrator rights without asking you.",
                          fix=fix("Ask before changes (default)", [reg("uac_consent_admin", 5)])))
            elif cons is not None:
                add(check("uac_prompt", "account", "UAC prompt level", "pass",
                          value={1: "Ask for password (secure desktop)", 2: "Always notify", 3: "Ask for password",
                                 4: "Ask for consent", 5: "Notify for app changes (default)"}.get(cons, str(cons))))
            if sd == 0 and cons != 0:
                add(check("uac_secure_desktop", "account", "UAC secure desktop", "fail", "medium", value="Off",
                          why="On the dimmed secure desktop other programs cannot click 'Yes' for you.",
                          fix=fix("Use the secure desktop", [reg("uac_secure_desktop", 1)])))
            elif sd is not None:
                add(check("uac_secure_desktop", "account", "UAC secure desktop", "pass", value="On"))
    acc = facts.get("accounts")
    if win and acc is not None:
        users = acc.get("users") or []
        guest = next((u for u in users if u["builtin"] == "guest"), None)
        if guest:
            if guest["enabled"]:
                add(check("guest_account", "account", "Guest account", "fail", "high", value="Enabled",
                          why="Anyone can sign in without a password and reach shared files and the network.",
                          fix=fix("Disable the Guest account",
                                  [{"op": "user_enabled", "sid": guest["sid"], "enabled": False}])))
            else:
                add(check("guest_account", "account", "Guest account", "pass", value="Disabled"))
        admin = next((u for u in users if u["builtin"] == "admin"), None)
        if admin:
            if admin["enabled"]:
                add(check("builtin_admin", "account", "Built-in Administrator account", "fail", "medium",
                          value="Enabled", evidence={"name": admin["name"]},
                          why="The first account attackers try: its name is well known and it is never locked "
                              "out after wrong passwords.",
                          fix=fix("Disable it", [{"op": "user_enabled", "sid": admin["sid"], "enabled": False}],
                                  admin=True, confirm=f"Make sure you can sign in with another administrator "
                                                      f"account before disabling '{admin['name']}'.")))
            else:
                add(check("builtin_admin", "account", "Built-in Administrator account", "pass", value="Disabled"))
        blank = [u["name"] for u in users if u["enabled"] and u["builtin"] is None and
                 u.get("password_required") is False]
        if blank:
            add(check("blank_passwords", "account", "Accounts without a required password", "fail", "medium",
                      value=", ".join(blank[:5]), evidence={"accounts": blank},
                      why="These accounts are allowed to have an empty password - anyone at the keyboard (or on "
                          "the network) can sign in as them.",
                      manual=manual(["Open Settings > Accounts > Other users (or Family).",
                                     "Give each listed account a password, or remove accounts nobody uses."],
                                    "accounts")))
        elif users:
            add(check("blank_passwords", "account", "Accounts without a required password", "pass", value="None"))
        admins = acc.get("admins")
        if admins is not None:
            add(check("admin_accounts", "account", "Administrator accounts", "pass" if len(admins) <= 2 else "fail",
                      "low", value=str(len(admins)), evidence={"admins": admins},
                      detail=", ".join(admins[:8]),
                      why="Every extra administrator is another password that unlocks the whole PC. Use a "
                          "standard account for daily work.",
                      manual=None if len(admins) <= 2 else manual(
                          ["Open Settings > Accounts > Other users.",
                           "Change accounts that do not need it to 'Standard User'."], "accounts")))
    hd = facts.get("hardening")
    if win and hd is not None:
        if hd.get("wdigest") == 1:
            add(check("wdigest", "account", "Plain-text passwords in memory (WDigest)", "fail", "high", value="On",
                      why="Passwords are kept readable in memory - one Mimikatz run dumps them all.",
                      fix=fix("Turn WDigest caching off", [reg("wdigest", 0)], reboot=True)))
        else:
            add(check("wdigest", "account", "Plain-text passwords in memory (WDigest)", "pass", value="Off"))
        if hd.get("lsa_ppl") in (1, 2):
            add(check("lsa_protection", "account", "Local Security Authority protection", "pass", value="On"))
        else:
            add(check("lsa_protection", "account", "Local Security Authority protection", "fail", "low",
                      value="Off", why="Stops tools from reading passwords and tickets out of LSASS memory.",
                      detail="Turn on manually - a few old drivers / smart-card tools may stop working.",
                      manual=manual(["Open Windows Security > Device security > Core isolation details.",
                                     "Turn 'Local Security Authority protection' on and restart."],
                                    "core_isolation")))
        inact = hd.get("inactivity") or 0
        ss_ok = hd.get("ss_active") == 1 and hd.get("ss_secure") == 1 and 0 < (hd.get("ss_timeout") or 0) <= 1800
        if (0 < inact <= 1800) or ss_ok:
            add(check("screen_lock", "account", "Lock the screen when idle", "pass",
                      value=f"after {round((inact or hd.get('ss_timeout') or 0) / 60)} min"))
        else:
            add(check("screen_lock", "account", "Lock the screen when idle", "fail", "low", value="Not set",
                      why="An unlocked, unattended PC gives anyone nearby your accounts and files.",
                      detail="Sets a screen saver that asks for your password after 15 minutes.",
                      fix=fix("Lock after 15 minutes idle", [reg("ss_active", "1"), reg("ss_secure", "1"),
                                                            reg("ss_timeout", "900")])))

    # ------------------------------------------------------------ firewall & network protection
    fw = ctx.get("firewall")
    if fw is not None:
        if fw.get("error") or fw.get("state") == "unavailable":
            add(check("firewall_on", "network", "Firewall", "unknown", value="Unknown",
                      detail=str(fw.get("error") or "No supported firewall")[:200]))
        else:
            off = [p["name"] for p in fw.get("profiles") or [] if not p.get("enabled")]
            if off:
                sev = "critical" if ("public" in off or "all" in off) else "high"
                add(check("firewall_on", "network", "Firewall", "fail", sev,
                          value="Off for " + ", ".join(n.capitalize() for n in off),
                          why="Programs listening on this PC can be reached by everyone on the network.",
                          evidence={"profiles_off": off},
                          fix={"label": "Turn the firewall on", "ops": [{"op": "firewall_on", "profiles": off}],
                               "admin": False, "confirm": None, "reboot": False, "needs_elevation": True,
                               "reversible": True}))
            else:
                add(check("firewall_on", "network", "Firewall", "pass", value="On",
                          evidence={"score": fw.get("score")}))
    rdp = facts.get("rdp")
    if win and rdp is not None and rdp.get("enabled") is not None:
        if rdp["enabled"]:
            v = ctx.get("rdp_verdict") or {}
            verdict = v.get("verdict")
            sev = {"open": "high", "allowed": "high" if v.get("scope") == "any" else "medium",
                   "blocked": "low"}.get(verdict, "medium")
            reach = {"open": "reachable from the network (firewall off for it)",
                     "allowed": "allowed through the firewall" + (" from any address" if v.get("scope") == "any"
                                                                   else " from some addresses"),
                     "blocked": "blocked by the firewall right now"}.get(verdict, "firewall state unknown")
            add(check("remote_desktop", "network", "Remote Desktop", "fail", sev,
                      value=f"On (port {rdp.get('port')})", detail=f"Remote Desktop is {reach}.",
                      evidence={"port": rdp.get("port"), "firewall": v}, managed=rdp.get("policy_managed", False),
                      why="Exposed Remote Desktop is the #1 way ransomware gangs get in (password guessing, "
                          "stolen passwords). Turn it off if you do not use it.",
                      fix=None if rdp.get("policy_managed") else fix(
                          "Turn Remote Desktop off", [reg("rdp_deny", 1)], admin=True,
                          confirm="Anyone who uses Remote Desktop to reach this PC will be cut off."),
                      manual=manual(["Open Settings > System > Remote Desktop and turn it off."], "remote_desktop")))
            nla = rdp.get("policy_nla") if rdp.get("policy_nla") is not None else rdp.get("nla")
            if nla == 0:
                add(check("rdp_nla", "network", "Remote Desktop sign-in before connecting (NLA)", "fail", "high",
                          value="Off", managed=rdp.get("policy_nla") is not None,
                          why="Without Network Level Authentication anyone can open a session screen and probe "
                              "Remote Desktop bugs (BlueKeep-style) before signing in.",
                          fix=None if rdp.get("policy_nla") is not None else fix(
                              "Require NLA", [reg("rdp_nla", 1)],
                              confirm="Very old Remote Desktop apps (before Windows 7) will no longer connect.")))
            else:
                add(check("rdp_nla", "network", "Remote Desktop sign-in before connecting (NLA)", "pass", value="On"))
        else:
            add(check("remote_desktop", "network", "Remote Desktop", "pass", value="Off"))
        if rdp.get("assistance") == 1:
            add(check("remote_assistance", "network", "Remote Assistance", "fail", "low", value="Allowed",
                      why="Tech-support scammers ask victims to send a Remote Assistance invitation.",
                      fix=fix("Turn Remote Assistance off", [reg("remote_assistance", 0)])))
        elif rdp.get("assistance") is not None:
            add(check("remote_assistance", "network", "Remote Assistance", "pass", value="Off"))
    if win and hd is not None:
        smb1 = hd.get("smb1")
        if smb1 is True:
            add(check("smb1", "network", "SMBv1 file sharing protocol", "fail", "high", value="On",
                      why="The 30-year-old protocol WannaCry and NotPetya spread through. Nothing modern needs it.",
                      fix=fix("Turn SMBv1 off", [reg("smb1_server", 0)], reboot=True,
                              confirm="Very old NAS boxes, printers or Windows XP machines that only speak SMBv1 "
                                      "will no longer reach this PC's shared folders.")))
        elif smb1 is False:
            add(check("smb1", "network", "SMBv1 file sharing protocol", "pass", value="Off"))
        if hd.get("llmnr") == 0:
            add(check("llmnr", "network", "LLMNR name broadcasts", "pass", value="Off"))
        else:
            add(check("llmnr", "network", "LLMNR name broadcasts", "fail", "low", value="On",
                      why="When a name is mistyped Windows asks the whole network - a tool like Responder answers "
                          "and collects your password hash.",
                      fix=fix("Turn LLMNR off", [reg("llmnr", 0)])))

    # ------------------------------------------------------------ app & browser control
    ss = facts.get("smartscreen")
    if win and ss is not None:
        pol = ss.get("policy")
        ex = ss.get("explorer")
        if pol == 0 or (pol is None and ex == "off"):
            add(check("smartscreen_apps", "app", "SmartScreen for apps and files", "fail", "high", value="Off",
                      managed=pol == 0,
                      why="Warns before you run a downloaded program nobody has seen before - the typical first "
                          "stage of an infection.",
                      fix=None if pol == 0 else fix("Turn SmartScreen on (warn)", [reg("smartscreen_explorer",
                                                                                         "Warn")]),
                      manual=manual(["Open Windows Security > App & browser control > Reputation-based protection.",
                                     "Turn 'Check apps and files' on."], "app_browser")))
        else:
            add(check("smartscreen_apps", "app", "SmartScreen for apps and files", "pass",
                      value="Managed by policy" if pol == 1 else ("Block" if ex == "requireadmin" else "Warn")))
        edge = ss.get("edge_policy") if ss.get("edge_policy") is not None else ss.get("edge")
        if edge == 0:
            add(check("smartscreen_edge", "app", "SmartScreen in Microsoft Edge", "fail", "medium", value="Off",
                      managed=ss.get("edge_policy") == 0,
                      why="Blocks phishing and malware sites in the browser.",
                      manual=manual(["Open Edge > Settings > Privacy, search, and services > Security.",
                                     "Turn 'Microsoft Defender SmartScreen' on."], "app_browser")))
        else:
            add(check("smartscreen_edge", "app", "SmartScreen in Microsoft Edge", "pass", value="On"))
        if ss.get("store") == 0:
            add(check("smartscreen_store", "app", "SmartScreen for Microsoft Store apps", "fail", "low", value="Off",
                      why="Checks web content that Store apps load.",
                      fix=fix("Turn it on", [reg("store_web_eval", 1)])))
        else:
            add(check("smartscreen_store", "app", "SmartScreen for Microsoft Store apps", "pass", value="On"))
        sac = ss.get("smart_app_control")
        if sac is not None:
            add(check("smart_app_control", "app", "Smart App Control", "pass" if sac == 1 else "fail", "info",
                      value={0: "Off", 1: "On", 2: "Evaluation"}.get(sac, str(sac)),
                      detail="Optional (Windows 11): only lets known-good apps run. Once off it can only be turned "
                             "back on by reinstalling Windows, so Cyber Hub never changes it." if sac != 1 else ""))
    if win and hd is not None:
        if hd.get("hide_ext") == 0:
            add(check("file_extensions", "app", "Show file extensions", "pass", value="Shown"))
        else:
            add(check("file_extensions", "app", "Show file extensions", "fail", "low", value="Hidden",
                      why="'invoice.pdf.exe' shows up as 'invoice.pdf' - the oldest trick for making a program "
                          "look like a document.", fix=fix("Show file extensions", [reg("hide_ext", 0)])))
        autorun_all = (hd.get("nodrive_autorun") or 0) & 0xFF == 0xFF
        if hd.get("autoplay_off") == 1 or autorun_all:
            add(check("autoplay", "app", "AutoPlay for USB drives and discs", "pass", value="Off"))
        else:
            add(check("autoplay", "app", "AutoPlay for USB drives and discs", "fail", "low", value="On",
                      why="Plugging in a stick should never start anything by itself (Cyber Hub's real-time "
                          "protection scans USB drives instead).",
                      fix=fix("Turn AutoPlay off", [reg("autoplay_off", 1)])))
        pu, pm = hd.get("ps_user") or "Undefined", hd.get("ps_machine") or "Undefined"
        effective = pu if pu != "Undefined" else pm
        if effective in ("Unrestricted", "Bypass"):
            add(check("ps_execution_policy", "app", "PowerShell script policy", "fail", "low", value=effective,
                      evidence={"current_user": pu, "local_machine": pm},
                      why="Any downloaded .ps1 script runs without a warning. RemoteSigned still runs your own "
                          "scripts but stops unsigned ones from the internet.",
                      fix=fix("Set RemoteSigned for your account", [{"op": "exec_policy", "policy": "RemoteSigned"}])))
        else:
            add(check("ps_execution_policy", "app", "PowerShell script policy", "pass",
                      value="Windows default" if effective == "Undefined" else effective))

    # ------------------------------------------------------------ device security
    sb = facts.get("secure_boot")
    if sb is not None:
        if sb.get("uefi") is False:
            add(check("secure_boot", "device", "Secure Boot", "fail", "medium", value="Legacy BIOS mode",
                      why="Secure Boot stops bootkits / rootkits that load before Windows (and the antivirus).",
                      detail="This PC starts in legacy BIOS mode, which cannot use Secure Boot.",
                      manual=manual(["Back up first. Convert the disk with 'mbr2gpt /convert' (Windows).",
                                     "Switch the firmware (BIOS) to UEFI mode, then turn Secure Boot on."],
                                    "device_security")))
        elif sb.get("enabled") is False:
            add(check("secure_boot", "device", "Secure Boot", "fail", "high", value="Off",
                      why="Secure Boot stops bootkits / rootkits that load before Windows (and the antivirus).",
                      manual=manual(["Restart into the firmware settings (Settings > System > Recovery > Advanced "
                                     "startup > Restart now > Troubleshoot > UEFI Firmware Settings).",
                                     "Find 'Secure Boot', set it to Enabled, save and exit."], "recovery")))
        elif sb.get("enabled") is True:
            add(check("secure_boot", "device", "Secure Boot", "pass", value="On"))
        else:
            add(check("secure_boot", "device", "Secure Boot", "unknown", value="Unknown"))
    tpm = facts.get("tpm")
    if tpm is not None:
        if tpm.get("present") is False:
            add(check("tpm", "device", "Security processor (TPM)", "fail", "medium", value="Not found",
                      why="The TPM protects BitLocker keys, Windows Hello and passkeys in hardware.",
                      detail="Many PCs have one switched off in the firmware (Intel PTT / AMD fTPM).",
                      manual=manual(["Restart into the firmware settings and enable 'Intel PTT', 'AMD fTPM' or "
                                     "'Security Device Support'."], "recovery")))
        elif tpm.get("present") is True:
            if tpm.get("version") == "1.2":
                add(check("tpm", "device", "Security processor (TPM)", "fail", "low", value="TPM 1.2",
                          why="TPM 1.2 uses old cryptography (SHA-1) and does not meet Windows 11's requirement."))
            elif tpm.get("ready") is False:
                add(check("tpm", "device", "Security processor (TPM)", "fail", "medium", value="Not ready",
                          why="The TPM is there but not ready, so BitLocker / Windows Hello cannot use it.",
                          manual=manual(["Open the TPM console (tpm.msc) and choose 'Prepare the TPM'."], "tpm")))
            else:
                add(check("tpm", "device", "Security processor (TPM)", "pass",
                          value=f"TPM {tpm.get('version') or ''}".strip()))
        else:
            add(check("tpm", "device", "Security processor (TPM)", "unknown", value="Unknown"))
    if win and hd is not None:
        if hd.get("hvci") == 1 or hd.get("hvci_running"):
            add(check("memory_integrity", "device", "Memory integrity (Core isolation)", "pass",
                      value="On" if hd.get("hvci_running") else "On (after restart)"))
        else:
            add(check("memory_integrity", "device", "Memory integrity (Core isolation)", "fail", "medium",
                      value="Off", why="Uses virtualization to stop malicious drivers from tampering with the "
                                       "Windows kernel.",
                      detail="Turn on manually: Windows first checks every driver is compatible.",
                      manual=manual(["Open Windows Security > Device security > Core isolation details.",
                                     "Turn 'Memory integrity' on and restart."], "core_isolation")))
    bl = facts.get("bitlocker")
    if bl is not None:
        vols = bl.get("volumes") or []
        osv = next((v for v in vols if v["kind"] == "os"), None)
        label = "BitLocker" if win else "Disk encryption"
        steps = (["Open Control Panel > BitLocker Drive Encryption (or Settings > Privacy & security > Device "
                  "encryption on Home).", "Turn it on for the Windows drive and SAVE the recovery key (Microsoft "
                  "account or a USB stick) - without it a firmware change can lock you out."]
                 if win else ["Encryption can only be chosen when installing Linux (LUKS).",
                              "Reinstall with 'Encrypt the new installation' after backing up."])
        ed = str(o.get("edition_id") or "").lower()
        home_ed = ed.startswith("core") or "home" in ed            # Home = EditionID Core / CoreN / CoreSingleLanguage
        open_t = "device_encryption" if home_ed else "bitlocker"
        if osv is None or osv["state"] in ("unknown", "unencryptable"):
            add(check("bitlocker_os", "device", f"{label} on the system drive", "unknown", value="Unknown",
                      detail=(bl.get("error") or "")[:200] or "Not reported"))
        elif osv["state"] == "on":
            add(check("bitlocker_os", "device", f"{label} on the system drive", "pass", value="On",
                      evidence={"volume": osv}))
        elif osv["state"] == "encrypting":
            add(check("bitlocker_os", "device", f"{label} on the system drive", "pass",
                      value=f"Encrypting ({osv.get('percent') or 0}%)", evidence={"volume": osv}))
        elif osv["state"] == "suspended":
            add(check("bitlocker_os", "device", f"{label} on the system drive", "fail", "high", value="Suspended",
                      evidence={"volume": osv},
                      why="The drive is encrypted but the key is stored in the clear - like leaving the key in "
                          "the lock. Windows suspends it during some updates and usually resumes it.",
                      fix=fix("Resume protection", [{"op": "bitlocker", "mount": osv["mount"], "resume": True}])
                      if win else None))
        elif osv["state"] == "waiting_activation":
            add(check("bitlocker_os", "device", f"{label} on the system drive", "fail", "medium",
                      value="Waiting for activation", evidence={"volume": osv},
                      why="Encrypted, but no key protector yet - finish turning it on (and back up the key).",
                      manual=manual(steps, open_t)))
        else:
            add(check("bitlocker_os", "device", f"{label} on the system drive", "fail",
                      "high" if portable else "medium", value="Off" if osv["state"] == "off" else osv["state"],
                      evidence={"volume": osv, "portable": portable},
                      why="If the " + ("laptop is lost or stolen" if portable else "PC or its disk is stolen") +
                          ", everything on it can be read by plugging the disk into another computer.",
                      manual=manual(steps, open_t)))
        data_off = [v["mount"] for v in vols if v["kind"] == "data" and v["state"] == "off"]
        if win and [v for v in vols if v["kind"] == "data"]:
            if data_off:
                add(check("bitlocker_data", "device", "BitLocker on other internal drives", "fail", "low",
                          value="Off: " + ", ".join(data_off), manual=manual(steps, open_t)))
            else:
                add(check("bitlocker_data", "device", "BitLocker on other internal drives", "pass", value="On"))

    # ------------------------------------------------------------ updates & support
    if win and o.get("build"):
        sup = windows_support(o, now.date())
        if sup and sup.get("end"):
            left = sup["days_left"]
            ev = {"version": sup["version"], "end_of_updates": sup["end"], "edition": o.get("edition_id")}
            if left < 0:
                w10 = sup.get("product") == "Windows 10"
                add(check("os_supported", "updates", "Windows version still supported", "fail",
                          "high", value=f"{sup['version']} - ended {sup['end']}", evidence=ev,
                          why="This version gets no more security fixes; every new Windows hole stays open.",
                          detail=("Windows 10 support ended on 2025-10-14 (unless this PC is enrolled in Extended "
                                  "Security Updates)." if w10 else
                                  f"Install the newer Windows 11 version offered in Windows Update - it is free."),
                          manual=manual(["Open Windows Update and install the offered feature update"
                                         + (" (or upgrade to Windows 11 / enrol in ESU)." if w10 else "."),
                                         ], "windows_update")))
            elif left <= 60:
                add(check("os_supported", "updates", "Windows version still supported", "fail", "low",
                          value=f"{sup['version']} - ends in {left} days", evidence=ev,
                          detail=f"Security updates stop on {sup['end']}.",
                          manual=manual(["Install the next Windows version from Windows Update."], "windows_update")))
            else:
                add(check("os_supported", "updates", "Windows version still supported", "pass",
                          value=f"{sup['version']} - until {sup['end']}", evidence=ev))
        elif sup and sup.get("newer"):
            add(check("os_supported", "updates", "Windows version still supported", "pass",
                      value=f"{sup['version']} (newer than Cyber Hub's list)"))
    up = facts.get("update")
    if up is not None:
        lim = int(ctx.get("update_max_age", 35))
        age = _age_days(up.get("last_install"), now)
        if win and up.get("policy_no_auto"):
            add(check("updates_policy", "updates", "Automatic updates", "fail", "high", value="Turned off by policy",
                      managed=True, why="Security updates are not installed automatically.",
                      detail="Set by Group Policy / your organisation (NoAutoUpdate)."))
        elif win and up.get("service") == "disabled":
            add(check("updates_service", "updates", "Windows Update service", "fail", "high", value="Disabled",
                      why="With the service disabled Windows can neither find nor install security updates "
                          "(some 'debloat' tools do this).",
                      fix=fix("Re-enable Windows Update",
                              [{"op": "service_start", "service": "wuauserv", "start": "Manual"}])))
        elif win and up.get("service"):
            add(check("updates_service", "updates", "Windows Update service", "pass",
                      value=str(up["service"]).capitalize()))
        paused = _parse(up.get("paused_until"))
        if paused and paused > now:
            add(check("updates_paused", "updates", "Updates paused", "fail", "medium",
                      value=f"until {paused.date().isoformat()}",
                      why="No security fixes are installed while updates are paused.",
                      fix=fix("Resume updates", [{"op": "reg_delete", "target": t} for t in WU_PAUSE_TARGETS])))
        elif win:
            add(check("updates_paused", "updates", "Updates paused", "pass", value="No"))
        if age is None:
            add(check("updates_recent", "updates", "Recent updates installed", "unknown", value="Unknown",
                      detail="Windows did not report when updates were last installed."))
        elif age > lim:
            add(check("updates_recent", "updates", "Recent updates installed", "fail",
                      "high" if age > 60 else "medium", value=f"{age} days ago",
                      evidence={"last_install": up.get("last_install")},
                      why="Microsoft releases security fixes every month (Patch Tuesday); attackers start "
                          "exploiting them within days.",
                      manual=manual(["Open Windows Update and choose 'Check for updates' / 'Install all'.",
                                     "Or use 'Search for missing updates' here to see what is missing."],
                                    "windows_update") if win else
                      manual(["Run your distribution's updater (e.g. 'sudo apt update && sudo apt upgrade')."])))
        else:
            add(check("updates_recent", "updates", "Recent updates installed", "pass",
                      value="Today" if age == 0 else f"{age} day(s) ago",
                      evidence={"last_install": up.get("last_install")}))
        if up.get("pending_reboot"):
            add(check("updates_reboot", "updates", "Restart to finish updates", "fail", "low", value="Pending",
                      why="Installed fixes only protect you after the restart.",
                      manual=manual(["Save your work and restart the PC."], "windows_update" if win else None)))
        else:
            add(check("updates_reboot", "updates", "Restart to finish updates", "pass", value="Not needed"))
        if not win and up.get("auto_updates") is not None:
            add(check("auto_updates", "updates", "Automatic security updates", "pass" if up["auto_updates"]
                      else "fail", "medium", value="On" if up["auto_updates"] else "Off",
                      manual=None if up["auto_updates"] else manual(
                          ["Debian / Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure "
                           "unattended-upgrades", "Fedora: sudo dnf install dnf-automatic && sudo systemctl "
                                                  "enable --now dnf-automatic.timer"])))

    # ------------------------------------------------------------ Linux extras
    ssh = facts.get("ssh")
    if ssh is not None and ssh.get("running"):
        pr = ssh.get("permit_root")
        add(check("ssh_root", "network", "SSH root login", "fail" if pr == "yes" else "pass", "high",
                  value=pr, why="Root login with a password lets attackers guess the one account that owns "
                                "everything.",
                  manual=None if pr != "yes" else manual(["Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
                                                          "Run: sudo systemctl restart ssh"])))
        pa = ssh.get("password_auth")
        add(check("ssh_passwords", "network", "SSH password login", "fail" if pa == "yes" else "pass", "low",
                  value=pa, why="Internet-facing SSH with passwords gets guessed around the clock - keys are safer.",
                  manual=None if pa != "yes" else manual(["Set up an SSH key, then 'PasswordAuthentication no'."])))
    if not win and (facts.get("accounts") or {}).get("guest_session") is not None:
        g = facts["accounts"]["guest_session"]
        add(check("guest_account", "account", "Guest session", "fail" if g else "pass", "medium",
                  value="Allowed" if g else "Off",
                  manual=None if not g else manual(["Set 'allow-guest=false' in /etc/lightdm/lightdm.conf."])))
    return out


def score_of(checks: list[dict]) -> tuple[int, str]:
    """100 * 100 / (100 + penalty): every issue costs points but a neglected PC never sits flat at 0 (so the
    trend graph still shows progress). Any critical issue caps the score at 49 (At risk), any high at 84."""
    active = [c for c in checks if c["status"] == "fail" and not c.get("ignored")]
    penalty = sum(SEVERITY_WEIGHT[c["severity"]] for c in active)
    s = round(100 * 100 / (100 + penalty))
    if any(c["severity"] == "critical" for c in active):
        s = min(s, 49)
    elif any(c["severity"] == "high" for c in active):
        s = min(s, 84)
    grade = "Protected" if s >= 90 else "Good" if s >= 70 else "Needs attention" if s >= 50 else "At risk"
    return s, grade


# ====================================================================== service
class PostureService:
    FACTS_TTL = 60.0

    def __init__(self, db: Database, settings, activity, firewall=None, data_dir: Path | None = None,
                 backend: PostureBackend | None = None):
        self.db, self.settings, self.activity, self.firewall = db, settings, activity, firewall
        self.backend = backend or pick_backend()
        self.data_dir = Path(data_dir or ".")
        self._lock = threading.RLock()
        self._fix_lock = threading.Lock()
        self._facts: tuple[float, dict | None] = (0.0, None)
        self._search: dict[str, Any] = {"state": "idle"}
        self._search_thread: threading.Thread | None = None
        self._stopping = False
        root = Path(__file__).resolve().parent.parent.parent
        self.own_dirs = tuple(sorted({str(p).rstrip("\\/").replace("/", "\\").lower()
                                      for p in (self.data_dir, root)}))

    # ------------------------------------------------------------------ plumbing
    def _call(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except BackendError as e:
            raise PostureError(e.status, e.message)

    def available(self) -> bool:
        return self.backend.available()[0]

    def _require_available(self) -> None:
        ok, why = self.backend.available()
        if not ok:
            raise PostureError(501, why or "Not supported on this computer")

    def invalidate(self) -> None:
        self._facts = (0.0, None)

    def collect(self, refresh: bool = False) -> dict:
        self._require_available()
        with self._lock:
            ts, data = self._facts
            if refresh or data is None or time.monotonic() - ts > self.FACTS_TTL:
                data = self._call(self.backend.collect)
                self._facts = (time.monotonic(), data)
            return data

    def _state_get(self, key: str, default: Any = None) -> Any:
        row = self.db.fetchone("SELECT value FROM posture_state WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def _state_set(self, key: str, value: Any) -> None:
        self.db.execute("INSERT INTO posture_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))

    def _event(self, kind: str, severity: str, title: str, detail: str | None = None, check_id: str | None = None,
               username: str | None = None, data: Any = None, activity: bool = True) -> dict:
        cur = self.db.execute(
            "INSERT INTO posture_events(kind, severity, title, detail, check_id, username, data, acknowledged) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (kind, severity, title, detail, check_id, username, json.dumps(data) if data is not None else None,
             0 if SEVERITIES.index(severity) >= 2 else 1))
        if activity:
            who = f" (by {username})" if username else ""
            self.activity.record("posture", title, ((detail or "") + who) or None, severity=severity,
                                 source="posture")
        return self.db.fetchone("SELECT * FROM posture_events WHERE id=?", (cur.lastrowid,))

    # ------------------------------------------------------------------ context from other parts
    def _firewall_ctx(self, facts: dict) -> dict:
        """Read-only view of Part 9: firewall state + would RDP / SMB get through. Never changes anything."""
        ctx: dict[str, Any] = {"firewall": None, "rdp_verdict": None}
        fw = self.firewall
        if fw is None:
            return ctx
        try:
            st = fw.status()
            ctx["firewall"] = {"state": st.get("state"), "error": st.get("error"), "score": st.get("score"),
                               "profiles": [{"name": p["name"], "enabled": p["enabled"]} for p in
                                            st.get("profiles") or []]}
            rdp = facts.get("rdp") or {}
            if rdp.get("enabled") and st.get("state") != "unavailable" and not st.get("error"):
                ctx["rdp_verdict"] = fw.inbound_verdict(int(rdp.get("port") or 3389), "tcp", None)
        except Exception as e:                                       # Part 9 trouble must never break Part 11
            log.debug("Firewall context unavailable: %s", e)
            ctx["firewall"] = {"state": "unavailable", "error": str(getattr(e, "message", e))[:200]}
        return ctx

    def _ctx(self, facts: dict) -> dict:
        s = self.settings
        return {"now": _now(), "signature_max_age": s.get("posture_signature_max_age_days"),
                "update_max_age": s.get("posture_update_max_age_days"),
                "scan_max_age": s.get("posture_scan_max_age_days"), "own_dirs": self.own_dirs,
                **self._firewall_ctx(facts)}

    def _ignored(self) -> dict[str, dict]:
        now = _iso()
        rows = self.db.fetchall("SELECT * FROM posture_ignored")
        out = {}
        for r in rows:
            if r["until"] and r["until"] < now:
                self.db.execute("DELETE FROM posture_ignored WHERE check_id=?", (r["check_id"],))
                continue
            out[r["check_id"]] = {"reason": r["reason"], "by": r["username"], "at": r["created_at"],
                                  "until": r["until"]}
        return out

    # ------------------------------------------------------------------ analyze
    def analyze(self, refresh: bool = False) -> dict:
        facts = self.collect(refresh)
        checks = evaluate(facts, self._ctx(facts))
        ign = self._ignored()
        for c in checks:
            if c["id"] in ign and c["status"] == "fail":
                c["ignored"] = ign[c["id"]]
            if c["fix"]:
                f = c["fix"]
                f["blocked"] = (NEEDS_ADMIN if f["needs_elevation"] and not self.backend.can_modify()
                                and not all(o["op"] == "firewall_on" for o in f["ops"]) else None)
        order = {k: i for i, (k, _) in enumerate(CATEGORIES)}
        checks.sort(key=lambda c: (c["status"] != "fail" or bool(c["ignored"]), -SEVERITIES.index(c["severity"]),
                                   order[c["category"]], c["title"]))
        score, grade = score_of(checks)
        cats = []
        for cid, name in CATEGORIES:
            cs = [c for c in checks if c["category"] == cid]
            if not cs:
                continue
            s, g = score_of(cs)
            cats.append({"id": cid, "name": name, "score": s, "grade": g, "total": len(cs),
                         "passed": sum(1 for c in cs if c["status"] == "pass"),
                         "failed": sum(1 for c in cs if c["status"] == "fail" and not c["ignored"]),
                         "unknown": sum(1 for c in cs if c["status"] == "unknown"),
                         "ignored": sum(1 for c in cs if c["ignored"]),
                         "worst": next((c["severity"] for c in cs if c["status"] == "fail" and not c["ignored"]),
                                       None)})
        active = [c for c in checks if c["status"] == "fail" and not c["ignored"]]
        counts = {s: sum(1 for c in active if c["severity"] == s) for s in SEVERITIES}
        out = {"score": score, "grade": grade, "categories": cats, "counts": counts,
               "totals": {"checks": len(checks), "passed": sum(1 for c in checks if c["status"] == "pass"),
                          "failed": len(active), "unknown": sum(1 for c in checks if c["status"] == "unknown"),
                          "ignored": sum(1 for c in checks if c["ignored"]),
                          "fixable": sum(1 for c in active if c["fix"] and not c["fix"].get("blocked"))},
               "checks": checks, "checked_at": _iso(), "platform": facts.get("platform"),
               "elevated": facts.get("elevated"), "backend": self.backend.info()}
        self._record_score(out)
        return out

    def _record_score(self, a: dict, force: bool = False) -> None:
        last = self.db.fetchone("SELECT ts, score, failed FROM posture_scores ORDER BY id DESC LIMIT 1")
        if not force and last and last["score"] == a["score"] and last["failed"] == a["totals"]["failed"] and \
                (_now() - (_parse(last["ts"]) or _now())).total_seconds() < 3600:
            return
        self.db.execute("INSERT INTO posture_scores(score, grade, passed, failed, unknown, categories) "
                        "VALUES (?,?,?,?,?,?)",
                        (a["score"], a["grade"], a["totals"]["passed"], a["totals"]["failed"], a["totals"]["unknown"],
                         json.dumps({c["id"]: c["score"] for c in a["categories"]})))

    def get_check(self, check_id: str, refresh: bool = False) -> dict:
        a = self.analyze(refresh)
        c = next((x for x in a["checks"] if x["id"] == check_id), None)
        if not c:
            raise PostureError(404, "No such check on this computer")
        return c

    def status(self) -> dict:
        info = self.backend.info()
        out: dict[str, Any] = {"backend": info, "error": None, "score": None, "grade": None, "categories": [],
                               "counts": {}, "totals": {}, "os": None, "top_issues": [],
                               "unacknowledged_alerts": self.db.fetchone(
                                   "SELECT COUNT(*) AS n FROM posture_events WHERE acknowledged=0")["n"],
                               "last_watch": self._state_get("last_watch"),
                               "pending_reboot": False, "changes_pending_reboot": self.db.fetchone(
                                   "SELECT COUNT(*) AS n FROM posture_changes WHERE status='applied' AND "
                                   "reboot_required=1 AND ts > ?", (_boot_iso(),))["n"]}
        if not info["available"]:
            out["error"] = info["reason"]
            return out
        try:
            a = self.analyze()
            facts = self.collect()
            out.update({k: a[k] for k in ("score", "grade", "categories", "counts", "totals", "checked_at",
                                          "elevated", "platform")})
            out["os"] = facts.get("os")
            out["pending_reboot"] = bool((facts.get("update") or {}).get("pending_reboot"))
            out["top_issues"] = [{k: c[k] for k in ("id", "title", "severity", "value", "category")} | {
                "fixable": bool(c["fix"] and not c["fix"].get("blocked"))}
                for c in a["checks"] if c["status"] == "fail" and not c["ignored"] and c["severity"] != "info"][:5]
        except PostureError as e:
            out["error"] = e.message
        return out

    # ------------------------------------------------------------------ fixes
    def _before(self, op: dict, facts: dict) -> Any:
        k = op["op"]
        if k in ("reg_set", "reg_delete"):
            exists, value = self._call(self.backend.reg_get, op["target"])
            return {"exists": exists, "value": value}
        if k == "mp_pref":
            return ((facts.get("av") or {}).get("prefs") or {}).get(PREF_FACT[op["pref"]])
        if k == "mp_exclusion":
            return True                                   # it was present (we only remove what we saw)
        if k == "user_enabled":
            u = next((x for x in (facts.get("accounts") or {}).get("users") or [] if x["sid"] == op["sid"]), None)
            return None if u is None else u["enabled"]
        if k == "service_start":
            return {"automatic": "Automatic", "manual": "Manual", "disabled": "Disabled"}.get(
                str((facts.get("update") or {}).get("service") or ""), None)
        if k == "exec_policy":
            return (facts.get("hardening") or {}).get("ps_user") or "Undefined"
        if k == "firewall_on":
            return list(op["profiles"])
        return None

    @staticmethod
    def _inverse(op: dict, before: Any) -> dict | None:
        k = op["op"]
        if k in ("reg_set", "reg_delete"):
            if not before or not before.get("exists"):
                return {"op": "reg_delete", "target": op["target"]}
            return {"op": "reg_set", "target": op["target"], "value": before["value"]}
        if k == "mp_pref":
            return None if before is None else {"op": "mp_pref", "pref": op["pref"], "value": before}
        if k == "mp_exclusion":
            return {"op": "mp_exclusion", "kind": op["kind"], "value": op["value"], "remove": not op.get("remove")}
        if k == "user_enabled":
            return None if before is None else {"op": "user_enabled", "sid": op["sid"], "enabled": before}
        if k == "bitlocker":
            return {"op": "bitlocker", "mount": op["mount"], "resume": not op["resume"]}
        if k == "service_start":
            return None if before is None else {"op": "service_start", "service": op["service"], "start": before}
        if k == "exec_policy":
            return {"op": "exec_policy", "policy": before or "Undefined"}
        if k == "firewall_on":
            return {"op": "firewall_off", "profiles": before}
        return None

    def _apply_op(self, op: dict, username: str) -> None:
        if op["op"] == "firewall_on":
            if self.firewall is None:
                raise PostureError(501, "The firewall module is not available")
            from .firewall import FirewallError
            try:
                names = op["profiles"]
                for n in names:                        # Part 9 does the change, its guards + events apply
                    self.firewall.set_profile(n, {"enabled": True}, username)
            except FirewallError as e:
                raise PostureError(e.status, e.message)
            return
        if op["op"] == "firewall_off":
            from .firewall import FirewallError
            try:
                for n in op["profiles"]:
                    self.firewall.set_profile(n, {"enabled": False}, username)
            except FirewallError as e:
                raise PostureError(e.status, e.message)
            return
        self._call(self.backend.apply, op)

    def _guard(self, c: dict, facts: dict, force: bool, is_admin: bool) -> None:
        """Safety checks that stop a fix from locking the user (or a remote colleague) out."""
        if c["id"] == "builtin_admin":
            acc = facts.get("accounts") or {}
            admin = next((u for u in acc.get("users") or [] if u["builtin"] == "admin"), None)
            me = str((facts.get("os") or {}).get("user") or "").lower()
            if admin and admin["name"].lower() == me:
                raise PostureError(409, f"Cyber Hub is running as '{admin['name']}' - sign in with another "
                                        f"administrator account first, then disable this one")
            others = [u for u in acc.get("users") or [] if u["enabled"] and u.get("admin") and
                      u["builtin"] != "admin"]
            if acc.get("admins") is not None and not others:
                raise PostureError(409, "It is the only enabled administrator account - create or enable another "
                                        "administrator first")
        if c["id"] == "remote_desktop":
            rdp = facts.get("rdp") or {}
            session = str((facts.get("os") or {}).get("session") or "")
            if session.upper().startswith("RDP-") and not (force and is_admin):
                raise PostureError(409, "You are connected through Remote Desktop yourself - turning it off would "
                                        "cut this session (send force=true as an administrator to do it anyway)")
            n = self.backend.rdp_sessions(int(rdp.get("port") or 3389))
            if n and not (force and is_admin):
                raise PostureError(409, f"{n} Remote Desktop connection(s) are open right now - turning it off "
                                        f"would cut them (send force=true as an administrator to do it anyway)")

    def fix(self, check_id: str, username: str, is_admin: bool, confirm: bool = False, force: bool = False) -> dict:
        if not self._fix_lock.acquire(blocking=False):
            raise PostureError(409, "Another fix is being applied - try again in a moment")
        try:
            facts = self.collect(refresh=True)
            c = self.get_check(check_id)
            if c["status"] != "fail":
                raise PostureError(409, "This check is already passing")
            f = c["fix"]
            if not f:
                raise PostureError(400, "This one has no automatic fix - follow the steps"
                                   + (" (it is managed by your organisation's policy)" if c["managed"] else ""))
            if f["admin"] and not is_admin:
                raise PostureError(403, "Administrator rights required for this fix")
            if f["confirm"] and not confirm:
                raise PostureError(428, f["confirm"])
            if f.get("blocked"):
                raise PostureError(403, f["blocked"])
            self._guard(c, facts, force, is_admin)
            return self._apply_fix(c, facts, username)
        finally:
            self._fix_lock.release()

    def _apply_fix(self, c: dict, facts: dict, username: str) -> dict:
        f = c["fix"]
        ops = [o if o["op"] == "firewall_on" else check_op(dict(o)) for o in f["ops"]]
        done: list[tuple[dict, Any]] = []
        try:
            for op in ops:
                before = self._before(op, facts)
                self._apply_op(op, username)
                done.append((op, before))
        except PostureError as e:
            rolled = self._rollback(done, username)
            self.invalidate()
            self._change_row(c, done, username, "failed", f["reboot"], e.message)
            self._event("fix_failed", "low", f"Fix failed: {c['title']}", e.message + (
                f" ({rolled} step(s) rolled back)" if rolled else ""), c["id"], username)
            raise PostureError(e.status, e.message + (f" - {rolled} completed step(s) were rolled back"
                                                      if rolled else ""))
        self.invalidate()
        after = self.get_check(c["id"], refresh=True)
        verified = after["status"] == "pass"
        msg = None
        if not verified:
            d = ((facts.get("av") or {}).get("defender") or {})
            if any(o["op"] == "mp_pref" for o in ops) and d.get("tamper"):
                msg = ("Windows Tamper Protection kept the old setting - change it in Windows Security instead")
            elif any(o["op"] == "mp_update" for o in ops):
                msg = "Definitions were requested; Windows may need a minute to finish downloading them"
                verified = None
            elif any(o["op"] == "mp_scan" for o in ops):
                msg = "The quick scan was started in the background (it takes a few minutes)"
                verified = None
            else:
                msg = "Windows did not keep the change (Group Policy or another security tool may control it)"
        status = "applied" if verified is not False else "not_applied"
        if verified is False:
            self._rollback(done, username)            # nothing to keep - leave the PC exactly as it was
            self.invalidate()
        cid = self._change_row(c, done, username, status, f["reboot"] and verified is not False, msg)
        if verified is not False:
            self._event("fix_applied", "info", f"Fixed: {c['title']}", f"{f['label']}" +
                        (" - restart needed" if f["reboot"] else "") + (f". {msg}" if msg else ""),
                        c["id"], username, {"change_id": cid})
        else:
            self._event("fix_not_applied", "low", f"Fix did not stick: {c['title']}", msg, c["id"], username,
                        {"change_id": cid})
        self._store_states(self.analyze())
        return {"check": after if verified is not False else self.get_check(c["id"]), "verified": verified,
                "status": status, "message": msg, "reboot_required": bool(f["reboot"] and verified is not False),
                "change_id": cid, "reversible": f["reversible"]}

    def _rollback(self, done: list[tuple[dict, Any]], username: str) -> int:
        n = 0
        for op, before in reversed(done):
            inv = self._inverse(op, before)
            if inv is None:
                continue
            try:
                self._apply_op(inv, username)
                n += 1
            except PostureError as e:                                  # pragma: no cover - logged, keep going
                log.warning("Rollback of %s failed: %s", op["op"], e.message)
        return n

    def _change_row(self, c: dict, done: list[tuple[dict, Any]], username: str, status: str, reboot: bool,
                    message: str | None) -> int:
        cur = self.db.execute(
            "INSERT INTO posture_changes(check_id, title, label, ops, before, username, status, reboot_required, "
            "message) VALUES (?,?,?,?,?,?,?,?,?)",
            (c["id"], c["title"], c["fix"]["label"], json.dumps([o for o, _ in done]),
             json.dumps([b for _, b in done], default=str), username, status, 1 if reboot else 0, message))
        return cur.lastrowid

    def fix_all(self, username: str, is_admin: bool, categories: list[str] | None = None,
                min_severity: str = "low") -> dict:
        """Apply every safe automatic fix: no confirmation needed, not admin-only (unless you are one),
        nothing that needs an elevated engine when it is not elevated, nothing ignored."""
        a = self.analyze(refresh=True)
        results, skipped = [], []
        for c in a["checks"]:
            if c["status"] != "fail" or c["ignored"] or not c["fix"]:
                continue
            if categories and c["category"] not in categories:
                continue
            if SEVERITIES.index(c["severity"]) < SEVERITIES.index(min_severity):
                continue
            f = c["fix"]
            why = ("needs your confirmation" if f["confirm"] else
                   "administrator only" if f["admin"] and not is_admin else
                   "needs the engine started as administrator" if f.get("blocked") else None)
            if why:
                skipped.append({"id": c["id"], "title": c["title"], "reason": why})
                continue
            try:
                r = self.fix(c["id"], username, is_admin)
                results.append({"id": c["id"], "title": c["title"], "status": r["status"],
                                "message": r["message"], "reboot_required": r["reboot_required"]})
            except PostureError as e:
                results.append({"id": c["id"], "title": c["title"], "status": "failed", "message": e.message,
                                "reboot_required": False})
        final = self.analyze()
        return {"applied": [r for r in results if r["status"] == "applied"],
                "not_applied": [r for r in results if r["status"] != "applied"], "skipped": skipped,
                "score_before": a["score"], "score": final["score"], "grade": final["grade"],
                "reboot_required": any(r["reboot_required"] for r in results)}

    # ------------------------------------------------------------------ change history / undo
    def changes(self, limit: int = 100, offset: int = 0) -> dict:
        total = self.db.fetchone("SELECT COUNT(*) AS n FROM posture_changes")["n"]
        rows = self.db.fetchall("SELECT * FROM posture_changes ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        items = []
        for r in rows:
            ops = json.loads(r["ops"])
            befores = json.loads(r["before"])
            r = dict(r, ops=ops, reboot_required=bool(r["reboot_required"]))
            r.pop("before", None)
            r["reversible"] = r["status"] == "applied" and any(
                self._inverse(o, b) for o, b in zip(ops, befores))
            items.append(r)
        return {"total": total, "items": items}

    def revert(self, change_id: int, username: str) -> dict:
        row = self.db.fetchone("SELECT * FROM posture_changes WHERE id=?", (change_id,))
        if not row:
            raise PostureError(404, "No such change")
        if row["status"] != "applied":
            raise PostureError(409, f"This change is {row['status']} - nothing to undo")
        ops, befores = json.loads(row["ops"]), json.loads(row["before"])
        invs = [self._inverse(o, b) for o, b in zip(ops, befores)]
        if not any(invs):
            raise PostureError(400, "This change cannot be undone (updates and scans are one-way)")
        if not self._fix_lock.acquire(blocking=False):
            raise PostureError(409, "Another fix is being applied - try again in a moment")
        try:
            n = 0
            for inv in reversed(invs):
                if inv:
                    if inv["op"] != "firewall_off":
                        check_op(inv)
                    self._apply_op(inv, username)
                    n += 1
        finally:
            self._fix_lock.release()
            self.invalidate()
        self.db.execute("UPDATE posture_changes SET status='reverted', reverted_at=?, reverted_by=? WHERE id=?",
                        (_iso(), username, change_id))
        self._event("fix_reverted", "medium", f"Undone: {row['title']}", f"{row['label']} reverted ({n} step(s))",
                    row["check_id"], username)
        a = self.analyze(refresh=True)
        self._store_states(a)
        return {"reverted": n, "check": next((c for c in a["checks"] if c["id"] == row["check_id"]), None)}

    # ------------------------------------------------------------------ ignore (accept the risk)
    def ignore(self, check_id: str, username: str, reason: str | None, days: int | None) -> dict:
        c = self.get_check(check_id)
        if c["status"] != "fail":
            raise PostureError(409, "Only failing checks can be ignored")
        until = _iso(_now() + timedelta(days=days)) if days else None
        self.db.execute("INSERT INTO posture_ignored(check_id, reason, username, until) VALUES (?,?,?,?) "
                        "ON CONFLICT(check_id) DO UPDATE SET reason=excluded.reason, username=excluded.username, "
                        "until=excluded.until, created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                        (check_id, reason, username, until))
        self._event("ignored", "low", f"Risk accepted: {c['title']}",
                    (reason or "no reason given") + (f" (for {days} days)" if days else ""), check_id, username)
        return self.get_check(check_id)

    def unignore(self, check_id: str, username: str) -> dict:
        n = self.db.execute("DELETE FROM posture_ignored WHERE check_id=?", (check_id,)).rowcount
        if not n:
            raise PostureError(404, "That check is not ignored")
        self._event("unignored", "info", f"Watching again: {check_id}", None, check_id, username, activity=False)
        return self.get_check(check_id)

    def ignored(self) -> list[dict]:
        return [{"check_id": k, **v} for k, v in self._ignored().items()]

    # ------------------------------------------------------------------ Defender / updates / accounts / open
    def defender(self, refresh: bool = False) -> dict:
        facts = self.collect(refresh)
        av = facts.get("av")
        if av is None:
            raise PostureError(501, "Microsoft Defender is only on Windows")
        prefs = av.get("prefs") or {}
        ex = prefs.get("exclusions") or {}
        excl = None
        if ex.get("readable"):
            excl = [{"kind": k, "value": v, "risk": exclusion_risk(k, v, self.own_dirs)}
                    for k in ("path", "process", "extension") for v in ex.get(k) or []]
        checks = [c for c in self.analyze()["checks"] if c["category"] == "virus"]
        return {"defender": av.get("defender"), "preferences": {k: v for k, v in prefs.items() if k != "exclusions"},
                "exclusions": excl, "exclusions_readable": bool(ex.get("readable")), "products": av.get("products"),
                "error": av.get("error"), "checks": checks}

    def update_signatures(self, username: str) -> dict:
        self._call(self.backend.apply, {"op": "mp_update"})
        self.invalidate()
        self._event("signatures_updated", "info", "Defender definition update requested", None, "defender_signatures",
                    username, activity=True)
        return self.defender(refresh=True)

    def defender_scan(self, scan_type: str, username: str) -> dict:
        self._call(self.backend.apply, {"op": "mp_scan", "type": scan_type})
        self._event("defender_scan", "info", f"Microsoft Defender {scan_type} scan started", None, "defender_scan",
                    username)
        self.invalidate()
        return {"started": True, "type": scan_type}

    def updates(self, refresh: bool = False) -> dict:
        facts = self.collect(refresh)
        up = facts.get("update") or {}
        o = facts.get("os") or {}
        sup = windows_support(o, _now().date()) if facts.get("platform") == "windows" else None
        checks = [c for c in self.analyze()["checks"] if c["category"] == "updates"]
        return {"update": up, "support": sup, "os": o, "checks": checks, "search": self.search_status()}

    def search_status(self) -> dict:
        s = dict(self._search)
        if s.get("state") == "idle":
            last = self._state_get("last_update_search")
            if last:
                s = dict(last, state="done", cached=True)
        return s

    def start_update_search(self, username: str) -> dict:
        self._require_available()
        with self._lock:
            if self._search.get("state") == "running":
                return self.search_status()
            self._search = {"state": "running", "started_at": _iso(), "started_by": username, "updates": None}

        def run():
            try:
                ups = self._call(self.backend.search_updates)
                res = {"state": "done", "started_at": self._search["started_at"], "finished_at": _iso(),
                       "started_by": username, "updates": ups, "count": len(ups),
                       "security": sum(1 for u in ups if u.get("severity")), "error": None}
                prev = self._state_get("last_update_search") or {}
                seen = {u["title"] for u in prev.get("updates") or []}
                self._state_set("last_update_search", res)
                if [u for u in ups if u["title"] not in seen] and not self._stopping:     # only NEW ones alert
                    crit = sum(1 for u in ups if (u.get("severity") or "").lower() == "critical")
                    self._event("updates_missing", "medium" if crit else "low", f"{len(ups)} Windows update(s) "
                                f"waiting", ", ".join(u["title"] for u in ups[:3]), "updates_recent", username)
            except PostureError as e:
                res = {"state": "error", "started_at": self._search.get("started_at"), "finished_at": _iso(),
                       "error": e.message, "updates": None}
            except Exception as e:                                      # pragma: no cover
                res = {"state": "error", "finished_at": _iso(), "error": str(e)[:300], "updates": None}
            self._search = res
        t = threading.Thread(target=run, name="posture-update-search", daemon=True)
        self._search_thread = t
        t.start()
        return self.search_status()

    def accounts(self) -> dict:
        facts = self.collect()
        acc = facts.get("accounts")
        if acc is None:
            raise PostureError(501, "Local accounts could not be read on this computer")
        checks = [c for c in self.analyze()["checks"] if c["category"] == "account"]
        return {"users": acc.get("users") or [], "admins": acc.get("admins"), "current_user":
                (facts.get("os") or {}).get("user"), "checks": checks, "error": acc.get("error")}

    def open_settings(self, target: str) -> dict:
        if target not in OPEN_TARGETS:
            raise PostureError(404, "Unknown settings page")
        self._call(self.backend.open_target, target)
        return {"opened": target}

    # ------------------------------------------------------------------ watch
    def _store_states(self, a: dict) -> None:
        now = _iso()
        with self.db.tx() as cx:
            for c in a["checks"]:
                cx.execute("INSERT INTO posture_check_state(check_id, status, severity, title, value, since, "
                           "last_checked) VALUES (?,?,?,?,?,?,?) ON CONFLICT(check_id) DO UPDATE SET "
                           "since=CASE WHEN posture_check_state.status=excluded.status THEN posture_check_state.since "
                           "ELSE excluded.since END, status=excluded.status, severity=excluded.severity, "
                           "title=excluded.title, value=excluded.value, last_checked=excluded.last_checked",
                           (c["id"], c["status"], c["severity"], c["title"], c["value"], now, now))

    def _exclusion_set(self, facts: dict) -> list[str] | None:
        ex = (((facts.get("av") or {}).get("prefs") or {}).get("exclusions") or {})
        if not ex.get("readable"):
            return None
        return sorted(f"{k}:{v}" for k in ("path", "process", "extension") for v in ex.get(k) or [])

    def watch_once(self) -> dict:
        self._require_available()
        with self._lock:
            a = self.analyze(refresh=True)
            facts = self.collect()
            out = {"regressions": 0, "resolved": 0, "exclusions_added": 0, "baseline": False, "score": a["score"]}
            prev = {r["check_id"]: r for r in self.db.fetchall("SELECT * FROM posture_check_state")}
            alert = bool(self.settings.get("posture_alert_regressions"))
            if not self._state_get("baseline_at"):
                self._store_states(a)
                self._state_set("baseline_at", _iso())
                ex = self._exclusion_set(facts)
                if ex is not None:
                    self._state_set("exclusions", ex)
                self._event("baseline", "info", f"Security posture baseline: {a['score']}/100 ({a['grade']})",
                            f"{a['totals']['failed']} issue(s), {a['totals']['passed']} checks passing", activity=False)
                out["baseline"] = True
            else:
                for c in a["checks"]:
                    p = prev.get(c["id"])
                    if not p or p["status"] == c["status"]:
                        continue
                    if p["status"] == "pass" and c["status"] == "fail" and not c["ignored"]:
                        out["regressions"] += 1
                        if alert:
                            self._event("regression", _sev_max(c["severity"], "low"),
                                        f"Security setting got weaker: {c['title']}",
                                        f"Now: {c['value'] or 'failing'} (was passing). " + (c["why"] or ""),
                                        c["id"], data={"value": c["value"], "previous": p["value"]})
                    elif p["status"] == "fail" and c["status"] == "pass":
                        out["resolved"] += 1
                        self._event("resolved", "info", f"Now OK: {c['title']}", c["value"], c["id"],
                                    activity=False)
                self._store_states(a)
                ex = self._exclusion_set(facts)
                if ex is not None:
                    old = self._state_get("exclusions")
                    if old is not None:
                        added = [e for e in ex if e not in old]
                        removed = [e for e in old if e not in ex]
                        out["exclusions_added"] = len(added)
                        for e in added[:20]:
                            kind, val = e.split(":", 1)
                            risk = exclusion_risk(kind, val, self.own_dirs)
                            self._event("exclusion_added", "high",
                                        f"Microsoft Defender exclusion added: {val}",
                                        f"A new {kind} exclusion means Defender stops scanning it. Malware adds "
                                        f"exclusions for itself - remove it if you did not add it." +
                                        (f" Risk: {risk}." if risk else ""), "defender_exclusions",
                                        data={"kind": kind, "value": val, "risk": risk})
                        if len(added) > 20:
                            self._event("exclusion_added", "high", f"{len(added) - 20} more Defender exclusions "
                                        f"added", None, "defender_exclusions")
                        if removed:
                            self._event("exclusion_removed", "info", f"{len(removed)} Defender exclusion(s) removed",
                                        ", ".join(e.split(":", 1)[1] for e in removed[:5]), "defender_exclusions",
                                        activity=False)
                    self._state_set("exclusions", ex)
            self._record_score(a, force=True)
            self._state_set("last_watch", _iso())
            keep = int(self.settings.get("posture_score_retention_days"))
            self.db.execute("DELETE FROM posture_scores WHERE ts < ?", (_iso(_now() - timedelta(days=keep)),))
            return out

    def rebaseline(self) -> dict:
        self.db.execute("DELETE FROM posture_state WHERE key IN ('baseline_at','exclusions')")
        return self.watch_once()

    # ------------------------------------------------------------------ events & graphs
    def events(self, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100, offset: int = 0) -> dict:
        where, params = ["id > ?"], [after_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if kind:
            where.append("kind=?"); params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        clause = "WHERE " + " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM posture_events {clause}", tuple(params))["n"]
        items = self.db.fetchall(f"SELECT * FROM posture_events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                 tuple(params) + (limit, offset))
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM posture_events")["m"]
        unack = self.db.fetchone("SELECT COUNT(*) AS n FROM posture_events WHERE acknowledged=0")["n"]
        return {"total": total, "last_id": last, "unacknowledged": unack,
                "items": [dict(i, acknowledged=bool(i["acknowledged"]),
                               data=json.loads(i["data"]) if i["data"] else None) for i in items]}

    def acknowledge(self, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE posture_events SET acknowledged=1 WHERE id IN ({q})", tuple(ids)).rowcount
        return self.db.execute("UPDATE posture_events SET acknowledged=1 WHERE acknowledged=0").rowcount

    def clear_events(self) -> int:
        return self.db.execute("DELETE FROM posture_events").rowcount

    def summary(self, days: int = 30) -> dict:
        now = _now()
        since = _iso(now - timedelta(days=days))
        day_list = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
        per_day = {d: {"day": d, "score": None, "failed": None, **{s: 0 for s in SEVERITIES}} for d in day_list}
        for r in self.db.fetchall("SELECT substr(ts,1,10) AS day, score, failed FROM posture_scores WHERE ts >= ? "
                                  "ORDER BY id", (since,)):
            if r["day"] in per_day:                                    # the day's last score wins
                per_day[r["day"]]["score"], per_day[r["day"]]["failed"] = r["score"], r["failed"]
        for r in self.db.fetchall("SELECT substr(ts,1,10) AS day, severity, COUNT(*) AS n FROM posture_events WHERE "
                                  "ts >= ? GROUP BY day, severity", (since,)):
            if r["day"] in per_day:
                per_day[r["day"]][r["severity"]] += r["n"]
        by_kind = {r["kind"]: r["n"] for r in self.db.fetchall(
            "SELECT kind, COUNT(*) AS n FROM posture_events WHERE ts >= ? GROUP BY kind ORDER BY n DESC", (since,))}
        fixes = {r["status"]: r["n"] for r in self.db.fetchall(
            "SELECT status, COUNT(*) AS n FROM posture_changes WHERE ts >= ? GROUP BY status", (since,))}
        out: dict[str, Any] = {"days": days, "per_day": list(per_day.values()), "events_by_kind": by_kind,
                               "fixes": fixes, "score": None, "grade": None, "categories": [], "error": None}
        if self.available():
            try:
                a = self.analyze()
                out.update(score=a["score"], grade=a["grade"], categories=a["categories"], counts=a["counts"],
                           totals=a["totals"])
            except PostureError as e:
                out["error"] = e.message
        return out

    def shutdown(self) -> None:
        self._stopping = True
        t = self._search_thread
        if t and t.is_alive():
            t.join(timeout=0.5)                     # the COM search cannot be cancelled; it is a daemon thread


async def posture_loop(svc: PostureService, settings, tick: float = 60, first_delay: float = 45) -> None:
    """Every N minutes (default 30): re-read the posture, alert on settings that got weaker and on new
    Defender exclusions. The first run only records a baseline."""
    if not svc.available():
        log.info("Posture watch not started: %s", svc.backend.available()[1])
        return
    log.info("Security posture watch started (%s)", svc.backend.label)
    await asyncio.sleep(first_delay)
    last: float | None = None
    while True:
        try:
            interval = int(settings.get("posture_watch_interval_minutes")) * 60
            if settings.get("posture_watch_enabled") and (last is None or time.monotonic() - last >= interval):
                last = time.monotonic()
                await asyncio.to_thread(svc.watch_once)
        except Exception as e:                                   # never let the loop die
            log.warning("Posture watch failed: %s", getattr(e, "message", e))
        await asyncio.sleep(tick)
