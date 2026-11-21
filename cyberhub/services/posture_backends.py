"""
Cyber Hub Backend - Windows Security Posture probes (Part 11)
Developed by Syed Muhammad Tayyab

One small interface over "how is this computer configured", so the service
layer (posture.py) never cares which machine it is talking to:

  * WindowsPosture - ONE fixed PowerShell script reads everything (Microsoft
    Defender status + preferences + exclusions, other antivirus products from
    Security Center, UAC, BitLocker, Secure Boot, TPM, SmartScreen, Windows
    Update history / pause / policy / service, Remote Desktop, local accounts,
    SMBv1, WDigest, LLMNR, LSA protection, Memory integrity, AutoPlay, file
    extensions, PowerShell execution policy, screen lock). Every section has
    its own try / catch, so one missing feature (e.g. no BitLocker on Home)
    never hides the rest. Works without administrator rights - the few things
    Windows only shows to admins (Defender exclusions, Get-Tpm, Get-BitLocker
    Volume) fall back to user-readable sources or are reported as "unknown".
    Changes go through small fixed scripts; every value arrives through
    $env:CH_* and registry locations come only from REG_TARGETS (an allow-list
    in this file) - a caller can never name an arbitrary registry path.
  * LinuxPosture   - read-only: Secure Boot (efivars), TPM (sysfs), root disk
    encryption (lsblk), pending reboot, automatic updates, SSH root / password
    login, guest session. Linux fixes are shown as manual steps.
  * MemoryPosture  - an in-memory Windows PC used by the tests and by the UI
    developer (CYBERHUB_POSTURE_BACKEND=memory). It keeps the SAME raw shape
    the PowerShell script prints, so the Windows parser is what reads it, and
    it behaves like Windows where it matters (Tamper Protection silently
    ignores Defender changes, HKLM needs an elevated engine, ...).
  * NoPosture      - nothing supported here; status says why.
"""
from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from ..logger import get_logger
from .platform_tools import IS_LINUX, IS_WINDOWS, run_cmd, run_powershell_json

log = get_logger("posture")

NEEDS_ADMIN = ("Windows only lets an administrator change this - start Cyber Hub with "
               "start_cyberhub_admin.bat (Run as administrator) and try again")


class BackendError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ====================================================================== allow-lists
HKLM_SYS = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
WU_UX = r"HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

# key -> registry location + where the value lives in the raw probe output (section, field).
# The ONLY registry values Cyber Hub can ever write.
REG_TARGETS: dict[str, dict] = {
    "uac_enable_lua":       {"path": HKLM_SYS, "name": "EnableLUA", "type": "DWord", "raw": ("uac", "enable_lua")},
    "uac_consent_admin":    {"path": HKLM_SYS, "name": "ConsentPromptBehaviorAdmin", "type": "DWord",
                             "raw": ("uac", "consent_admin")},
    "uac_secure_desktop":   {"path": HKLM_SYS, "name": "PromptOnSecureDesktop", "type": "DWord",
                             "raw": ("uac", "secure_desktop")},
    "wdigest":              {"path": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                             "name": "UseLogonCredential", "type": "DWord", "raw": ("hardening", "wdigest")},
    "llmnr":                {"path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                             "name": "EnableMulticast", "type": "DWord", "raw": ("hardening", "llmnr")},
    "smb1_server":          {"path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                             "name": "SMB1", "type": "DWord", "raw": ("hardening", "smb1")},
    "smartscreen_explorer": {"path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                             "name": "SmartScreenEnabled", "type": "String", "raw": ("smartscreen", "explorer")},
    "store_web_eval":       {"path": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost",
                             "name": "EnableWebContentEvaluation", "type": "DWord", "raw": ("smartscreen", "store")},
    "hide_ext":             {"path": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                             "name": "HideFileExt", "type": "DWord", "raw": ("hardening", "hide_ext")},
    "autoplay_off":         {"path": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                             "name": "DisableAutoplay", "type": "DWord", "raw": ("hardening", "autoplay_off")},
    "ss_active":            {"path": r"HKCU:\Control Panel\Desktop", "name": "ScreenSaveActive", "type": "String",
                             "raw": ("hardening", "ss_active")},
    "ss_secure":            {"path": r"HKCU:\Control Panel\Desktop", "name": "ScreenSaverIsSecure",
                             "type": "String", "raw": ("hardening", "ss_secure")},
    "ss_timeout":           {"path": r"HKCU:\Control Panel\Desktop", "name": "ScreenSaveTimeOut", "type": "String",
                             "raw": ("hardening", "ss_timeout")},
    "rdp_deny":             {"path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
                             "name": "fDenyTSConnections", "type": "DWord", "raw": ("rdp", "deny")},
    "rdp_nla":              {"path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                             "name": "UserAuthentication", "type": "DWord", "raw": ("rdp", "nla")},
    "remote_assistance":    {"path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance",
                             "name": "fAllowToGetHelp", "type": "DWord", "raw": ("rdp", "assistance")},
    "wu_pause_expiry":      {"path": WU_UX, "name": "PauseUpdatesExpiryTime", "type": "String",
                             "raw": ("update", "pause_expiry")},
    "wu_pause_start":       {"path": WU_UX, "name": "PauseUpdatesStartTime", "type": "String",
                             "raw": ("update", "pause_start")},
    "wu_pause_quality_start": {"path": WU_UX, "name": "PauseQualityUpdatesStartTime", "type": "String",
                               "raw": ("update", "pause_quality_start")},
    "wu_pause_quality_end": {"path": WU_UX, "name": "PauseQualityUpdatesEndTime", "type": "String",
                             "raw": ("update", "pause_quality_end")},
    "wu_pause_feature_start": {"path": WU_UX, "name": "PauseFeatureUpdatesStartTime", "type": "String",
                               "raw": ("update", "pause_feature_start")},
    "wu_pause_feature_end": {"path": WU_UX, "name": "PauseFeatureUpdatesEndTime", "type": "String",
                             "raw": ("update", "pause_feature_end")},
}
HKCU_TARGETS = {k for k, v in REG_TARGETS.items() if v["path"].startswith("HKCU:")}
WU_PAUSE_TARGETS = [k for k in REG_TARGETS if k.startswith("wu_pause_")]

# Set-MpPreference parameters Cyber Hub may change -> (kind, raw prefs field)
MP_PREFS: dict[str, tuple[str, str]] = {
    "DisableRealtimeMonitoring": ("bool", "disable_rt"),
    "DisableBehaviorMonitoring": ("bool", "disable_behavior"),
    "DisableIOAVProtection":     ("bool", "disable_ioav"),
    "DisableScriptScanning":     ("bool", "disable_script"),
    "MAPSReporting":             ("int", "maps"),
    "SubmitSamplesConsent":      ("int", "samples"),
    "PUAProtection":             ("int", "pua"),
    "EnableNetworkProtection":   ("int", "net_prot"),
    "EnableControlledFolderAccess": ("int", "cfa"),
}
# Defender keeps ignoring these while Tamper Protection is on (Windows' own rule)
TAMPER_GUARDED = {"DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection",
                  "DisableScriptScanning", "MAPSReporting", "SubmitSamplesConsent"}
EXCLUSION_KINDS = {"path": "ex_path", "process": "ex_proc", "extension": "ex_ext"}
SERVICES = {"wuauserv": ("update", "service")}
SERVICE_STARTS = {"Automatic", "Manual", "Disabled"}
EXEC_POLICIES = {"Restricted", "AllSigned", "RemoteSigned", "Unrestricted", "Bypass", "Undefined"}

# Settings pages / consoles Cyber Hub may open on the user's desktop
OPEN_TARGETS: dict[str, str] = {
    "windows_update":   "ms-settings:windowsupdate",
    "update_history":   "ms-settings:windowsupdate-history",
    "virus_protection": "windowsdefender://threat",
    "defender_settings": "windowsdefender://threatsettings",
    "app_browser":      "windowsdefender://appbrowser",
    "device_security":  "windowsdefender://devicesecurity",
    "core_isolation":   "windowsdefender://coreisolation",
    "account_protection": "windowsdefender://account",
    "firewall":         "windowsdefender://network",
    "remote_desktop":   "ms-settings:remotedesktop",
    "accounts":         "ms-settings:otherusers",
    "sign_in":          "ms-settings:signinoptions",
    "lock_screen":      "ms-settings:lockscreen",
    "bitlocker":        "control:/name Microsoft.BitLockerDriveEncryption",
    "device_encryption": "ms-settings:deviceencryption",
    "tpm":              "file:tpm.msc",
    "uac":              "file:UserAccountControlSettings.exe",
    "recovery":         "ms-settings:recovery",
}


def _get(raw: dict, path: tuple[str, str]) -> Any:
    sec = raw.get(path[0])
    return sec.get(path[1]) if isinstance(sec, dict) else None


def _set(raw: dict, path: tuple[str, str], value: Any) -> None:
    sec = raw.get(path[0])
    if not isinstance(sec, dict):
        sec = raw[path[0]] = {}
    sec[path[1]] = value


# ====================================================================== value helpers
def _int(v: Any) -> int | None:
    if v is None or isinstance(v, bool):
        return int(v) if isinstance(v, bool) else None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return None


def _iso(v: Any) -> str | None:
    """'2026-10-02T08:15:00Z' / '2026-10-02T08:15:00.000+05:00' / '/Date(1700000000000)/' -> UTC ISO."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    m = re.match(r"^/Date\((-?\d+)\)/$", s)
    try:
        if m:
            d = datetime.fromtimestamp(int(m.group(1)) / 1000, timezone.utc)
        else:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
        if d.year < 1990:
            return None
        return d.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def av_state(state: Any) -> tuple[bool | None, bool | None]:
    """Security Center productState -> (enabled, up_to_date). 0x1000 = on, 0x10 = signatures out of date."""
    n = _int(state)
    if n is None:
        return None, None
    return bool(n & 0x1000), not bool(n & 0x10)


BL_SHELL = {0: "unencryptable", 1: "on", 2: "off", 3: "encrypting", 4: "decrypting", 5: "suspended",
            6: "on", 7: "unknown", 8: "waiting_activation"}
PORTABLE_CHASSIS = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}


def bitlocker_state(v: dict) -> str:
    """Get-BitLockerVolume row (or the Shell fallback) -> on | off | suspended | encrypting | decrypting |
    waiting_activation | unknown."""
    if v.get("shell") is not None:
        return BL_SHELL.get(_int(v.get("shell")), "unknown")
    prot = str(v.get("protection") or "").lower()
    st = str(v.get("status") or "").lower()
    protectors = [p for p in _list(v.get("protectors")) if p]
    if "decryption" in st:
        return "decrypting"
    if st == "fullydecrypted":
        return "off"
    if prot == "on":
        return "encrypting" if "encryption" in st and "inprogress" in st.replace(" ", "") else "on"
    if st in ("fullyencrypted", "encryptioninprogress", "encryptionpaused"):
        return "suspended" if protectors else "waiting_activation"
    return "unknown"


def _vol_kind(t: Any) -> str:
    s = str(t or "").lower()
    return "os" if s.startswith("operatingsystem") or s == "os" else ("removable" if "remov" in s else "data")


# ====================================================================== normalise (Windows raw -> facts)
_DEFINITION_UPDATE = re.compile(r"security intelligence update|definition update|antimalware platform|KB2267602|"
                                r"KB4052623|KB2461484|KB915597|malicious software removal", re.I)


def normalize_windows(raw: dict, elevated: bool) -> dict:
    """The PowerShell probe's JSON (or MemoryPosture's copy of it) -> the platform-neutral facts dict that
    posture.evaluate() reads. Missing / unreadable sections become None (the check is then 'unknown')."""
    errors = raw.get("errors") or {}
    o = raw.get("os") or {}
    chassis = {_int(x) for x in _list(o.get("chassis"))} - {None}
    fw = str(o.get("firmware") or "").lower()
    facts: dict[str, Any] = {
        "platform": "windows", "elevated": bool(elevated), "errors": dict(errors),
        "os": {"name": o.get("caption") or "Windows", "build": _int(o.get("build")), "ubr": _int(o.get("ubr")),
               "display_version": (o.get("display_version") or o.get("release_id") or None),
               "edition_id": o.get("edition_id") or None, "product_type": _int(o.get("product_type")) or 1,
               "computer": o.get("computer"), "user": o.get("user"), "session": o.get("session") or None,
               "portable": bool(chassis & PORTABLE_CHASSIS) if chassis else None,
               "firmware": "uefi" if fw == "uefi" else ("bios" if fw in ("legacy", "bios") else None)},
    }
    # ---- antivirus
    d = raw.get("defender")
    products = None
    if isinstance(raw.get("av_products"), list):
        products = []
        for p in raw["av_products"]:
            en, fresh = av_state(p.get("state"))
            name = str(p.get("name") or "?")
            products.append({"name": name, "enabled": en, "up_to_date": fresh,
                             "is_defender": "defender" in name.lower() or "windows security" in name.lower()})
    defender = None
    if isinstance(d, dict):
        mode = str(d.get("mode") or "").lower()
        defender = {
            "service": _bool(d.get("am_service")), "antivirus": _bool(d.get("antivirus")),
            "realtime": _bool(d.get("realtime")), "behavior": _bool(d.get("behavior")),
            "ioav": _bool(d.get("ioav")), "on_access": _bool(d.get("on_access")),
            "tamper": _bool(d.get("tamper")), "signature_age_days": _int(d.get("sig_age")),
            "signature_version": d.get("sig_version") or None, "signature_updated": _iso(d.get("sig_updated")),
            "engine_version": d.get("engine") or None, "product_version": d.get("product") or None,
            "quick_scan_age_days": _int(d.get("quick_age")), "full_scan_age_days": _int(d.get("full_age")),
            "mode": mode or None, "passive": "passive" in mode or "edr" in mode,
        }
        for k in ("quick_scan_age_days", "full_scan_age_days", "signature_age_days"):
            if defender[k] is not None and defender[k] >= 65535:          # "never" (UInt32 max / 65535)
                defender[k] = None
    prefs = None
    p = raw.get("prefs")
    if isinstance(p, dict):
        def excl(key: str) -> tuple[list[str] | None, bool]:
            items = [str(x) for x in _list(p.get(key)) if x not in (None, "")]
            if any(i.lower().startswith("n/a") for i in items):
                return None, False                     # "N/A: Must be an administrator to view exclusions"
            return items, True
        paths, ok1 = excl("ex_path")
        procs, ok2 = excl("ex_proc")
        exts, ok3 = excl("ex_ext")
        prefs = {"maps": _int(p.get("maps")), "samples": _int(p.get("samples")), "pua": _int(p.get("pua")),
                 "network_protection": _int(p.get("net_prot")), "cfa": _int(p.get("cfa")),
                 "disable_realtime": _bool(p.get("disable_rt")),
                 "disable_behavior": _bool(p.get("disable_behavior")),
                 "disable_ioav": _bool(p.get("disable_ioav")), "disable_script": _bool(p.get("disable_script")),
                 "exclusions": {"readable": ok1 and ok2 and ok3, "path": paths, "process": procs,
                                "extension": exts}}
    facts["av"] = {"defender": defender, "prefs": prefs, "products": products,
                   "error": errors.get("defender") or errors.get("prefs")}
    # ---- UAC
    u = raw.get("uac") or {}
    facts["uac"] = {"enable_lua": _int(u.get("enable_lua")), "consent_admin": _int(u.get("consent_admin")),
                    "secure_desktop": _int(u.get("secure_desktop"))}
    # ---- BitLocker
    b = raw.get("bitlocker")
    if isinstance(b, dict):
        vols = []
        for v in _list(b.get("volumes")):
            if not isinstance(v, dict):
                continue
            mount = str(v.get("mount") or "").rstrip("\\")
            vols.append({"mount": mount, "kind": _vol_kind(v.get("type")), "state": bitlocker_state(v),
                         "percent": _int(v.get("percent")), "method": v.get("method") or None,
                         "protectors": [str(x) for x in _list(v.get("protectors")) if x]})
        source = b.get("source") or "cmdlet"
        known = [v for v in vols if v["state"] not in ("unknown", "unencryptable")]
        facts["bitlocker"] = {"source": source, "volumes": vols,
                              "available": bool(known) or source == "cmdlet",
                              "error": errors.get("bitlocker")}
    else:
        facts["bitlocker"] = None
    # ---- Secure Boot
    sb = raw.get("secure_boot") or {}
    confirm = str(sb.get("confirm") or "").lower()
    cerr = str(sb.get("confirm_error") or "").lower()
    enabled = _bool(sb.get("enabled"))
    if confirm in ("true", "false"):
        enabled = confirm == "true"
    uefi = None
    if facts["os"]["firmware"]:
        uefi = facts["os"]["firmware"] == "uefi"
    if "not supported on this platform" in cerr:
        uefi = False
    elif sb.get("state_key") or confirm in ("true", "false"):
        uefi = True if uefi is None else uefi
    facts["secure_boot"] = {"uefi": uefi, "enabled": (False if uefi is False else enabled)}
    # ---- TPM
    t = raw.get("tpm")
    if isinstance(t, dict):
        version = None
        spec = str(t.get("spec") or "")
        names = " ".join(str(x) for x in _list(t.get("devices")))
        for text in (spec.split(",")[0].strip(), names):
            m = re.search(r"(2\.0|1\.2)", text)
            if m:
                version = m.group(1)
                break
        present = _bool(t.get("present"))
        if present is None and t.get("source") == "pnp":
            present = bool(_list(t.get("devices")))
        facts["tpm"] = {"present": present, "version": version, "ready": _bool(t.get("ready")),
                        "enabled": _bool(t.get("enabled")), "activated": _bool(t.get("activated")),
                        "manufacturer": t.get("manufacturer") or None, "source": t.get("source") or "cmdlet"}
    else:
        facts["tpm"] = None
    # ---- SmartScreen
    s = raw.get("smartscreen") or {}
    ex = str(s.get("explorer") or "").strip().lower() or None
    facts["smartscreen"] = {"explorer": ex, "policy": _int(s.get("policy")), "edge": _int(s.get("edge")),
                            "edge_policy": _int(s.get("edge_policy")), "store": _int(s.get("store")),
                            "smart_app_control": _int(s.get("sac"))}
    # ---- Windows Update
    w = raw.get("update") or {}
    hist = []
    for h in _list(w.get("history")):
        if isinstance(h, dict):
            hist.append({"title": h.get("title"), "date": _iso(h.get("date")), "result": _int(h.get("result"))})
    hist.sort(key=lambda h: h["date"] or "", reverse=True)
    # Defender definition updates arrive through Windows Update several times a day - they must not count
    # as "Windows was updated" or a PC missing months of security patches would look fine.
    os_hist = [h for h in hist if not _DEFINITION_UPDATE.search(str(h["title"] or ""))]
    ok_dates = [h["date"] for h in os_hist if h["date"] and h["result"] in (2, 3)]   # 2 = succeeded, 3 = w/ errors
    candidates = [x for x in (ok_dates[0] if ok_dates else None, _iso(w.get("hotfix_last"))) if x]
    if not candidates and _iso(w.get("last_install")):
        candidates = [_iso(w.get("last_install"))]               # only when nothing better is known
    pauses = [_iso(w.get(k)) for k in ("pause_expiry", "pause_quality_end", "pause_feature_end")]
    pauses = [x for x in pauses if x]
    svc = str(w.get("service") or "").strip().lower()
    facts["update"] = {
        "last_install": max(candidates) if candidates else None, "last_search": _iso(w.get("last_search")),
        "history": hist[:50], "pending_reboot": bool(w.get("reboot_wu") or w.get("reboot_cbs")),
        "paused_until": max(pauses) if pauses else None,
        "policy_no_auto": _int(w.get("no_auto")) == 1, "au_options": _int(w.get("au_options")),
        "service": {"automatic": "automatic", "auto": "automatic", "manual": "manual",
                    "disabled": "disabled"}.get(svc, svc or None),
        "available": bool(hist or candidates),
    }
    # ---- Remote Desktop
    r = raw.get("rdp") or {}
    deny = _int(r.get("deny"))
    pdeny = _int(r.get("policy_deny"))
    eff_deny = pdeny if pdeny is not None else deny
    facts["rdp"] = {"enabled": None if eff_deny is None else eff_deny == 0, "nla": _int(r.get("nla")),
                    "policy_nla": _int(r.get("policy_nla")), "port": _int(r.get("port")) or 3389,
                    "policy_managed": pdeny is not None, "assistance": _int(r.get("assistance"))}
    # ---- local accounts
    a = raw.get("accounts")
    if isinstance(a, dict) and isinstance(a.get("users"), list):
        admins = a.get("admins")
        admin_names = None if admins is None else {str(x).split("\\")[-1].lower() for x in _list(admins)}
        users = []
        for x in a["users"]:
            sid = str(x.get("sid") or "")
            name = str(x.get("name") or "")
            builtin = "admin" if sid.endswith("-500") else ("guest" if sid.endswith("-501") else None)
            if sid.endswith("-503") or sid.endswith("-504"):
                builtin = "system"                         # DefaultAccount / WDAGUtilityAccount
            users.append({"name": name, "sid": sid, "enabled": bool(_bool(x.get("enabled"))),
                          "password_required": _bool(x.get("password_required")),
                          "last_logon": _iso(x.get("last_logon")), "password_last_set": _iso(x.get("pw_set")),
                          "builtin": builtin,
                          "admin": None if admin_names is None else name.lower() in admin_names})
        facts["accounts"] = {"users": users, "admins": None if admins is None else
                             [str(x) for x in _list(admins)], "error": errors.get("admins")}
    else:
        facts["accounts"] = None
    # ---- hardening
    h = raw.get("hardening") or {}
    smb1 = _int(h.get("smb1"))
    cfg = _bool(h.get("smb1_cfg"))
    build = facts["os"]["build"] or 0
    smb1_on = cfg if cfg is not None else (smb1 == 1 if smb1 is not None else (build < 16299 if build else None))
    if smb1 == 0:
        smb1_on = False
    running = {_int(x) for x in _list(h.get("dg_running"))}
    facts["hardening"] = {
        "smb1": smb1_on, "wdigest": _int(h.get("wdigest")), "llmnr": _int(h.get("llmnr")),
        "lsa_ppl": _int(h.get("lsa_ppl")), "hvci": _int(h.get("hvci")), "hvci_running": 2 in running,
        "nodrive_autorun": _int(h.get("nodrive_m")) if h.get("nodrive_m") is not None else _int(h.get("nodrive_u")),
        "autoplay_off": _int(h.get("autoplay_off")), "hide_ext": _int(h.get("hide_ext")),
        "ps_machine": str(h.get("ps_machine") or "Undefined"), "ps_user": str(h.get("ps_user") or "Undefined"),
        "ss_active": _int(h.get("ss_active")), "ss_secure": _int(h.get("ss_secure")),
        "ss_timeout": _int(h.get("ss_timeout")), "inactivity": _int(h.get("inactivity")),
    }
    return facts


# ====================================================================== interface
class PostureBackend:
    name = "none"
    label = "Not supported"
    platform = "none"

    def available(self) -> tuple[bool, str | None]:
        return False, "Security posture checks need Windows (or Linux for a smaller set)"

    def can_modify(self) -> bool:
        return False

    def collect(self) -> dict:
        raise BackendError(501, self.available()[1] or "Not supported")

    def reg_get(self, target: str) -> tuple[bool, Any]:
        raise BackendError(501, "Not supported")

    def apply(self, op: dict) -> Any:
        raise BackendError(501, "Automatic fixes are not supported on this computer")

    def search_updates(self) -> list[dict]:
        raise BackendError(501, "Windows Update is not available here")

    def open_target(self, name: str) -> None:
        raise BackendError(501, "Opening Windows settings only works on Windows")

    def rdp_sessions(self, port: int) -> int:
        return 0

    def info(self) -> dict:
        ok, why = self.available()
        return {"name": self.name, "label": self.label, "platform": self.platform, "available": ok,
                "reason": why, "can_modify": bool(ok and self.can_modify())}


class NoPosture(PostureBackend):
    pass


def check_op(op: dict) -> dict:
    """Validate a change against the allow-lists before ANY backend sees it."""
    kind = op.get("op")
    if kind in ("reg_set", "reg_delete"):
        if op.get("target") not in REG_TARGETS:
            raise BackendError(400, "Unknown registry setting")
        if kind == "reg_set" and op.get("value") is None:
            raise BackendError(400, "Missing value")
    elif kind == "mp_pref":
        if op.get("pref") not in MP_PREFS:
            raise BackendError(400, "Unknown Defender setting")
    elif kind == "mp_exclusion":
        if op.get("kind") not in EXCLUSION_KINDS or not str(op.get("value") or "").strip():
            raise BackendError(400, "Bad exclusion")
    elif kind == "mp_scan":
        if op.get("type") not in ("quick", "full"):
            raise BackendError(400, "Scan type must be quick or full")
    elif kind == "user_enabled":
        if not re.fullmatch(r"S-1-5-21-[\d-]+-50[01]", str(op.get("sid") or "")):
            raise BackendError(400, "Only the built-in Administrator / Guest accounts can be switched here")
    elif kind == "bitlocker":
        if not re.fullmatch(r"[A-Za-z]:", str(op.get("mount") or "")):
            raise BackendError(400, "Bad drive")
    elif kind == "service_start":
        if op.get("service") not in SERVICES or op.get("start") not in SERVICE_STARTS:
            raise BackendError(400, "Unknown service setting")
    elif kind == "exec_policy":
        if op.get("policy") not in EXEC_POLICIES:
            raise BackendError(400, "Unknown execution policy")
    elif kind != "mp_update":
        raise BackendError(400, f"Unknown change '{kind}'")
    return op


def needs_elevation(op: dict) -> bool:
    k = op["op"]
    if k in ("reg_set", "reg_delete"):
        return op["target"] not in HKCU_TARGETS
    return k not in ("exec_policy", "mp_update", "mp_scan")


# ====================================================================== Windows
_PS_HEAD = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ErrorActionPreference = 'Stop'\ntry {\n"
_PS_TAIL = ("\n} catch { ConvertTo-Json -InputObject @{ ok = $false; error = [string]$_.Exception.Message } "
            "-Compress }\n")

PS_COLLECT = _PS_HEAD + r"""
function RegV([string]$Path, [string]$Name) {
  try { $k = Get-Item -LiteralPath $Path -ErrorAction Stop; return $k.GetValue($Name, $null) } catch { return $null }
}
function Utc($d) {
  if ($null -eq $d) { return $null }
  try { return ([datetime]$d).ToUniversalTime().ToString('o') } catch { return $null }
}
$f = [ordered]@{ ok = $true; errors = @{} }
$cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
try {
  $os = Get-CimInstance Win32_OperatingSystem
  $ch = @()
  try { $ch = @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes | ForEach-Object { [int]$_ }) } catch {}
  $f.os = @{ caption = [string]$os.Caption; build = [string](RegV $cv 'CurrentBuildNumber'); ubr = (RegV $cv 'UBR')
    display_version = [string](RegV $cv 'DisplayVersion'); release_id = [string](RegV $cv 'ReleaseId')
    edition_id = [string](RegV $cv 'EditionID'); product_type = [int]$os.ProductType; computer = $env:COMPUTERNAME
    user = $env:USERNAME; session = $env:SESSIONNAME; firmware = $env:firmware_type; chassis = $ch }
} catch { $f.errors.os = [string]$_.Exception.Message }
try {
  $s = Get-MpComputerStatus
  $f.defender = @{ am_service = $s.AMServiceEnabled; antivirus = $s.AntivirusEnabled
    realtime = $s.RealTimeProtectionEnabled; behavior = $s.BehaviorMonitorEnabled; ioav = $s.IoavProtectionEnabled
    on_access = $s.OnAccessProtectionEnabled; tamper = $s.IsTamperProtected; sig_age = $s.AntivirusSignatureAge
    sig_version = [string]$s.AntivirusSignatureVersion; sig_updated = (Utc $s.AntivirusSignatureLastUpdated)
    engine = [string]$s.AMEngineVersion; product = [string]$s.AMProductVersion; quick_age = $s.QuickScanAge
    full_age = $s.FullScanAge; mode = [string]$s.AMRunningMode }
} catch { $f.errors.defender = [string]$_.Exception.Message }
try {
  $p = Get-MpPreference
  $f.prefs = @{ maps = [int]$p.MAPSReporting; samples = [int]$p.SubmitSamplesConsent; pua = [int]$p.PUAProtection
    net_prot = [int]$p.EnableNetworkProtection; cfa = [int]$p.EnableControlledFolderAccess
    disable_rt = $p.DisableRealtimeMonitoring; disable_behavior = $p.DisableBehaviorMonitoring
    disable_ioav = $p.DisableIOAVProtection; disable_script = $p.DisableScriptScanning
    ex_path = @($p.ExclusionPath); ex_proc = @($p.ExclusionProcess); ex_ext = @($p.ExclusionExtension) }
} catch { $f.errors.prefs = [string]$_.Exception.Message }
try {
  $f.av_products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.displayName; state = [int]$_.productState; path = [string]$_.pathToSignedProductExe } })
} catch { $f.errors.av_products = [string]$_.Exception.Message }
$f.uac = @{ enable_lua = (RegV $sys 'EnableLUA'); consent_admin = (RegV $sys 'ConsentPromptBehaviorAdmin')
  secure_desktop = (RegV $sys 'PromptOnSecureDesktop') }
try {
  $v = @(Get-BitLockerVolume | ForEach-Object {
    [pscustomobject]@{ mount = [string]$_.MountPoint; type = [string]$_.VolumeType; protection = [string]$_.ProtectionStatus
      status = [string]$_.VolumeStatus; percent = $_.EncryptionPercentage; method = [string]$_.EncryptionMethod
      protectors = @($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }) } })
  $f.bitlocker = @{ source = 'cmdlet'; volumes = $v }
} catch {
  $f.errors.bitlocker = [string]$_.Exception.Message
  try {
    $sh = New-Object -ComObject Shell.Application
    $v = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
      $d = [string]$_.DeviceID; $t = 'Data'
      if ($d -eq $env:SystemDrive) { $t = 'OperatingSystem' }
      [pscustomobject]@{ mount = $d; type = $t; shell = $sh.NameSpace($d + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') } })
    $f.bitlocker = @{ source = 'shell'; volumes = $v }
  } catch {}
}
$sbk = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
$f.secure_boot = @{ state_key = (Test-Path -LiteralPath $sbk); enabled = (RegV $sbk 'UEFISecureBootEnabled') }
try { $f.secure_boot.confirm = [string](Confirm-SecureBootUEFI) } catch { $f.secure_boot.confirm_error = [string]$_.Exception.Message }
try {
  $t = Get-Tpm
  $f.tpm = @{ source = 'cmdlet'; present = $t.TpmPresent; ready = $t.TpmReady; enabled = $t.TpmEnabled
    activated = $t.TpmActivated; manufacturer = [string]$t.ManufacturerIdTxt; version = [string]$t.ManufacturerVersion }
  try { $f.tpm.spec = [string](Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm).SpecVersion } catch {}
} catch {
  $f.errors.tpm = [string]$_.Exception.Message
  try { $f.tpm = @{ source = 'pnp'; devices = @(Get-PnpDevice -Class SecurityDevices -PresentOnly | ForEach-Object { [string]$_.FriendlyName }) } } catch {}
}
$f.smartscreen = @{ explorer = (RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
  policy = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
  edge = (RegV 'HKCU:\Software\Microsoft\Edge\SmartScreenEnabled' ''); edge_policy = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled')
  store = (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation')
  sac = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState') }
$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$f.update = @{ reboot_wu = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
  reboot_cbs = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
  pause_expiry = (RegV $ux 'PauseUpdatesExpiryTime'); pause_start = (RegV $ux 'PauseUpdatesStartTime')
  pause_quality_start = (RegV $ux 'PauseQualityUpdatesStartTime'); pause_quality_end = (RegV $ux 'PauseQualityUpdatesEndTime')
  pause_feature_start = (RegV $ux 'PauseFeatureUpdatesStartTime'); pause_feature_end = (RegV $ux 'PauseFeatureUpdatesEndTime')
  no_auto = (RegV $au 'NoAutoUpdate'); au_options = (RegV $au 'AUOptions') }
try { $f.update.service = [string](Get-Service -Name wuauserv).StartType } catch {}
try {
  $se = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $n = $se.GetTotalHistoryCount()
  if ($n -gt 0) {
    $f.update.history = @($se.QueryHistory(0, [Math]::Min($n, 60)) | Where-Object { $_.Operation -eq 1 } | ForEach-Object {
      [pscustomobject]@{ title = [string]$_.Title; date = ([datetime]$_.Date).ToString('s') + 'Z'; result = [int]$_.ResultCode } })
  }
} catch { $f.errors.update_history = [string]$_.Exception.Message }
try {
  $r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
  if ($r.LastSearchSuccessDate) { $f.update.last_search = ([datetime]$r.LastSearchSuccessDate).ToString('s') + 'Z' }
  if ($r.LastInstallationSuccessDate) { $f.update.last_install = ([datetime]$r.LastInstallationSuccessDate).ToString('s') + 'Z' }
} catch {}
try { $f.update.hotfix_last = Utc (Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn } catch {}
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$tsp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$f.rdp = @{ deny = (RegV $ts 'fDenyTSConnections'); nla = (RegV "$ts\WinStations\RDP-Tcp" 'UserAuthentication')
  port = (RegV "$ts\WinStations\RDP-Tcp" 'PortNumber'); policy_deny = (RegV $tsp 'fDenyTSConnections')
  policy_nla = (RegV $tsp 'UserAuthentication'); assistance = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp') }
try {
  $users = @(Get-LocalUser | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.Name; sid = [string]$_.SID.Value; enabled = [bool]$_.Enabled
      password_required = [bool]$_.PasswordRequired; last_logon = (Utc $_.LastLogon); pw_set = (Utc $_.PasswordLastSet) } })
  $f.accounts = @{ users = $users; admins = $null }
  try { $f.accounts.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [string]$_.Name }) }
  catch { $f.errors.admins = [string]$_.Exception.Message }
} catch { $f.errors.accounts = [string]$_.Exception.Message }
$f.hardening = @{ smb1 = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
  wdigest = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential')
  llmnr = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast')
  lsa_ppl = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
  hvci = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled')
  nodrive_m = (RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun')
  nodrive_u = (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun')
  autoplay_off = (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay')
  hide_ext = (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt')
  ps_machine = [string](Get-ExecutionPolicy -Scope LocalMachine); ps_user = [string](Get-ExecutionPolicy -Scope CurrentUser)
  ss_active = (RegV 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'); ss_secure = (RegV 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure')
  ss_timeout = (RegV 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'); inactivity = (RegV $sys 'InactivityTimeoutSecs') }
try { $f.hardening.smb1_cfg = [string](Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}
try { $f.hardening.dg_running = @((Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning | ForEach-Object { [int]$_ }) } catch {}
ConvertTo-Json -InputObject $f -Compress -Depth 6
""" + _PS_TAIL

PS_REG_GET = _PS_HEAD + r"""
$k = $null
try { $k = Get-Item -LiteralPath $env:CH_PATH -ErrorAction Stop } catch {}
if (($null -ne $k) -and (@($k.GetValueNames()) -contains $env:CH_NAME)) {
  ConvertTo-Json -InputObject @{ ok = $true; exists = $true; value = $k.GetValue($env:CH_NAME) } -Compress
} else {
  ConvertTo-Json -InputObject @{ ok = $true; exists = $false } -Compress
}
""" + _PS_TAIL

PS_REG_SET = _PS_HEAD + r"""
$p = $env:CH_PATH
if ($env:CH_DELETE -eq '1') {
  if (Test-Path -LiteralPath $p) { Remove-ItemProperty -LiteralPath $p -Name $env:CH_NAME -ErrorAction SilentlyContinue }
} else {
  if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force | Out-Null }
  if ($env:CH_TYPE -eq 'DWord') { $v = [int]$env:CH_VALUE } else { $v = [string]$env:CH_VALUE }
  New-ItemProperty -LiteralPath $p -Name $env:CH_NAME -PropertyType $env:CH_TYPE -Value $v -Force | Out-Null
}
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_MP_PREF = _PS_HEAD + r"""
$a = @{}
if ($env:CH_KIND -eq 'bool') { $a[$env:CH_PREF] = [bool]::Parse($env:CH_VALUE) } else { $a[$env:CH_PREF] = [int]$env:CH_VALUE }
Set-MpPreference @a
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_MP_EXCLUSION = _PS_HEAD + r"""
$a = @{}
switch ($env:CH_KIND) {
  'path' { $a.ExclusionPath = $env:CH_VALUE }
  'process' { $a.ExclusionProcess = $env:CH_VALUE }
  'extension' { $a.ExclusionExtension = $env:CH_VALUE }
  default { throw 'Unknown exclusion kind' }
}
if ($env:CH_REMOVE -eq '1') { Remove-MpPreference @a } else { Add-MpPreference @a }
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_MP_UPDATE = _PS_HEAD + r"""
Update-MpSignature
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_MP_SCAN = _PS_HEAD + r"""
$exe = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Microsoft Defender (MpCmdRun.exe) was not found' }
Start-Process -FilePath $exe -ArgumentList @('-Scan', '-ScanType', $env:CH_TYPE) -WindowStyle Hidden
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_USER_ENABLED = _PS_HEAD + r"""
$u = Get-LocalUser -SID $env:CH_SID
if ($env:CH_ENABLED -eq '1') { Enable-LocalUser -InputObject $u } else { Disable-LocalUser -InputObject $u }
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_BITLOCKER = _PS_HEAD + r"""
if ($env:CH_RESUME -eq '1') { Resume-BitLocker -MountPoint $env:CH_MOUNT | Out-Null }
else { Suspend-BitLocker -MountPoint $env:CH_MOUNT -RebootCount 1 | Out-Null }
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_SERVICE = _PS_HEAD + r"""
Set-Service -Name $env:CH_SERVICE -StartupType $env:CH_START
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

# Cyber Hub's own PowerShell runs with -ExecutionPolicy Bypass (Process scope), so Set-ExecutionPolicy
# always reports "overridden by a more specific scope" - the change still lands; read it back instead.
PS_EXEC_POLICY = _PS_HEAD + r"""
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $env:CH_POLICY -Force -ErrorAction SilentlyContinue
ConvertTo-Json -InputObject @{ ok = $true; now = [string](Get-ExecutionPolicy -Scope CurrentUser) } -Compress
""" + _PS_TAIL

PS_UPDATE_SEARCH = _PS_HEAD + r"""
$se = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$r = $se.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$u = @($r.Updates | ForEach-Object {
  [pscustomobject]@{ title = [string]$_.Title; kb = (@($_.KBArticleIDs) -join ','); severity = [string]$_.MsrcSeverity
    downloaded = [bool]$_.IsDownloaded; reboot = [int]$_.InstallationBehavior.RebootBehavior; size = [int64]$_.MaxDownloadSize
    categories = (@($_.Categories | ForEach-Object { [string]$_.Name }) -join ', ') } })
ConvertTo-Json -InputObject @{ ok = $true; updates = $u } -Compress -Depth 4
""" + _PS_TAIL

ALL_SCRIPTS = {"collect": PS_COLLECT, "reg_get": PS_REG_GET, "reg_set": PS_REG_SET, "mp_pref": PS_MP_PREF,
               "mp_exclusion": PS_MP_EXCLUSION, "mp_update": PS_MP_UPDATE, "mp_scan": PS_MP_SCAN,
               "user_enabled": PS_USER_ENABLED, "bitlocker": PS_BITLOCKER, "service": PS_SERVICE,
               "exec_policy": PS_EXEC_POLICY, "update_search": PS_UPDATE_SEARCH}

_DENIED = re.compile(r"access is denied|0x80070005|permissiondenied|unauthorizedaccess|requested registry access "
                     r"is not allowed|requires elevation|administrator", re.I)


def _norm_update(u: dict) -> dict:
    sev = str(u.get("severity") or "").strip() or None
    return {"title": str(u.get("title") or "?"), "kb": [f"KB{k}" for k in str(u.get("kb") or "").split(",") if k],
            "severity": sev, "downloaded": bool(u.get("downloaded")),
            "reboot": _int(u.get("reboot")) in (1, 2), "size_mb": round((_int(u.get("size")) or 0) / 1048576, 1),
            "categories": str(u.get("categories") or "") or None}


def _rdp_connections(port: int) -> int:
    """Established incoming connections to the Remote Desktop port (someone is connected right now)."""
    try:
        import psutil
        return sum(1 for c in psutil.net_connections("tcp")
                   if c.status == "ESTABLISHED" and c.laddr and c.laddr.port == port and c.raddr)
    except Exception:
        return 0


class WindowsPosture(PostureBackend):
    name = "windows"
    label = "Windows Security (PowerShell)"
    platform = "windows"

    def __init__(self, ps: Callable[..., Any] | None = None, elevated: Callable[[], bool] | None = None,
                 opener: Callable[[str], None] | None = None):
        self._ps = ps or run_powershell_json
        if elevated is None:
            from .processes import is_elevated
            elevated = is_elevated
        self._elevated = elevated
        self._opener = opener

    def available(self) -> tuple[bool, str | None]:
        if self._ps is run_powershell_json and not IS_WINDOWS:            # pragma: no cover
            return False, "Windows security checks only run on Windows"
        return True, None

    def can_modify(self) -> bool:
        return bool(self._elevated())

    def _run(self, script: str, env: dict | None = None, timeout: float = 60.0) -> dict:
        data = self._ps(script, timeout=timeout, env=env or {})
        if not isinstance(data, dict):
            raise BackendError(502, "Windows did not answer (PowerShell unavailable or timed out)")
        if not data.get("ok"):
            msg = str(data.get("error") or "Windows refused the change").strip()
            if _DENIED.search(msg):
                raise BackendError(403, NEEDS_ADMIN)
            raise BackendError(400, msg[:400])
        return data

    def collect(self) -> dict:
        return normalize_windows(self._run(PS_COLLECT, timeout=120), self.can_modify())

    def reg_get(self, target: str) -> tuple[bool, Any]:
        t = REG_TARGETS[target]
        d = self._run(PS_REG_GET, {"CH_PATH": t["path"], "CH_NAME": t["name"]}, 20)
        return bool(d.get("exists")), d.get("value")

    def apply(self, op: dict) -> Any:
        op = check_op(op)
        if needs_elevation(op) and not self.can_modify():
            raise BackendError(403, NEEDS_ADMIN)
        k = op["op"]
        if k in ("reg_set", "reg_delete"):
            t = REG_TARGETS[op["target"]]
            env = {"CH_PATH": t["path"], "CH_NAME": t["name"], "CH_TYPE": t["type"],
                   "CH_DELETE": "1" if k == "reg_delete" else "0", "CH_VALUE": "" if k == "reg_delete" else
                   str(int(op["value"]) if t["type"] == "DWord" else op["value"])}
            self._run(PS_REG_SET, env, 30)
        elif k == "mp_pref":
            kind = MP_PREFS[op["pref"]][0]
            val = ("true" if op["value"] else "false") if kind == "bool" else str(int(op["value"]))
            self._run(PS_MP_PREF, {"CH_PREF": op["pref"], "CH_KIND": kind, "CH_VALUE": val}, 60)
        elif k == "mp_exclusion":
            self._run(PS_MP_EXCLUSION, {"CH_KIND": op["kind"], "CH_VALUE": str(op["value"]),
                                        "CH_REMOVE": "1" if op.get("remove") else "0"}, 60)
        elif k == "mp_update":
            self._run(PS_MP_UPDATE, {}, 600)
        elif k == "mp_scan":
            self._run(PS_MP_SCAN, {"CH_TYPE": "1" if op["type"] == "quick" else "2"}, 30)
        elif k == "user_enabled":
            self._run(PS_USER_ENABLED, {"CH_SID": op["sid"], "CH_ENABLED": "1" if op["enabled"] else "0"}, 30)
        elif k == "bitlocker":
            self._run(PS_BITLOCKER, {"CH_MOUNT": op["mount"].upper(), "CH_RESUME": "1" if op["resume"] else "0"},
                      120)
        elif k == "service_start":
            self._run(PS_SERVICE, {"CH_SERVICE": op["service"], "CH_START": op["start"]}, 30)
        elif k == "exec_policy":
            d = self._run(PS_EXEC_POLICY, {"CH_POLICY": op["policy"]}, 30)
            if str(d.get("now") or "").lower() != op["policy"].lower():
                raise BackendError(409, "Windows kept the old execution policy (set by Group Policy?)")
        return True

    def search_updates(self) -> list[dict]:
        d = self._run(PS_UPDATE_SEARCH, {}, 900)
        return [_norm_update(u) for u in _list(d.get("updates")) if isinstance(u, dict)]

    def open_target(self, name: str) -> None:
        target = OPEN_TARGETS.get(name)
        if not target:
            raise BackendError(404, "Unknown settings page")
        if self._opener:
            self._opener(target)
            return
        if not IS_WINDOWS:                                                 # pragma: no cover
            raise BackendError(501, "Opening Windows settings only works on Windows")
        try:                                                               # pragma: no cover - Windows only
            if target.startswith("control:"):
                subprocess.Popen(["control"] + target[len("control:"):].split(" ", 1), creationflags=0x08000000)
            elif target.startswith("file:"):
                os.startfile(target[len("file:"):])                        # type: ignore[attr-defined]
            else:
                os.startfile(target)                                       # type: ignore[attr-defined]
        except OSError as e:                                               # pragma: no cover
            raise BackendError(502, f"Windows could not open it: {e}")

    def rdp_sessions(self, port: int) -> int:
        return _rdp_connections(port)


# ====================================================================== Linux (read-only)
class LinuxPosture(PostureBackend):
    name = "linux"
    label = "Linux security checks (read-only)"
    platform = "linux"

    def __init__(self, root: str | Path = "/", lsblk: Callable[[], Any] | None = None,
                 sshd_running: Callable[[], bool] | None = None, elevated: Callable[[], bool] | None = None):
        self.root = Path(root)
        self._lsblk = lsblk or self._run_lsblk
        self._sshd = sshd_running or self._sshd_running
        if elevated is None:
            from .processes import is_elevated
            elevated = is_elevated
        self._elevated = elevated

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def can_modify(self) -> bool:
        return False                                  # Linux posture is advice only

    def _p(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")

    def _read(self, rel: str) -> str | None:
        try:
            return self._p(rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    @staticmethod
    def _run_lsblk() -> Any:
        out = run_cmd(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT"], 5)
        try:
            return json.loads(out) if out else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _sshd_running() -> bool:
        try:
            import psutil
            return any((p.info.get("name") or "") == "sshd" for p in psutil.process_iter(["name"]))
        except Exception:
            return False

    def _secure_boot(self) -> dict:
        efi = self._p("sys/firmware/efi").is_dir()
        enabled = None
        if efi:
            enabled = False
            var = self._p("sys/firmware/efi/efivars")
            try:
                for f in var.glob("SecureBoot-*"):
                    data = f.read_bytes()
                    enabled = bool(data) and data[-1] == 1
                    break
            except OSError:
                enabled = None
        return {"uefi": efi, "enabled": enabled if efi else False}

    def _tpm(self) -> dict:
        d = self._p("sys/class/tpm/tpm0")
        if not d.exists():
            return {"present": False, "version": None, "ready": None, "enabled": None, "activated": None,
                    "manufacturer": None, "source": "sysfs"}
        major = (self._read("sys/class/tpm/tpm0/tpm_version_major") or "").strip()
        return {"present": True, "version": "2.0" if major == "2" else ("1.2" if major == "1" else None),
                "ready": True, "enabled": True, "activated": True, "manufacturer": None, "source": "sysfs"}

    def _root_encryption(self) -> dict | None:
        data = self._lsblk()
        if not isinstance(data, dict):
            return None

        def walk(nodes, crypt: bool) -> bool | None:
            for n in nodes or []:
                c = crypt or str(n.get("type") or "") == "crypt"
                mps = n.get("mountpoints") or [n.get("mountpoint")]
                if "/" in mps:
                    return c
                r = walk(n.get("children"), c)
                if r is not None:
                    return r
            return None
        enc = walk(data.get("blockdevices"), False)
        if enc is None:
            return None
        return {"source": "lsblk", "available": True, "error": None,
                "volumes": [{"mount": "/", "kind": "os", "state": "on" if enc else "off", "percent": None,
                             "method": "LUKS" if enc else None, "protectors": []}]}

    def _sshd_config(self) -> dict:
        vals: dict[str, str] = {}
        files = [self._p("etc/ssh/sshd_config")]
        try:
            files = sorted(self._p("etc/ssh/sshd_config.d").glob("*.conf")) + files    # Include is read first
        except OSError:
            pass
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.lower().startswith("match "):
                    if line.lower().startswith("match "):
                        break                       # Match blocks only apply to some users
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    vals.setdefault(parts[0].lower(), parts[1].strip().lower())     # first value wins (sshd)
        return {"running": self._sshd(), "permit_root": vals.get("permitrootlogin", "prohibit-password"),
                "password_auth": vals.get("passwordauthentication", "yes")}

    def _updates(self) -> dict:
        auto = None
        cfg = self._read("etc/apt/apt.conf.d/20auto-upgrades")
        if cfg is not None:
            m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"(\d+)"', cfg)
            auto = bool(m and m.group(1) != "0")
        elif any(self._p("etc/systemd/system/timers.target.wants").glob("dnf-automatic*")) \
                if self._p("etc/systemd/system/timers.target.wants").is_dir() else False:
            auto = True
        last = None
        for rel in ("var/lib/dpkg/status", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages",
                    "var/lib/pacman/local"):
            p = self._p(rel)
            if p.exists():
                last = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()
                break
        return {"last_install": last, "last_search": None, "history": [], "available": last is not None,
                "pending_reboot": self._p("var/run/reboot-required").exists() or
                self._p("run/reboot-required").exists(),
                "paused_until": None, "policy_no_auto": False, "au_options": None, "service": None,
                "auto_updates": auto}

    def _guest(self) -> bool | None:
        found = None
        for f in [self._p("etc/lightdm/lightdm.conf")] + sorted(self._p("etc/lightdm/lightdm.conf.d").glob("*.conf")
                                                                if self._p("etc/lightdm/lightdm.conf.d").is_dir()
                                                                else []):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = re.findall(r"^\s*allow-guest\s*=\s*(\w+)", text, re.M)
            if m:
                found = m[-1].lower() == "true"
        return found

    def collect(self) -> dict:
        osr = self._read("etc/os-release") or ""
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)', osr, re.M)
        guest = self._guest()
        return {
            "platform": "linux", "elevated": bool(self._elevated()), "errors": {},
            "os": {"name": m.group(1) if m else f"Linux {platform.release()}", "build": None, "ubr": None,
                   "display_version": None, "edition_id": None, "product_type": 1, "computer": platform.node(),
                   "user": os.environ.get("USER"), "session": None, "portable": None, "firmware": None},
            "av": None, "uac": None, "smartscreen": None, "rdp": None, "hardening": None,
            "secure_boot": self._secure_boot(), "tpm": self._tpm(), "bitlocker": self._root_encryption(),
            "update": self._updates(), "ssh": self._sshd_config(),
            "accounts": {"users": [], "admins": None, "error": None, "guest_session": guest},
        }


# ====================================================================== in-memory Windows PC
def _days_ago(n: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def default_raw() -> dict:
    """A realistic, slightly neglected Windows 11 laptop - every category has something to fix."""
    return {
        "ok": True, "errors": {"admins": None},
        "os": {"caption": "Microsoft Windows 11 Pro", "build": "26200", "ubr": 6899, "display_version": "25H2",
               "edition_id": "Professional", "product_type": 1, "computer": "LAB-PC", "user": "syed",
               "session": "Console", "firmware": "UEFI", "chassis": [10]},
        "defender": {"am_service": True, "antivirus": True, "realtime": True, "behavior": True, "ioav": True,
                     "on_access": True, "tamper": True, "sig_age": 9, "sig_version": "1.421.118.0",
                     "sig_updated": _days_ago(9), "engine": "1.1.25090.3", "product": "4.18.25090.3002",
                     "quick_age": 21, "full_age": 65535, "mode": "Normal"},
        "prefs": {"maps": 2, "samples": 1, "pua": 0, "net_prot": 0, "cfa": 0, "disable_rt": False,
                  "disable_behavior": False, "disable_ioav": False, "disable_script": False,
                  "ex_path": [r"C:\Users\syed\Downloads", r"D:\Projects\build"], "ex_proc": [], "ex_ext": []},
        "av_products": [{"name": "Windows Defender", "state": 397568, "path": "windowsdefender://"}],
        "uac": {"enable_lua": 1, "consent_admin": 0, "secure_desktop": 1},
        "bitlocker": {"source": "cmdlet", "volumes": [
            {"mount": "C:", "type": "OperatingSystem", "protection": "Off", "status": "FullyDecrypted",
             "percent": 0, "method": "None", "protectors": []},
            {"mount": "D:", "type": "Data", "protection": "Off", "status": "FullyDecrypted", "percent": 0,
             "method": "None", "protectors": []}]},
        "secure_boot": {"state_key": True, "enabled": 1, "confirm": "True"},
        "tpm": {"source": "cmdlet", "present": True, "ready": True, "enabled": True, "activated": True,
                "manufacturer": "INTC", "version": "600.18.0.0", "spec": "2.0, 0, 1.59"},
        "smartscreen": {"explorer": "Warn", "policy": None, "edge": 1, "edge_policy": None, "store": 0, "sac": 0},
        "update": {"history": [{"title": "2026-09 Cumulative Update for Windows 11 Version 25H2 (KB5065999)",
                                "date": _days_ago(52), "result": 2},
                               {"title": "Security Intelligence Update for Microsoft Defender Antivirus",
                                "date": _days_ago(9), "result": 2},
                               {"title": "2026-10 Cumulative Update for Windows 11 Version 25H2 (KB5066888)",
                                "date": _days_ago(20), "result": 4}],
                   "last_search": _days_ago(1), "last_install": None, "hotfix_last": _days_ago(52),
                   "reboot_wu": True, "reboot_cbs": False, "pause_expiry": None, "pause_start": None,
                   "pause_quality_start": None, "pause_quality_end": None, "pause_feature_start": None,
                   "pause_feature_end": None, "no_auto": None, "au_options": None, "service": "Manual"},
        "rdp": {"deny": 0, "nla": 0, "port": 3389, "policy_deny": None, "policy_nla": None, "assistance": 1},
        "accounts": {"users": [
            {"name": "Administrator", "sid": "S-1-5-21-1111111111-2222222222-3333333333-500", "enabled": False,
             "password_required": True, "last_logon": None, "pw_set": None},
            {"name": "Guest", "sid": "S-1-5-21-1111111111-2222222222-3333333333-501", "enabled": True,
             "password_required": False, "last_logon": None, "pw_set": None},
            {"name": "DefaultAccount", "sid": "S-1-5-21-1111111111-2222222222-3333333333-503", "enabled": False,
             "password_required": False, "last_logon": None, "pw_set": None},
            {"name": "syed", "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001", "enabled": True,
             "password_required": True, "last_logon": _days_ago(0), "pw_set": _days_ago(200)},
            {"name": "kid", "sid": "S-1-5-21-1111111111-2222222222-3333333333-1002", "enabled": True,
             "password_required": False, "last_logon": _days_ago(3), "pw_set": None}],
            "admins": [r"LAB-PC\Administrator", r"LAB-PC\syed"]},
        "hardening": {"smb1": None, "smb1_cfg": "False", "wdigest": 1, "llmnr": None, "lsa_ppl": None, "hvci": 0,
                      "dg_running": [], "nodrive_m": None, "nodrive_u": None, "autoplay_off": 0, "hide_ext": 1,
                      "ps_machine": "Undefined", "ps_user": "Unrestricted", "ss_active": "1", "ss_secure": "0",
                      "ss_timeout": "900", "inactivity": None},
    }


class MemoryPosture(PostureBackend):
    """Windows-like simulator. `raw` has exactly the PowerShell probe's shape."""
    name = "memory"
    label = "Simulated Windows PC"
    platform = "windows"

    def __init__(self, raw: dict | None = None, elevated: bool = True):
        self.raw = raw or default_raw()
        self.elevated = elevated
        self.calls: list[str] = []
        self.fail: BackendError | None = None
        self.opened: list[str] = []
        self.rdp_connected = 0
        self.updates = [{"title": "2026-11 Cumulative Update for Windows 11 Version 25H2 (KB5068111)",
                         "kb": "5068111", "severity": "Critical", "downloaded": True, "reboot": 1,
                         "size": 734003200, "categories": "Security Updates"},
                        {"title": "Microsoft Defender Antivirus antimalware platform update (KB4052623)",
                         "kb": "4052623", "severity": "", "downloaded": False, "reboot": 0, "size": 15728640,
                         "categories": "Definition Updates"}]
        self.search_delay = 0.0

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def can_modify(self) -> bool:
        return self.elevated

    def _tick(self, what: str) -> None:
        self.calls.append(what)
        if self.fail:
            e, self.fail = self.fail, None
            raise e

    def collect(self) -> dict:
        self._tick("collect")
        return normalize_windows(copy.deepcopy(self.raw), self.elevated)

    def reg_get(self, target: str) -> tuple[bool, Any]:
        v = _get(self.raw, REG_TARGETS[target]["raw"])
        return v is not None, v

    def apply(self, op: dict) -> Any:
        op = check_op(op)
        self._tick("apply:" + op["op"])
        if needs_elevation(op) and not self.elevated:
            raise BackendError(403, NEEDS_ADMIN)
        k, r = op["op"], self.raw
        if k == "reg_set":
            t = REG_TARGETS[op["target"]]
            _set(r, t["raw"], int(op["value"]) if t["type"] == "DWord" else str(op["value"]))
        elif k == "reg_delete":
            _set(r, REG_TARGETS[op["target"]]["raw"], None)
        elif k == "mp_pref":
            if r.get("prefs") is None:
                raise BackendError(502, "Microsoft Defender is not running")
            if op["pref"] in TAMPER_GUARDED and (r.get("defender") or {}).get("tamper"):
                return True                           # Windows answers "OK" and silently keeps the old value
            kind, field = MP_PREFS[op["pref"]]
            r["prefs"][field] = bool(op["value"]) if kind == "bool" else int(op["value"])
            live = {"disable_rt": "realtime", "disable_behavior": "behavior", "disable_ioav": "ioav"}
            if field in live and r.get("defender"):
                r["defender"][live[field]] = not bool(op["value"])
        elif k == "mp_exclusion":
            field = EXCLUSION_KINDS[op["kind"]]
            items = list(r["prefs"].get(field) or [])
            if op.get("remove"):
                items = [x for x in items if x.lower() != str(op["value"]).lower()]
            elif str(op["value"]).lower() not in (x.lower() for x in items):
                items.append(str(op["value"]))
            r["prefs"][field] = items
        elif k == "mp_update":
            r["defender"]["sig_age"] = 0
            r["defender"]["sig_updated"] = _days_ago(0)
        elif k == "mp_scan":
            r["defender"]["quick_age" if op["type"] == "quick" else "full_age"] = 0
        elif k == "user_enabled":
            for u in r["accounts"]["users"]:
                if u["sid"] == op["sid"]:
                    u["enabled"] = bool(op["enabled"])
                    break
            else:
                raise BackendError(404, "That account does not exist")
        elif k == "bitlocker":
            for v in r["bitlocker"]["volumes"]:
                if v["mount"].upper() == op["mount"].upper():
                    v["protection"] = "On" if op["resume"] else "Off"
                    break
            else:
                raise BackendError(404, "That drive is not encrypted")
        elif k == "service_start":
            _set(r, SERVICES[op["service"]], op["start"])
        elif k == "exec_policy":
            r["hardening"]["ps_user"] = op["policy"]
        return True

    def search_updates(self) -> list[dict]:
        self._tick("search_updates")
        if self.search_delay:
            time.sleep(self.search_delay)
        return [_norm_update(u) for u in self.updates]

    def open_target(self, name: str) -> None:
        if name not in OPEN_TARGETS:
            raise BackendError(404, "Unknown settings page")
        self.opened.append(name)

    def rdp_sessions(self, port: int) -> int:
        return self.rdp_connected


def pick_backend() -> PostureBackend:
    """CYBERHUB_POSTURE_BACKEND = windows | linux | memory | none, else auto-detect."""
    forced = os.environ.get("CYBERHUB_POSTURE_BACKEND", "").strip().lower()
    if forced == "memory":
        return MemoryPosture()
    if forced == "none":
        return NoPosture()
    if forced == "linux" or (not forced and IS_LINUX):
        return LinuxPosture()
    if forced == "windows" or (not forced and IS_WINDOWS):
        return WindowsPosture()
    return NoPosture()
