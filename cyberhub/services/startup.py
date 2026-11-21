"""
Cyber Hub Backend - Startup manager & persistence watch (Part 4)
Developed by Syed Muhammad Tayyab

Collects everything that starts automatically with the PC, the same places
malware uses for persistence:

  Windows   registry Run / RunOnce keys (user + machine, 32 + 64 bit),
            Startup folders (user + all users), auto-start services,
            scheduled tasks (logon / boot / timed)
  Linux     XDG autostart .desktop files, systemd services, cron @reboot
            (so the engine is fully usable and testable off Windows)

Enable / disable works the way Task Manager does it - the original entry is
never deleted:
  * Run keys + Startup folder -> Explorer\\StartupApproved (02 = on, 03 = off)
  * services                  -> sc.exe config start= disabled / previous type
  * scheduled tasks           -> schtasks /Change /ENABLE | /DISABLE
  * XDG autostart             -> Hidden=true (user override for system entries)

Every item gets an ID, risk flags, signature (Windows) and a "new since you
last reviewed" marker; the watch loop raises an activity alert when a new
startup entry appears - a classic sign of malware installing itself.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import struct
import time
from pathlib import Path

from ..database import Database
from ..logger import get_logger
from . import threat_flags as tf
from .platform_tools import (CACHE, IS_LINUX, IS_WINDOWS, run_cmd, run_cmd_full,
                             run_powershell_json)
from .signatures import SignatureService

log = get_logger("startup")

SOURCES = {
    "registry_run": "Registry Run key",
    "registry_runonce": "Registry RunOnce key",
    "startup_folder": "Startup folder",
    "service": "Windows service",
    "scheduled_task": "Scheduled task",
    "xdg_autostart": "Desktop autostart",
    "systemd": "systemd service",
    "cron": "cron @reboot",
}

# Services Cyber Hub refuses to disable: turning these off breaks Windows or its protection.
PROTECTED_SERVICES = {
    "windefend", "wdnissvc", "mpssvc", "bfe", "securityhealthservice", "wscsvc", "sense",
    "eventlog", "rpcss", "dcomlaunch", "rpceptmapper", "lsm", "samss", "winmgmt", "cryptsvc",
    "dhcp", "dnscache", "nsi", "profsvc", "power", "schedule", "systemeventsbroker",
    "brokerinfrastructure", "coremessagingregistrar", "plugplay", "wuauserv", "usosvc",
    "trustedinstaller", "appinfo", "gpsvc", "lanmanworkstation", "netprofm", "nlasvc",
    "audiosrv", "audioendpointbuilder", "themes", "userManager".lower(), "staterepository",
    "sgrmbroker", "keyiso", "vaultsvc", "msiserver",
}
SERVICE_NAME_RE = re.compile(r"^[\w.\-@$ ]{1,256}$")
TASK_PATH_RE = re.compile(r"^\\[^\"<>|\x00-\x1f]{0,512}$")


# (include_services, include_microsoft_tasks, include_manual): everything Cyber Hub can see
FULL = (True, True, True)


class StartupError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def item_id(source: str, location: str, name: str) -> str:
    return hashlib.sha1(f"{source}|{location}|{name}".lower().encode()).hexdigest()[:16]


# ============================================================ StartupApproved bytes
def approved_is_enabled(data: bytes | None) -> bool:
    """Explorer\\StartupApproved value: missing or even first byte = enabled, odd = disabled."""
    if not data:
        return True
    return data[0] % 2 == 0


def approved_value(enabled: bool, now: float | None = None) -> bytes:
    """12-byte value exactly as Task Manager writes it (flag + FILETIME of when it was disabled)."""
    if enabled:
        return bytes([0x02]) + bytes(11)
    filetime = int(((now or time.time()) + 11644473600) * 10_000_000)
    return bytes([0x03, 0, 0, 0]) + struct.pack("<Q", filetime)


# ============================================================ command -> program path
def _expand(s: str) -> str:
    return os.path.expandvars(os.path.expanduser(s))


def parse_command(command: str | None) -> tuple[str | None, str]:
    """Best-effort: the program file a startup command runs, plus its arguments.
    Handles quoted paths, unquoted paths with spaces, %VARS% and rundll32 DLL targets."""
    if not command:
        return None, ""
    cmd = _expand(command.strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        exe, args = (cmd[1:end], cmd[end + 1:].strip()) if end > 0 else (cmd[1:], "")
    else:
        exe, args = None, ""
        parts = cmd.split(" ")
        for i in range(len(parts), 0, -1):               # longest prefix that exists on disk
            cand = " ".join(parts[:i])
            if os.path.isfile(cand) or (IS_WINDOWS and os.path.isfile(cand + ".exe")):
                exe, args = (cand if os.path.isfile(cand) else cand + ".exe"), " ".join(parts[i:])
                break
        if exe is None:
            first = parts[0]
            if not IS_WINDOWS:
                try:
                    first = shlex.split(cmd)[0]
                except ValueError:
                    pass
            exe, args = first, cmd[len(parts[0]):].strip()
    base = os.path.basename(exe.replace("\\", "/")).lower()
    if base in ("rundll32.exe", "rundll32") and args:      # rundll32 "x.dll",Entry -> the DLL is the payload
        target = args.strip().strip('"').split(",")[0].strip('"')
        if target:
            return _expand(target), args
    return exe, args


def _sig_status_flags(item: dict) -> list[str]:
    return tf.signature_flags(item.get("signature"))


# ============================================================ Windows providers
if IS_WINDOWS:                                            # pragma: no cover - exercised on Windows
    import winreg

    _RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
    _RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    _APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
    _WOW = winreg.KEY_WOW64_64KEY

    REG_LOCATIONS = [
        # (hive, hive_name, key, scope, source, approved_subkey, view)
        (winreg.HKEY_CURRENT_USER, "HKCU", _RUN, "user", "registry_run", "Run", 0),
        (winreg.HKEY_CURRENT_USER, "HKCU", _RUNONCE, "user", "registry_runonce", None, 0),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", _RUN, "machine", "registry_run", "Run", _WOW),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
         "machine", "registry_run", "Run32", _WOW),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", _RUNONCE, "machine", "registry_runonce", None, _WOW),
    ]

    def _reg_values(hive, key: str, view: int) -> dict[str, object]:
        out: dict[str, object] = {}
        try:
            with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | view) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out[name] = val
                    i += 1
        except OSError:
            pass
        return out

    def _approved_write(hive, sub: str, name: str, enabled: bool) -> None:
        with winreg.CreateKeyEx(hive, _APPROVED + "\\" + sub, 0, winreg.KEY_SET_VALUE | _WOW) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, approved_value(enabled))

    _HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}


def _win_registry() -> list[dict]:                        # pragma: no cover
    items = []
    for hive, hname, key, scope, source, approved, view in REG_LOCATIONS:
        states = _reg_values(hive, _APPROVED + "\\" + approved, _WOW) if approved else {}
        for name, value in _reg_values(hive, key, view).items():
            if not name or not isinstance(value, str):
                continue
            loc = f"{hname}\\{key}"
            exe, args = parse_command(value)
            items.append({
                "id": item_id(source, loc, name), "source": source, "name": name, "command": value,
                "path": exe, "location": loc, "scope": scope,
                "enabled": approved_is_enabled(states.get(name)) if approved else True,
                "can_toggle": approved is not None, "requires_admin": hname == "HKLM",
                "_toggle": {"kind": "approved", "hive": hname, "sub": approved, "value": name},
            })
    return items


def _startup_folders() -> list[tuple[str, Path, str]]:
    out = []
    if os.environ.get("APPDATA"):
        out.append(("user", Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup", "HKCU"))
    if os.environ.get("ProgramData"):
        out.append(("machine", Path(os.environ["ProgramData"]) / r"Microsoft\Windows\Start Menu\Programs\StartUp", "HKLM"))
    return out


_LNK_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$sh = New-Object -ComObject WScript.Shell
$paths = $env:CYBERHUB_LNK_PATHS | ConvertFrom-Json
$out = foreach ($p in $paths) { $l = $sh.CreateShortcut($p)
  [pscustomobject]@{ path = $p; target = $l.TargetPath; args = $l.Arguments } }
ConvertTo-Json -InputObject @($out) -Compress
"""


def _win_startup_folder() -> list[dict]:                  # pragma: no cover
    items, lnks = [], []
    for scope, folder, hname in _startup_folders():
        if not folder.is_dir():
            continue
        states = _reg_values(_HIVES[hname], _APPROVED + r"\StartupFolder", _WOW)
        for f in folder.iterdir():
            if f.name.lower() == "desktop.ini" or not f.is_file():
                continue
            it = {"id": item_id("startup_folder", str(folder), f.name), "source": "startup_folder",
                  "name": f.stem, "command": str(f), "path": str(f), "location": str(folder), "scope": scope,
                  "enabled": approved_is_enabled(states.get(f.name)), "can_toggle": True,
                  "requires_admin": scope == "machine", "file": str(f),
                  "_toggle": {"kind": "approved", "hive": hname, "sub": "StartupFolder", "value": f.name}}
            items.append(it)
            if f.suffix.lower() == ".lnk":
                lnks.append(it)
    if lnks:
        data = run_powershell_json(_LNK_SCRIPT, timeout=15,
                                   env={"CYBERHUB_LNK_PATHS": json.dumps([i["file"] for i in lnks])}) or []
        if isinstance(data, dict):
            data = [data]
        targets = {str(d.get("path", "")).lower(): d for d in data if isinstance(d, dict)}
        for it in lnks:
            d = targets.get(it["file"].lower())
            if d and d.get("target"):
                it["path"] = d["target"]
                it["command"] = f'"{d["target"]}" {d.get("args") or ""}'.strip()
    return items


def _win_services(include_manual: bool) -> list[dict]:   # pragma: no cover
    import psutil
    items = []
    for s in psutil.win_service_iter():
        try:
            d = s.as_dict()
        except Exception:
            continue
        st = d.get("start_type")
        if st not in ("automatic", "disabled") and not (include_manual and st == "manual"):
            continue
        name = d.get("name") or ""
        exe, _ = parse_command(d.get("binpath"))
        protected = name.lower() in PROTECTED_SERVICES
        items.append({
            "id": item_id("service", "services", name), "source": "service", "name": d.get("display_name") or name,
            "service_name": name, "command": d.get("binpath"), "path": exe, "location": f"Services\\{name}",
            "scope": "machine", "enabled": st != "disabled", "start_type": st, "status": d.get("status"),
            "description": (d.get("description") or "")[:300] or None,
            "can_toggle": not protected, "requires_admin": True,
            "protected_reason": "Essential Windows / security service" if protected else None,
            "_toggle": {"kind": "service", "name": name, "start_type": st},
        })
    return items


_TASK_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$all = $env:CYBERHUB_TASKS_ALL -eq '1'
$out = Get-ScheduledTask | Where-Object { $all -or $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $a = @($_.Actions)[0]
  [pscustomobject]@{
    name = $_.TaskName; path = $_.TaskPath; state = [string]$_.State; author = $_.Author
    description = $_.Description; execute = $a.Execute; arguments = $a.Arguments
    triggers = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  } }
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""
_TRIGGER = {"MSFT_TaskLogonTrigger": "logon", "MSFT_TaskBootTrigger": "boot", "MSFT_TaskDailyTrigger": "daily",
            "MSFT_TaskWeeklyTrigger": "weekly", "MSFT_TaskTimeTrigger": "time", "MSFT_TaskIdleTrigger": "idle",
            "MSFT_TaskEventTrigger": "event", "MSFT_TaskSessionStateChangeTrigger": "session",
            "MSFT_TaskRegistrationTrigger": "registration"}


def _win_tasks(include_microsoft: bool) -> list[dict]:   # pragma: no cover
    data = run_powershell_json(_TASK_SCRIPT, timeout=40,
                               env={"CYBERHUB_TASKS_ALL": "1" if include_microsoft else "0"}) or []
    if isinstance(data, dict):
        data = [data]
    items = []
    for t in data:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        full = (t.get("path") or "\\") + t["name"]
        exe = _expand(t.get("execute") or "").strip('"') or None
        triggers = [_TRIGGER.get(x, x) for x in (t.get("triggers") or []) if x]
        command = f'"{exe}" {t.get("arguments") or ""}'.strip() if exe else None
        items.append({
            "id": item_id("scheduled_task", t.get("path") or "\\", t["name"]), "source": "scheduled_task",
            "name": t["name"], "task_path": full, "command": command, "path": exe, "location": t.get("path"),
            "scope": "machine", "enabled": t.get("state") != "Disabled", "state": t.get("state"),
            "author": t.get("author"), "description": (t.get("description") or "")[:300] or None,
            "triggers": triggers, "runs_at_startup": bool({"logon", "boot"} & set(triggers)),
            "can_toggle": True, "requires_admin": (t.get("path") or "").lower().startswith("\\microsoft\\"),
            "_toggle": {"kind": "task", "name": full},
        })
    return items


# ============================================================ Linux / XDG providers
def xdg_dirs() -> tuple[Path, list[Path]]:
    user = Path(os.environ.get("CYBERHUB_AUTOSTART_USER_DIR")
                or Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart")
    sys_env = os.environ.get("CYBERHUB_AUTOSTART_SYSTEM_DIR")
    system = [Path(sys_env)] if sys_env else [Path("/etc/xdg/autostart")]
    return user, system


def parse_desktop(text: str) -> dict[str, str]:
    out, in_entry = {}, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_entry = s == "[Desktop Entry]"
            continue
        if in_entry and "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def _desktop_enabled(d: dict[str, str]) -> bool:
    return (d.get("Hidden", "false").lower() != "true"
            and d.get("X-GNOME-Autostart-enabled", "true").lower() != "false")


def set_desktop_hidden(text: str, hidden: bool) -> str:
    """Set Hidden= inside [Desktop Entry]; every other line is kept as it was."""
    val = "true" if hidden else "false"
    out: list[str] = []
    in_entry = wrote = seen_entry = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            if in_entry and not wrote:
                out.append(f"Hidden={val}")
                wrote = True
            in_entry = s == "[Desktop Entry]"
            seen_entry = seen_entry or in_entry
            out.append(line)
            continue
        if in_entry and "=" in s:
            key = s.split("=", 1)[0].strip()
            if key == "Hidden":
                if not wrote:
                    out.append(f"Hidden={val}")
                    wrote = True
                continue
            if key == "X-GNOME-Autostart-enabled" and not hidden:
                out.append("X-GNOME-Autostart-enabled=true")
                continue
        out.append(line)
    if not wrote:
        if in_entry:
            out.append(f"Hidden={val}")
        elif not seen_entry:
            out = ["[Desktop Entry]", f"Hidden={val}"] + out
    return "\n".join(out) + "\n"


def _xdg_items() -> list[dict]:
    user_dir, system_dirs = xdg_dirs()
    found: dict[str, dict] = {}
    for scope, folder in [("machine", d) for d in system_dirs] + [("user", user_dir)]:
        if not folder.is_dir():
            continue
        for f in sorted(folder.glob("*.desktop")):
            try:
                d = parse_desktop(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            exe, _ = parse_command(d.get("Exec", "").split("%")[0].strip() or None)
            prev = found.get(f.name)
            found[f.name] = {          # a user file with the same name overrides the system one (XDG spec)
                "id": item_id("xdg_autostart", "autostart", f.name), "source": "xdg_autostart",
                "name": d.get("Name") or f.stem, "command": d.get("Exec"), "path": exe,
                "location": str(folder), "scope": prev["scope"] if prev else scope,
                "enabled": _desktop_enabled(d), "can_toggle": True, "requires_admin": False,
                "file": str(f), "overrides_system": bool(prev),
                "_toggle": {"kind": "xdg", "file": str(f), "name": f.name, "user_dir": str(user_dir),
                            "system_file": prev["file"] if prev else (str(f) if scope == "machine" else None)},
            }
    return list(found.values())


def _systemd_items() -> list[dict]:
    out = run_cmd(["systemctl", "list-unit-files", "--type=service", "--state=enabled,disabled",
                   "--no-legend", "--no-pager"], timeout=6)
    items = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].endswith(".service") or "@" in parts[0]:
            continue
        items.append({"id": item_id("systemd", "system", parts[0]), "source": "systemd", "name": parts[0],
                      "command": None, "path": None, "location": "systemd (system)", "scope": "machine",
                      "enabled": parts[1] == "enabled", "can_toggle": False, "requires_admin": True,
                      "protected_reason": "Manage system services with systemctl as root"})
    return items


def _cron_items() -> list[dict]:
    out = run_cmd(["crontab", "-l"], timeout=4)
    items = []
    for line in (out or "").splitlines():
        s = line.strip()
        if s.startswith("@reboot"):
            cmd = s[len("@reboot"):].strip()
            exe, _ = parse_command(cmd)
            items.append({"id": item_id("cron", "crontab", cmd), "source": "cron",
                          "name": os.path.basename(exe or cmd)[:80], "command": cmd, "path": exe,
                          "location": "user crontab", "scope": "user", "enabled": True,
                          "can_toggle": False, "requires_admin": False,
                          "protected_reason": "Edit with crontab -e"})
    return items


# ============================================================ service
class StartupService:
    def __init__(self, db: Database, signatures: SignatureService, activity, settings=None):
        self.db, self.sigs, self.activity, self.settings = db, signatures, activity, settings
        self.failed_sources = 0

    # ------------------------------------------------------------ collect
    def _collect(self, include_services: bool, include_microsoft_tasks: bool, include_manual: bool) -> list[dict]:
        items: list[dict] = []
        collectors = []
        if IS_WINDOWS:                                    # pragma: no cover
            collectors += [_win_registry, _win_startup_folder, lambda: _win_tasks(include_microsoft_tasks)]
            if include_services:
                collectors.append(lambda: _win_services(include_manual))
        else:
            collectors += [_xdg_items, _cron_items]
            if include_services and IS_LINUX:
                collectors.append(_systemd_items)
        self.failed_sources = 0
        for fn in collectors:
            try:
                items += fn()
            except Exception as e:                        # one broken source must not hide the others
                self.failed_sources += 1
                log.warning("Startup source failed: %s", e)
        return items

    def scan(self, include_services: bool = True, include_microsoft_tasks: bool = False,
             include_manual: bool = False, with_signatures: bool = True, use_cache: bool = True) -> list[dict]:
        key = f"startup:{include_services}:{include_microsoft_tasks}:{include_manual}:{with_signatures}"
        fn = lambda: self._scan(include_services, include_microsoft_tasks, include_manual, with_signatures)  # noqa: E731
        if not use_cache:
            CACHE.clear_key(key)
        return CACHE.get(key, 20.0, fn)

    def _scan(self, include_services: bool, include_microsoft_tasks: bool, include_manual: bool,
              with_signatures: bool) -> list[dict]:
        self.ensure_baseline()
        items = self._collect(include_services, include_microsoft_tasks, include_manual)
        sigs = {}
        if self.settings is not None and not self.settings.get("process_signature_check"):
            with_signatures = False
        if with_signatures and IS_WINDOWS:               # pragma: no cover
            sigs = self.sigs.check_many([i["path"] for i in items if i.get("path")])
        seen = self._track(items)
        for it in items:
            p = it.get("path")
            it["file_exists"] = bool(p) and os.path.exists(p)
            sig = sigs.get(p) if p else None
            it["signature"] = ({"status": sig["status"], "publisher": sig.get("publisher")} if sig else None)
            it["publisher"] = (sig or {}).get("publisher")
            flags = tf.path_flags(p) + tf.command_flags(it.get("command")) + _sig_status_flags(it)
            if p and not it["file_exists"] and (os.path.isabs(p) or "\\" in p):
                flags.append("missing_file")
            if tf.is_masquerading(os.path.basename((p or "").replace("\\", "/")), p):
                flags.append("masquerade")
            s = seen.get(it["id"], {})
            it["first_seen"] = s.get("first_seen")
            it["is_new"] = not s.get("accepted", 1)
            if it["is_new"]:
                flags.append("new_item")
            it.update(tf.score(flags))
            it["source_label"] = SOURCES.get(it["source"], it["source"])
            it.setdefault("protected_reason", None)
        return items

    @staticmethod
    def public(item: dict) -> dict:
        return {k: v for k, v in item.items() if not k.startswith("_")}

    # ------------------------------------------------------------ list / summary
    def list(self, source: str | None = None, state: str = "all", flagged_only: bool = False,
             search: str | None = None, include_services: bool = True, include_microsoft_tasks: bool = False,
             include_manual: bool = False, refresh: bool = False) -> dict:
        items = self.scan(include_services, include_microsoft_tasks, include_manual, use_cache=not refresh)
        rows = items
        if source:
            rows = [i for i in rows if i["source"] == source]
        if state in ("enabled", "disabled"):
            rows = [i for i in rows if i["enabled"] == (state == "enabled")]
        elif state == "new":
            rows = [i for i in rows if i["is_new"]]
        if flagged_only:
            rows = [i for i in rows if i["flags"] and i["flags"] != ["new_item"]]
        if search:
            s = search.lower()
            rows = [i for i in rows if s in (i["name"] or "").lower() or s in (i.get("command") or "").lower()
                    or s in (i.get("publisher") or "").lower()]
        rows = sorted(rows, key=lambda i: (-i["risk_score"], i["source"], (i["name"] or "").lower()))
        return {"total": len(rows), "summary": self.summary(items), "items": [self.public(i) for i in rows]}

    @staticmethod
    def summary(items: list[dict]) -> dict:
        by_source: dict[str, dict] = {}
        for i in items:
            b = by_source.setdefault(i["source"], {"label": SOURCES.get(i["source"], i["source"]),
                                                   "total": 0, "enabled": 0, "disabled": 0})
            b["total"] += 1
            b["enabled" if i["enabled"] else "disabled"] += 1
        risk = {"none": 0, "low": 0, "medium": 0, "high": 0}
        for i in items:
            risk[i["risk_level"]] += 1
        programs = [i for i in items if i["source"] not in ("service", "systemd")]
        return {
            "total": len(items), "enabled": sum(1 for i in items if i["enabled"]),
            "disabled": sum(1 for i in items if not i["enabled"]),
            "startup_programs_enabled": sum(1 for i in programs if i["enabled"]),
            "new": sum(1 for i in items if i["is_new"]),
            "flagged": sum(1 for i in items if i["flags"] and i["flags"] != ["new_item"]),
            "unsigned": sum(1 for i in items if (i.get("signature") or {}).get("status") == "unsigned"),
            "by_source": by_source, "by_risk": risk,
        }

    def get(self, iid: str, refresh: bool = True) -> dict:
        for it in self.scan(*FULL, use_cache=not refresh):      # full profile = superset of every list
            if it["id"] == iid:
                return it
        raise StartupError(404, "Startup item not found - refresh the list")

    # ------------------------------------------------------------ enable / disable
    def set_enabled(self, iid: str, enabled: bool, username: str) -> dict:
        it = self.get(iid)
        if not it["can_toggle"]:
            raise StartupError(403, it.get("protected_reason") or "This item cannot be changed from Cyber Hub")
        if it["enabled"] == enabled:
            return self.public(it) | {"changed": False}
        t = it["_toggle"]
        previous = {"enabled": it["enabled"], "start_type": it.get("start_type")}
        if t["kind"] == "approved":                        # pragma: no cover - Windows
            try:
                _approved_write(_HIVES[t["hive"]], t["sub"], t["value"], enabled)
            except PermissionError:
                raise StartupError(403, "Administrator rights needed for machine-wide startup items")
            except OSError as e:
                raise StartupError(500, f"Registry write failed: {e}")
        elif t["kind"] == "service":                       # pragma: no cover - Windows
            name = t["name"]
            if not SERVICE_NAME_RE.match(name):
                raise StartupError(422, "Invalid service name")
            target = "disabled" if not enabled else self._previous_start_type(iid)
            rc, _, err = run_cmd_full(["sc.exe", "config", name, "start=", target], timeout=15)
            if rc != 0:
                raise StartupError(403 if rc == 5 or "denied" in err.lower() else 500,
                                   "Access denied - run Cyber Hub as administrator" if rc == 5
                                   else f"sc.exe failed: {err.strip() or rc}")
        elif t["kind"] == "task":                          # pragma: no cover - Windows
            if not TASK_PATH_RE.match(t["name"]):
                raise StartupError(422, "Invalid task name")
            rc, _, err = run_cmd_full(["schtasks.exe", "/Change", "/TN", t["name"],
                                       "/ENABLE" if enabled else "/DISABLE"], timeout=20)
            if rc != 0:
                raise StartupError(403 if "denied" in err.lower() else 500,
                                   "Access denied - run Cyber Hub as administrator" if "denied" in err.lower()
                                   else f"schtasks failed: {err.strip() or rc}")
        elif t["kind"] == "xdg":
            self._xdg_toggle(t, enabled)
        else:
            raise StartupError(403, "This item cannot be changed from Cyber Hub")

        self.db.execute(
            "INSERT INTO startup_changes(item_id, source, name, action, previous, username) VALUES (?,?,?,?,?,?)",
            (iid, it["source"], it["name"], "enable" if enabled else "disable", json.dumps(previous), username))
        self.activity.record("startup", f"Startup item {'enabled' if enabled else 'disabled'}: {it['name']}",
                             f"{SOURCES.get(it['source'], it['source'])} - {it.get('command') or ''}"[:500],
                             "low", source="startup")
        CACHE.clear_prefix("startup:")
        fresh = self.get(iid)
        return self.public(fresh) | {"changed": True}

    def _previous_start_type(self, iid: str) -> str:
        row = self.db.fetchone("SELECT previous FROM startup_changes WHERE item_id=? AND action='disable' "
                               "ORDER BY id DESC LIMIT 1", (iid,))
        prev = json.loads(row["previous"]).get("start_type") if row else None
        return {"manual": "demand", "automatic": "auto"}.get(prev or "", "auto")

    @staticmethod
    def _xdg_toggle(t: dict, enabled: bool) -> None:
        f = Path(t["file"])
        user_dir = Path(t["user_dir"])
        try:
            if f.parent.resolve() == user_dir.resolve():
                f.write_text(set_desktop_hidden(f.read_text(encoding="utf-8", errors="replace"), not enabled),
                             encoding="utf-8")
            else:                                          # system entry -> per-user override file (XDG way)
                user_dir.mkdir(parents=True, exist_ok=True)
                override = user_dir / t["name"]
                override.write_text(set_desktop_hidden(f.read_text(encoding="utf-8", errors="replace"),
                                                       not enabled), encoding="utf-8")
        except PermissionError:
            raise StartupError(403, "Permission denied writing the autostart file")
        except OSError as e:
            raise StartupError(500, f"Could not update autostart file: {e}")

    def changes(self, limit: int = 50) -> list[dict]:
        rows = self.db.fetchall("SELECT * FROM startup_changes ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["previous"] = json.loads(r["previous"]) if r["previous"] else None
        return rows

    # ------------------------------------------------------------ persistence watch
    def ensure_baseline(self) -> None:
        """The very first full scan becomes the trusted baseline, so existing
        entries never show up as NEW - only things added afterwards do."""
        if self.db.fetchone("SELECT 1 AS x FROM startup_seen LIMIT 1"):
            return
        items = self._collect(*FULL)
        with self.db.tx() as c:
            for it in items:
                c.execute("INSERT OR IGNORE INTO startup_seen(id, source, name, command, accepted) "
                          "VALUES (?,?,?,?,1)", (it["id"], it["source"], it["name"], it.get("command")))
            if not items:                                  # empty machine: still mark the baseline as taken
                c.execute("INSERT OR IGNORE INTO startup_seen(id, source, name, accepted, removed_at) "
                          "VALUES ('__baseline__', 'baseline', 'baseline', 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
        log.info("Startup baseline recorded: %d item(s)", len(items))

    def _track(self, items: list[dict]) -> dict[str, dict]:
        """Remember every item ever seen; anything not in the baseline is NEW until accepted."""
        with self.db.tx() as c:
            for it in items:
                c.execute(
                    "INSERT INTO startup_seen(id, source, name, command, accepted) VALUES (?,?,?,?,0) "
                    "ON CONFLICT(id) DO UPDATE SET last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
                    "removed_at=NULL, command=excluded.command, name=excluded.name",
                    (it["id"], it["source"], it["name"], it.get("command")))
        rows = self.db.fetchall("SELECT id, first_seen, accepted FROM startup_seen")
        return {r["id"]: r for r in rows}

    def watch_once(self) -> dict:
        """Full rescan: alert once per new item, note removed ones."""
        items = self.scan(*FULL, use_cache=False)
        current = {i["id"]: i for i in items}
        new_alerts = []
        for r in self.db.fetchall("SELECT id FROM startup_seen WHERE accepted=0 AND alerted_at IS NULL"):
            it = current.get(r["id"])
            if not it:
                continue
            sev = "high" if it["risk_level"] == "high" else "medium"
            self.activity.record("startup", f"New startup item: {it['name']}",
                                 f"{SOURCES.get(it['source'], it['source'])} - {it.get('command') or ''}"[:500],
                                 sev, source="startup-watch")
            self.db.execute("UPDATE startup_seen SET alerted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                            (r["id"],))
            new_alerts.append(self.public(it))
        removed = []
        if not self.failed_sources:                        # a failing source must not look like mass removal
            for r in self.db.fetchall("SELECT id, name FROM startup_seen WHERE removed_at IS NULL "
                                      "AND source != 'baseline'"):
                if r["id"] not in current:
                    self.db.execute("UPDATE startup_seen SET removed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                                    "WHERE id=?", (r["id"],))
                    removed.append(r["name"])
        if removed:
            self.activity.record("startup", f"{len(removed)} startup item(s) removed", ", ".join(removed)[:500],
                                 source="startup-watch")
        return {"checked": len(items), "new": new_alerts, "removed": removed}

    def accept(self, iid: str | None = None) -> int:
        """Mark one item (or all) as reviewed - clears the NEW badge."""
        if iid:
            n = self.db.execute("UPDATE startup_seen SET accepted=1 WHERE id=?", (iid,)).rowcount
        else:
            n = self.db.execute("UPDATE startup_seen SET accepted=1 WHERE accepted=0").rowcount
        CACHE.clear_prefix("startup:")
        return n


async def watch_loop(svc: StartupService, settings) -> None:
    log.info("Startup persistence watch started")
    await asyncio.sleep(15)                                # let the engine settle first
    while True:
        try:
            if settings.get("startup_watch_enabled"):
                await asyncio.to_thread(svc.watch_once)
        except Exception as e:                             # never let the loop die
            log.warning("Startup watch failed: %s", e)
        await asyncio.sleep(settings.get("startup_watch_interval_minutes") * 60)
