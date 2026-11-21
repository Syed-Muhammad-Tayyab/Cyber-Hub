"""
Cyber Hub Backend - Removable drive detection (Part 7)
Developed by Syed Muhammad Tayyab

list_removable_drives() returns the USB / removable volumes plugged in right
now. Real-time protection polls it every couple of seconds and compares the
result with the previous one to raise "USB inserted / removed" events.

  Windows : psutil partitions flagged "removable" (flash drives, SD cards)
            + fixed letters whose disk BusType is USB (external HDD / SSD),
            looked up once per change of drive letters with a fixed
            PowerShell query. Label + volume serial come from
            GetVolumeInformationW.
  Linux   : /sys/block/<disk>/removable, a /usb/ device path, or a mount
            point under /media or /run/media. Label / UUID from /dev/disk/by-*.

inspect_drive() runs the quick checks done the moment a drive appears:
autorun.inf with a program to start, the "shortcut virus" pattern (hidden
folders + .lnk files in the root) and programs sitting in the root.
"""
from __future__ import annotations

import json
import os
import re
import stat

import psutil

from ..logger import get_logger
from .platform_tools import IS_WINDOWS, powershell_exe, run_cmd

log = get_logger("drives")

ROOT_PROGRAM_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
                    ".hta", ".ps1", ".msi", ".dll", ".cpl", ".jar"}

_usb_letter_cache: tuple[frozenset, dict] = (frozenset(), {})

_PS_USB_LETTERS = (
    "Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { "
    "$d = Get-Disk -Number $_.DiskNumber -ErrorAction SilentlyContinue; "
    "[pscustomobject]@{ l = [string]$_.DriveLetter; b = [string]$d.BusType; m = [string]$d.FriendlyName; "
    "s = ([string]$d.SerialNumber).Trim() } } | ConvertTo-Json -Compress"
)


# ---------------------------------------------------------------- Windows
def _win_volume_info(root: str) -> tuple[str | None, str | None]:          # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes
    label = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    maxlen, flags = wintypes.DWORD(), wintypes.DWORD()
    old = ctypes.windll.kernel32.SetErrorMode(1)            # SEM_FAILCRITICALERRORS: no "insert disk" popups
    try:
        ok = ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(root), label, 261, ctypes.byref(serial),
                                                          ctypes.byref(maxlen), ctypes.byref(flags), fs, 261)
    finally:
        ctypes.windll.kernel32.SetErrorMode(old)
    if not ok:
        return None, None
    return label.value or None, f"{serial.value:08X}"


def _win_usb_letters(fixed_letters: frozenset) -> dict:                    # pragma: no cover - Windows only
    """{'E': {'bus': 'USB', 'model': ..., 'serial': ...}} for fixed drives on a USB bus."""
    global _usb_letter_cache
    if fixed_letters == _usb_letter_cache[0]:
        return _usb_letter_cache[1]
    out: dict = {}
    ps = powershell_exe()
    if ps:
        raw = run_cmd([ps, "-NoProfile", "-NonInteractive", "-Command", _PS_USB_LETTERS], timeout=15)
        try:
            rows = json.loads(raw) if raw and raw.strip() else []
            rows = rows if isinstance(rows, list) else [rows]
            for r in rows:
                if str(r.get("b", "")).upper() in ("USB", "SD", "MMC"):
                    out[str(r["l"]).upper()] = {"bus": r["b"], "model": r.get("m") or None,
                                                "serial": r.get("s") or None}
        except (ValueError, KeyError, TypeError) as e:
            log.debug("BusType query failed: %s", e)
    _usb_letter_cache = (fixed_letters, out)
    return out


def _windows_drives() -> list[dict]:                                       # pragma: no cover - Windows only
    parts = psutil.disk_partitions(all=False)
    fixed = frozenset(p.mountpoint[:1].upper() for p in parts
                      if "fixed" in p.opts and p.mountpoint[:1].upper() not in ("C",))
    usb_fixed = _win_usb_letters(fixed) if fixed else {}
    out = []
    for p in parts:
        letter = p.mountpoint[:1].upper()
        if "cdrom" in p.opts or "remote" in p.opts:
            continue
        info = None
        if "removable" in p.opts:
            info = {"bus": "USB/Removable", "model": None, "serial": None}
        elif letter in usb_fixed:
            info = usb_fixed[letter]
        if info is None:
            continue
        label, vol_serial = _win_volume_info(p.mountpoint)
        if vol_serial is None and not p.fstype:            # card reader with no card inserted
            continue
        out.append(_entry(p.mountpoint, p.device, p.fstype, label, vol_serial or info.get("serial"),
                          info.get("bus"), info.get("model")))
    return out


# ---------------------------------------------------------------- Linux
def _by_link(folder: str, device: str) -> str | None:
    try:
        for name in os.listdir(folder):
            if os.path.realpath(os.path.join(folder, name)) == os.path.realpath(device):
                return name.replace("\\x20", " ")
    except OSError:
        pass
    return None


def _linux_disk(device: str) -> str | None:
    m = re.match(r"/dev/(sd[a-z]+|mmcblk\d+|nvme\d+n\d+|vd[a-z]+)", os.path.realpath(device))
    return m.group(1) if m else None


def _linux_drives() -> list[dict]:
    out = []
    for p in psutil.disk_partitions(all=False):
        disk = _linux_disk(p.device)
        removable, bus = False, None
        if disk:
            try:
                with open(f"/sys/block/{disk}/removable") as f:
                    removable = f.read().strip() == "1"
            except OSError:
                pass
            if "/usb" in os.path.realpath(f"/sys/block/{disk}"):
                removable, bus = True, "USB"
        if p.mountpoint.startswith(("/media/", "/run/media/", "/mnt/usb")):
            removable = True
        if not removable:
            continue
        model = None
        if disk:
            try:
                with open(f"/sys/block/{disk}/device/model") as f:
                    model = f.read().strip() or None
            except OSError:
                pass
        out.append(_entry(p.mountpoint, p.device, p.fstype, _by_link("/dev/disk/by-label", p.device),
                          _by_link("/dev/disk/by-uuid", p.device), bus or "Removable", model))
    return out


# ---------------------------------------------------------------- common
def _entry(mount: str, device: str, fstype: str, label, serial, bus, model) -> dict:
    try:
        total = psutil.disk_usage(mount).total
    except OSError:
        total = None
    key = f"serial:{serial}" if serial else f"vol:{label or '?'}|{total or 0}|{fstype or '?'}"
    return {"mountpoint": mount, "device": device, "fstype": fstype or None, "label": label, "serial": serial,
            "bus": bus, "model": model, "total_bytes": total, "device_key": key}


def list_removable_drives() -> list[dict]:
    try:
        return _windows_drives() if IS_WINDOWS else _linux_drives()
    except Exception as e:                                  # never let drive polling kill the loop
        log.debug("Drive listing failed: %s", e)
        return []


def _hidden(path: str, st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs:
        return bool(attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))   # pragma: no cover
    return os.path.basename(path).startswith(".")


def inspect_drive(mount: str, max_entries: int = 2000) -> list[dict]:
    """Fast checks of the drive root (no recursion). Returns warnings [{code, severity, title, detail}]."""
    warnings: list[dict] = []
    try:
        entries = list(os.scandir(mount))[:max_entries]
    except OSError as e:
        return [{"code": "unreadable", "severity": "low", "title": "Drive could not be read", "detail": str(e)[:200]}]
    names = {e.name.lower(): e for e in entries}
    # 1) autorun.inf that starts a program
    ar = names.get("autorun.inf")
    if ar is not None and ar.is_file(follow_symlinks=False):
        cmd = None
        try:
            with open(ar.path, "r", encoding="utf-8", errors="replace") as f:
                for line in f.read(64 * 1024).splitlines():
                    k, _, v = line.partition("=")
                    if k.strip().lower() in ("open", "shellexecute", "shell\\open\\command", "shell\\explore\\command"):
                        cmd = v.strip()
                        break
        except OSError:
            pass
        warnings.append({"code": "autorun", "severity": "high" if cmd else "medium",
                         "title": "autorun.inf found" + (" that starts a program" if cmd else ""),
                         "detail": f"Starts: {cmd}" if cmd else "Classic USB-worm file. Delete it if you didn't create it.",
                         "path": ar.path})
    # 2) "shortcut virus": real folders hidden, same-named .lnk shortcuts left in their place
    hidden_dirs, lnks = set(), set()
    for e in entries:
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        low = e.name.lower()
        if e.is_dir(follow_symlinks=False) and _hidden(e.path, st) and low not in (
                "system volume information", "$recycle.bin", ".trashes", ".spotlight-v100", ".fseventsd"):
            hidden_dirs.add(low.lstrip(".") or low)          # POSIX hides with a leading dot
        elif low.endswith(".lnk"):
            lnks.add(low[:-4])
    twins = hidden_dirs & lnks
    if twins or (lnks and len(hidden_dirs) >= 1 and len(lnks) >= 3):
        warnings.append({"code": "shortcut_virus", "severity": "high",
                         "title": "Possible shortcut virus",
                         "detail": f"{len(lnks)} shortcut(s) and {len(hidden_dirs)} hidden folder(s) in the drive root"
                                   + (f", e.g. '{sorted(twins)[0]}'" if twins else "")
                                   + ". Don't open the shortcuts - scan the drive."})
    # 3) programs / scripts in the root
    progs = [e.name for e in entries if os.path.splitext(e.name)[1].lower() in ROOT_PROGRAM_EXT
             and e.is_file(follow_symlinks=False)]
    if progs:
        warnings.append({"code": "root_programs", "severity": "medium",
                         "title": f"{len(progs)} program(s) / script(s) in the drive root",
                         "detail": ", ".join(sorted(progs)[:8]) + (" ..." if len(progs) > 8 else "")})
    return warnings
