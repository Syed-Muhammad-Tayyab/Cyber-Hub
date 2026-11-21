"""
Cyber Hub Backend - Lightweight risk flags for processes & startup items (Part 4)
Developed by Syed Muhammad Tayyab

Simple, explainable red flags commonly seen with malware persistence:
programs running from Temp/Downloads, Windows system names running from the
wrong folder, script hosts launched by Office, encoded PowerShell, hidden
windows, missing or unsigned binaries. Each flag carries a weight; the sum
becomes a 0-100 risk score and a level the UI can colour.
Part 8 builds the full rules engine (YARA + heuristics) on top of this.
"""
from __future__ import annotations

import os
import re

# flag -> (weight, human explanation)
FLAGS: dict[str, tuple[int, str]] = {
    "suspicious_location": (35, "Runs from a temporary, downloads or public folder"),
    "masquerade":          (60, "Uses a Windows system process name but runs from the wrong folder"),
    "office_child_shell":  (55, "Command shell / script host started by an Office or PDF app"),
    "encoded_command":     (50, "Encoded or obfuscated command line (e.g. PowerShell -EncodedCommand)"),
    "hidden_window":       (20, "Asks for a hidden window"),
    "script_launcher":     (20, "Launched through a script host or LOLBin (powershell, mshta, rundll32...)"),
    "missing_file":        (15, "The program file no longer exists on disk"),
    "unsigned":            (25, "Program file is not digitally signed"),
    "bad_signature":       (60, "Signature is invalid or the file was modified after signing"),
    "new_item":            (10, "Appeared since you last reviewed the startup list"),
}

SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe",
    "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
    "lsm.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "searchindexer.exe",
}
WINDOWS_DIR_NAMES = {"explorer.exe"}         # live directly in C:\Windows
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
                "installutil.exe", "powershell", "pwsh", "bash", "sh", "python", "python3", "perl"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                  "mspub.exe", "onenote.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe",
                  "foxitpdfreader.exe"}

_SUSPICIOUS_DIRS = re.compile(
    r"(\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\|\\users\\public\\|\\\$recycle\.bin\\"
    r"|\\programdata\\[^\\]+\.exe$|^/tmp/|^/var/tmp/|^/dev/shm/|/downloads/)",
    re.IGNORECASE,
)
_ENCODED = re.compile(
    r"(\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|\bIEX\b|invoke-expression"
    r"|downloadstring|base64\s+-d)",
    re.IGNORECASE,
)
_HIDDEN = re.compile(r"(-w(indowstyle)?\s+h(idden)?\b|\bvbhide\b|/min\b)", re.IGNORECASE)


def path_flags(path: str | None) -> list[str]:
    """Checks both the POSIX form and the backslash form of the path."""
    if not path:
        return []
    p = path.lower()
    hit = _SUSPICIOUS_DIRS.search(p) or _SUSPICIOUS_DIRS.search(p.replace("/", "\\"))
    return ["suspicious_location"] if hit else []


def is_masquerading(name: str | None, path: str | None) -> bool:
    """A Windows system process name running from outside System32 / SysWOW64 / Windows."""
    if not name or not path:
        return False
    n = name.lower()
    p = path.replace("/", "\\").lower()
    windir = (os.environ.get("SystemRoot") or r"C:\Windows").lower().rstrip("\\")
    folder = p.rsplit("\\", 1)[0] if "\\" in p else ""
    if n in SYSTEM_NAMES:
        return folder not in (windir + r"\system32", windir + r"\syswow64") and not folder.startswith(windir + r"\winsxs")
    if n in WINDOWS_DIR_NAMES:
        return folder != windir
    return False


def command_flags(command: str | None) -> list[str]:
    if not command:
        return []
    out = []
    if _ENCODED.search(" " + command):
        out.append("encoded_command")
    if _HIDDEN.search(command):
        out.append("hidden_window")
    first = command.strip().strip('"').split('"')[0].split()[0] if command.strip() else ""
    if os.path.basename(first.replace("\\", "/")).lower() in SCRIPT_HOSTS:
        out.append("script_launcher")
    return out


def signature_flags(sig: dict | None) -> list[str]:
    if not sig:
        return []
    st = sig.get("status")
    if st == "unsigned":
        return ["unsigned"]
    if st in ("tampered", "untrusted"):
        return ["bad_signature"]
    return []


def score(flags: list[str]) -> dict:
    flags = list(dict.fromkeys(flags))
    total = min(100, sum(FLAGS[f][0] for f in flags if f in FLAGS))
    level = ("high" if total >= 60 else "medium" if total >= 30 else "low" if total > 0 else "none")
    return {"flags": flags, "risk_score": total, "risk_level": level,
            "reasons": [FLAGS[f][1] for f in flags if f in FLAGS]}
