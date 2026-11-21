"""
Cyber Hub Backend - Platform helpers (Part 3)
Developed by Syed Muhammad Tayyab

Small, safe wrappers for running fixed PowerShell / command-line queries
(no user input is ever interpolated into a command). Used by the hardware
monitor now and by the firewall / posture modules in later parts.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

from ..logger import get_logger

log = get_logger("platform")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0          # CREATE_NO_WINDOW: no console flash


def run_cmd(args: list[str], timeout: float = 5.0, env: dict[str, str] | None = None) -> str | None:
    """Run a fixed command, return stdout or None on any failure."""
    rc, out, _ = run_cmd_full(args, timeout, env)
    return out if rc == 0 else None


def run_cmd_full(args: list[str], timeout: float = 5.0,
                 env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Run a command as an argument list (never through a shell) and return
    (returncode, stdout, stderr). returncode -1 = could not run at all.
    Part 4: `env` lets callers hand user-chosen values (file paths, task names)
    to PowerShell through environment variables instead of the script text."""
    if not args or not shutil.which(args[0]):
        return -1, "", f"{args[0] if args else '?'} not found"
    full_env = None
    if env:
        full_env = dict(os.environ)
        full_env.update(env)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           creationflags=_NO_WINDOW, env=full_env,
                           encoding="utf-8", errors="replace")
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("Command %s failed: %s", args[0], e)
        return -1, "", str(e)


def powershell_exe() -> str | None:
    if not IS_WINDOWS:
        return None
    return shutil.which("powershell") or shutil.which("pwsh")


def run_powershell_json(script: str, timeout: float = 8.0, env: dict[str, str] | None = None) -> Any:
    """Run a fixed PowerShell script that ends in ConvertTo-Json; return parsed JSON or None.
    Variable input must arrive via `env` ($env:NAME inside the script), never by
    formatting it into `script`."""
    exe = powershell_exe()
    if not exe:
        return None
    out = run_cmd([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-Command", script], timeout=timeout, env=env)
    if not out or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        log.debug("PowerShell returned non-JSON output")
        return None


class TTLCache:
    """Thread-safe cache so slow probes (PowerShell, nvidia-smi) run at most every `ttl` s."""

    def __init__(self):
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._key_locks: dict[str, threading.Lock] = {}

    def get(self, key: str, ttl: float, fn: Callable[[], Any]) -> Any:
        with self._lock:
            hit = self._data.get(key)
            if hit and time.monotonic() - hit[0] < ttl:
                return hit[1]
            klock = self._key_locks.setdefault(key, threading.Lock())
        with klock:                                   # one refresh at a time per key
            with self._lock:
                hit = self._data.get(key)
                if hit and time.monotonic() - hit[0] < ttl:
                    return hit[1]
            value = fn()
            with self._lock:
                self._data[key] = (time.monotonic(), value)
            return value

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def clear_key(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in [k for k in self._data if k.startswith(prefix)]:
                del self._data[k]


CACHE = TTLCache()
