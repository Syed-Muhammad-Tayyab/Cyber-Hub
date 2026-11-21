"""
Cyber Hub Backend - Safe clipboard (Part 12)
Developed by Syed Muhammad Tayyab

"Copy password" puts the secret on the OS clipboard and wipes it again after
N seconds - but only if it is still our text, so whatever you copied later
is never lost.

Windows: the copy is marked with the documented formats
ExcludeClipboardContentFromMonitorProcessing, CanIncludeInClipboardHistory = 0
and CanUploadToCloudClipboard = 0, so it never lands in Win+V clipboard history
or the cloud clipboard synced to your other devices.
Linux: wl-copy / xclip / xsel when installed. Elsewhere the API answers 501
and the UI falls back to the browser clipboard.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time

from ..logger import get_logger
from .platform_tools import IS_WINDOWS

log = get_logger("clipboard")


class ClipboardError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class MemoryClipboard:
    """Test / developer backend (CYBERHUB_CLIPBOARD_BACKEND=memory)."""
    name = "memory"

    def __init__(self):
        self.text: str | None = None
        self.seq = 0
        self.history_excluded = True

    def available(self) -> tuple[bool, str]:
        return True, ""

    def copy(self, text: str) -> int:
        self.text, self.seq = text, self.seq + 1
        return self.seq

    def clear_if(self, marker: int, text: str) -> bool:
        if self.seq == marker and self.text == text:
            self.text, self.seq = None, self.seq + 1
            return True
        return False


class NoClipboard:
    name = "none"

    def __init__(self, reason: str):
        self.reason = reason

    def available(self) -> tuple[bool, str]:
        return False, self.reason

    def copy(self, text: str) -> int:
        raise ClipboardError(501, self.reason)

    def clear_if(self, marker: int, text: str) -> bool:
        return False


class CommandClipboard:                                                   # pragma: no cover - needs a desktop
    """wl-copy / xclip / xsel. Clears only if a paste tool confirms the text is still ours."""
    name = "command"

    def __init__(self, copy_cmd: list[str], paste_cmd: list[str] | None):
        self.copy_cmd, self.paste_cmd = copy_cmd, paste_cmd

    def available(self) -> tuple[bool, str]:
        return True, ""

    def copy(self, text: str) -> int:
        try:
            subprocess.run(self.copy_cmd, input=text.encode(), timeout=5, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as e:
            raise ClipboardError(501, f"Clipboard tool failed: {type(e).__name__}") from e
        return int(time.monotonic() * 1000)

    def clear_if(self, marker: int, text: str) -> bool:
        if not self.paste_cmd:
            return False
        try:
            cur = subprocess.run(self.paste_cmd, capture_output=True, timeout=5).stdout.decode(errors="replace")
            if cur.rstrip("\n") != text:
                return False
            subprocess.run(self.copy_cmd, input=b"", timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (OSError, subprocess.SubprocessError):
            return False


class WindowsClipboard:                                                   # pragma: no cover - Windows only
    name = "windows"

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ct, self.wt = ctypes, wintypes
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.OpenClipboard.argtypes = [wintypes.HWND]; u32.OpenClipboard.restype = wintypes.BOOL
        u32.CloseClipboard.argtypes = []; u32.CloseClipboard.restype = wintypes.BOOL
        u32.EmptyClipboard.argtypes = []; u32.EmptyClipboard.restype = wintypes.BOOL
        u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]; u32.SetClipboardData.restype = wintypes.HANDLE
        u32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]; u32.RegisterClipboardFormatW.restype = wintypes.UINT
        u32.GetClipboardSequenceNumber.argtypes = []; u32.GetClipboardSequenceNumber.restype = wintypes.DWORD
        u32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                        wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
        u32.CreateWindowExW.restype = wintypes.HWND
        u32.DestroyWindow.argtypes = [wintypes.HWND]; u32.DestroyWindow.restype = wintypes.BOOL
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]; k32.GlobalAlloc.restype = wintypes.HGLOBAL
        k32.GlobalLock.argtypes = [wintypes.HGLOBAL]; k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]; k32.GlobalUnlock.restype = wintypes.BOOL
        k32.GlobalFree.argtypes = [wintypes.HGLOBAL]; k32.GlobalFree.restype = wintypes.HGLOBAL
        self.u32, self.k32 = u32, k32
        self._lock = threading.Lock()

    def available(self) -> tuple[bool, str]:
        return True, ""

    def _alloc(self, data: bytes):
        h = self.k32.GlobalAlloc(0x0002, len(data))            # GMEM_MOVEABLE
        if not h:
            raise ClipboardError(500, "Out of memory for the clipboard")
        p = self.k32.GlobalLock(h)
        self.ct.memmove(p, data, len(data))
        self.k32.GlobalUnlock(h)
        return h

    def _open(self, hwnd) -> None:
        for _ in range(25):                                    # another program may hold it for a moment
            if self.u32.OpenClipboard(hwnd):
                return
            time.sleep(0.02)
        raise ClipboardError(409, "The clipboard is busy - try again")

    def _set(self, fmt: int, data: bytes) -> None:
        h = self._alloc(data)
        if not self.u32.SetClipboardData(fmt, h):              # on success Windows owns the memory
            self.k32.GlobalFree(h)
            raise ClipboardError(500, "Windows refused the clipboard data")

    def copy(self, text: str) -> int:
        with self._lock:
            hwnd = self.u32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None)
            try:
                self._open(hwnd)
                try:
                    self.u32.EmptyClipboard()
                    self._set(13, text.encode("utf-16-le") + b"\0\0")                     # CF_UNICODETEXT
                    zero = (0).to_bytes(4, "little")
                    for name in ("ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory",
                                 "CanUploadToCloudClipboard"):
                        fmt = self.u32.RegisterClipboardFormatW(name)
                        if fmt:
                            self._set(fmt, zero)
                finally:
                    self.u32.CloseClipboard()
            finally:
                if hwnd:
                    self.u32.DestroyWindow(hwnd)
            return int(self.u32.GetClipboardSequenceNumber())

    def clear_if(self, marker: int, text: str) -> bool:
        with self._lock:
            if int(self.u32.GetClipboardSequenceNumber()) != marker:
                return False                                   # something else was copied since - leave it
            hwnd = self.u32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None)
            try:
                self._open(hwnd)
                try:
                    self.u32.EmptyClipboard()
                finally:
                    self.u32.CloseClipboard()
            finally:
                if hwnd:
                    self.u32.DestroyWindow(hwnd)
            return True


def pick_clipboard():
    forced = os.environ.get("CYBERHUB_CLIPBOARD_BACKEND", "").lower()
    if forced == "memory":
        return MemoryClipboard()
    if forced == "none":
        return NoClipboard("Clipboard disabled (CYBERHUB_CLIPBOARD_BACKEND=none)")
    if IS_WINDOWS:                                                        # pragma: no cover
        try:
            return WindowsClipboard()
        except Exception as e:
            return NoClipboard(f"Windows clipboard unavailable: {e}")
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):    # pragma: no cover
        return CommandClipboard(["wl-copy"], ["wl-paste", "-n"] if shutil.which("wl-paste") else None)
    if os.environ.get("DISPLAY"):                                         # pragma: no cover
        if shutil.which("xclip"):
            return CommandClipboard(["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"])
        if shutil.which("xsel"):
            return CommandClipboard(["xsel", "-ib"], ["xsel", "-ob"])
    return NoClipboard("No system clipboard here - copy from the app instead")


class ClipboardManager:
    """Copy + timed wipe. One pending wipe at a time (a new copy replaces the old one)."""

    def __init__(self, backend=None):
        self.backend = backend or pick_clipboard()
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._pending: tuple[int, str] | None = None

    def status(self) -> dict:
        ok, why = self.backend.available()
        return {"available": ok, "backend": self.backend.name, "reason": why or None,
                "pending_clear": self._pending is not None}

    def copy(self, text: str, clear_after: int) -> dict:
        marker = self.backend.copy(text)
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._pending, self._timer = (marker, text), None
            if clear_after > 0:
                self._timer = threading.Timer(clear_after, self.clear_now)
                self._timer.daemon = True
                self._timer.start()
        return {"copied": True, "backend": self.backend.name, "clears_in": clear_after or None}

    def clear_now(self) -> bool:
        with self._lock:
            pending, self._pending = self._pending, None
            if self._timer:
                self._timer.cancel()
                self._timer = None
        if not pending:
            return False
        try:
            return self.backend.clear_if(*pending)
        except ClipboardError as e:                                       # pragma: no cover
            log.warning("Clipboard wipe failed: %s", e.message)
            return False

    def shutdown(self) -> None:
        self.clear_now()                                                  # never leave a password behind on exit
