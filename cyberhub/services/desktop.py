"""
Cyber Hub Backend - Desktop integration (Part 20)
Developed by Syed Muhammad Tayyab

The engine side of the desktop app:

* About          - product name, version, developer, components (shown on the About page and in the installer)
* Run at sign-in - a per-user "Run" entry (HKCU\\...\\CurrentVersion\\Run, no administrator rights needed) that
                   starts Cyber Hub minimised to the tray; on Linux an XDG autostart .desktop file. The
                   `start_with_windows` setting and the real entry are always changed together and status()
                   reports the truth from the registry, so a cleaner tool that removed the entry is noticed.
* Shell hooks    - the window / tray process (cyberhub/desktop_app.py) registers callbacks here: show the
                   window, quit, restart, native file / folder pickers. Without a shell (engine started with
                   run.py and opened in a browser) those calls answer 501 and the UI falls back to typing paths.
"""
from __future__ import annotations

import os
import platform
import shlex
import sys
from pathlib import Path
from typing import Any, Callable

from ..config import APP_NAME, APP_VERSION, BUILD_PART, TOTAL_PARTS
from ..logger import get_logger
from .platform_tools import IS_WINDOWS

log = get_logger("desktop")

DEVELOPER = "Syed Muhammad Tayyab"
ABOUT = {
    "app": APP_NAME,
    "tagline": "Security center for your Windows PC and your online accounts",
    "developer": DEVELOPER,
    "credit": f"Developed by {DEVELOPER}",
    "github": "https://github.com/Syed-Muhammad-Tayyab",
    "location": "Islamabad, Pakistan",
    "copyright": f"© 2026 {DEVELOPER}",
}
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "CyberHub"

# Filled by the desktop shell before the engine starts: show / quit / restart / pick / toast
SHELL_HOOKS: dict[str, Callable[..., Any]] = {}
SHELL_INFO: dict[str, Any] = {"shell": "none", "tray": False}


class DesktopError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _is_elevated() -> bool:
    try:
        if IS_WINDOWS:                                               # pragma: no cover - Windows only
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:                                                # pragma: no cover
        return False


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def project_root() -> Path:
    return Path(sys.executable).resolve().parent if is_frozen() else Path(__file__).resolve().parents[2]


def launch_command(minimized: bool = True) -> list[str]:
    """How Cyber Hub's window is started on this PC."""
    if is_frozen():
        cmd = [str(Path(sys.executable).resolve())]
    else:
        exe = Path(sys.executable)
        if IS_WINDOWS:                                               # pragma: no cover - Windows only
            w = exe.with_name("pythonw.exe")
            exe = w if w.exists() else exe
        cmd = [str(exe), str(project_root() / "CyberHub.pyw")]
    return cmd + (["--minimized"] if minimized else [])


def _quote_windows(args: list[str]) -> str:
    return " ".join(f'"{a}"' if (" " in a or not a) else a for a in args)


# ====================================================================== run-at-sign-in backends
class Autostart:
    name = "none"
    supported = False

    def get(self) -> str | None:
        return None

    def set(self, command: list[str]) -> None:                       # pragma: no cover - interface
        raise DesktopError(501, "Starting with the system isn't supported on this platform")

    def remove(self) -> None:                                        # pragma: no cover - interface
        pass


class WindowsAutostart(Autostart):                                   # pragma: no cover - Windows only
    name = "registry"
    supported = True

    def get(self) -> str | None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
                return str(winreg.QueryValueEx(k, RUN_NAME)[0])
        except OSError:
            return None

    def set(self, command: list[str]) -> None:
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, _quote_windows(command))

    def remove(self) -> None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, RUN_NAME)
        except OSError:
            pass


class LinuxAutostart(Autostart):
    name = "xdg-autostart"
    supported = True

    def __init__(self, folder: Path | None = None):
        base = folder or Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart"
        self.file = Path(base) / "cyberhub.desktop"

    def get(self) -> str | None:
        try:
            for ln in self.file.read_text(encoding="utf-8").splitlines():
                if ln.startswith("Exec="):
                    return ln[5:]
        except OSError:
            pass
        return None

    def set(self, command: list[str]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text("[Desktop Entry]\nType=Application\nName=Cyber Hub\n"
                             f"Comment=Security center - Developed by {DEVELOPER}\n"
                             f"Exec={shlex.join(command)}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
                             encoding="utf-8")

    def remove(self) -> None:
        try:
            self.file.unlink()
        except OSError:
            pass


class MemoryAutostart(Autostart):
    """Tests: nothing is written outside the test."""
    name = "memory"
    supported = True

    def __init__(self):
        self.value: str | None = None

    def get(self) -> str | None:
        return self.value

    def set(self, command: list[str]) -> None:
        self.value = _quote_windows(command)

    def remove(self) -> None:
        self.value = None


def default_autostart(data_dir: Path | None = None) -> Autostart:
    forced = os.environ.get("CYBERHUB_DESKTOP_BACKEND", "").lower()
    if forced == "memory":
        return MemoryAutostart()
    if forced == "file" and data_dir is not None:
        return LinuxAutostart(Path(data_dir) / "autostart")
    if IS_WINDOWS:                                                   # pragma: no cover
        return WindowsAutostart()
    if platform.system() == "Linux":
        return LinuxAutostart()
    return Autostart()


# ====================================================================== service
class DesktopService:
    def __init__(self, settings, activity, data_dir: Path, autostart: Autostart | None = None):
        self.settings, self.activity = settings, activity
        self.data_dir = Path(data_dir)
        self.autostart = autostart or default_autostart(self.data_dir)

    # ---- about
    def about(self, extra: dict | None = None) -> dict:
        out = dict(ABOUT)
        out.update({"version": APP_VERSION, "build_part": BUILD_PART, "total_parts": TOTAL_PARTS,
                    "complete": BUILD_PART >= TOTAL_PARTS, "python": platform.python_version(),
                    "platform": f"{platform.system()} {platform.release()}", "packaged": is_frozen()})
        if extra:
            out["components"] = extra
        return out

    # ---- run at sign-in
    def autostart_status(self) -> dict:
        cur = self.autostart.get() if self.autostart.supported else None
        want = launch_command(True)
        expected = _quote_windows(want) if self.autostart.name in ("registry", "memory") else shlex.join(want)
        return {"supported": self.autostart.supported, "backend": self.autostart.name, "enabled": cur is not None,
                "command": cur, "expected_command": expected,
                "outdated": cur is not None and cur != expected,     # app was moved / updated since it was set
                "setting": bool(self.settings.get("start_with_windows"))}

    def set_autostart(self, enabled: bool, username: str = "system") -> dict:
        if not self.autostart.supported:
            raise DesktopError(501, "Starting with the system isn't supported on this platform")
        try:
            if enabled:
                self.autostart.set(launch_command(True))
            else:
                self.autostart.remove()
        except OSError as e:
            raise DesktopError(500, f"Could not change the start-up entry: {e}")
        self.settings.update({"start_with_windows": bool(enabled)})
        self.activity.record("settings", f"Start with Windows turned {'on' if enabled else 'off'}", f"by {username}",
                             source="desktop")
        return self.autostart_status()

    def sync_autostart(self) -> None:
        """At start-up: keep the entry pointing at this copy of the app when the setting is on."""
        try:
            st = self.autostart_status()
            if st["supported"] and st["setting"] and (not st["enabled"] or st["outdated"]) and SHELL_INFO["shell"] != "none":
                self.autostart.set(launch_command(True))
        except Exception as e:                                       # pragma: no cover
            log.debug("Autostart sync failed: %s", e)

    # ---- shell
    def status(self) -> dict:
        return {"shell": SHELL_INFO.get("shell", "none"), "tray": bool(SHELL_INFO.get("tray")),
                "window": bool(SHELL_HOOKS.get("show")), "packaged": is_frozen(),
                "can_pick_files": "pick" in SHELL_HOOKS, "can_restart": "restart" in SHELL_HOOKS,
                "can_quit": "quit" in SHELL_HOOKS, "autostart": self.autostart_status(),
                "elevated": bool(SHELL_INFO.get("elevated", _is_elevated())),
                "minimize_to_tray": bool(self.settings.get("minimize_to_tray")),
                "data_folder": str(self.data_dir), "version": APP_VERSION}

    def _hook(self, name: str, what: str) -> Callable[..., Any]:
        fn = SHELL_HOOKS.get(name)
        if fn is None:
            raise DesktopError(501, f"{what} needs the Cyber Hub desktop window (this engine was started without it)")
        return fn

    def show(self) -> dict:
        self._hook("show", "Showing the window")()
        return {"shown": True}

    def quit(self, username: str) -> dict:
        fn = self._hook("quit", "Closing Cyber Hub")
        self.activity.record("system", "Cyber Hub closed from the app", f"by {username}", source="desktop")
        fn()
        return {"quitting": True}

    def restart(self, username: str, elevated: bool = False) -> dict:
        fn = self._hook("restart", "Restarting Cyber Hub")
        self.activity.record("system", "Cyber Hub restart requested" + (" (as administrator)" if elevated else ""),
                             f"by {username}", source="desktop")
        fn(bool(elevated))
        return {"restarting": True, "elevated": bool(elevated)}

    def pick(self, kind: str = "folder", title: str | None = None, multiple: bool = False) -> dict:
        if kind not in ("file", "folder", "save"):
            raise DesktopError(422, "kind must be file, folder or save")
        fn = self._hook("pick", "Choosing files")
        try:
            paths = fn(kind, title or "", bool(multiple)) or []
        except Exception as e:
            raise DesktopError(500, f"The file dialog failed: {e}")
        return {"paths": [str(p) for p in paths], "cancelled": not paths}
