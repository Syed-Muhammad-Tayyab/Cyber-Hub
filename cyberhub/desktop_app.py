"""
Cyber Hub - Desktop application shell (Part 20)
Developed by Syed Muhammad Tayyab

Turns the engine + UI into one desktop program:

    CyberHub.exe / CyberHub.pyw
        |- starts the security engine on 127.0.0.1 (same process, background thread)
        |- opens the UI in its own window (Microsoft Edge WebView2 through pywebview) - no browser, no address bar
        |- tray icon: Open, Quick scan, Pause protection 15 min, Quit
        |- closing the window keeps protection running in the tray (setting: minimize_to_tray)
        `- a second start just brings the running window to the front (one engine per user)

Options
    --minimized     start in the tray (used by "Start with Windows")
    --browser       use the default web browser instead of the built-in window
    --server-only   engine only, no window, no tray (same as run.py)
    --port N        use another port (default 8765; a free one is picked when it is taken by another program)
    --no-tray       no tray icon (closing the window quits)

Everything degrades instead of failing: no pywebview -> the default browser is used; no pystray / Pillow -> no
tray icon; nothing here is needed by the engine itself.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

APP_TITLE = "Cyber Hub"


def _fix_std_streams() -> None:
    """A windowed .exe has no console: give libraries that print something harmless to write to."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))   # noqa: SIM115 - lives as long as the app


def _http(url: str, method: str = "GET", headers: dict | None = None, timeout: float = 1.5) -> dict | None:
    try:
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=b"" if method == "POST" else None)
        with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - fixed loopback address
            return json.loads(r.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def running_instance(port: int) -> bool:
    j = _http(f"http://127.0.0.1:{port}/api/health")
    return bool(j and j.get("app") == APP_TITLE)


def activate_running(port: int) -> bool:
    """Ask the already-running Cyber Hub to show its window."""
    boot = _http(f"http://127.0.0.1:{port}/api/bootstrap")
    if not boot or "token" not in boot:
        return False
    return _http(f"http://127.0.0.1:{port}/api/desktop/activate", "POST",
                 {"X-CyberHub-Token": boot["token"]}) is not None


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def pick_port(preferred: int) -> int:
    if port_free(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def is_elevated() -> bool:
    try:
        if os.name == "nt":                                          # pragma: no cover - Windows only
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:                                                # pragma: no cover
        return False


class Engine:
    """The FastAPI engine in a background thread of this process."""

    def __init__(self, port: int):
        import uvicorn

        from .config import get_settings
        from .main import create_app
        os.environ["CYBERHUB_PORT"] = str(port)
        self.cfg = get_settings()
        self.port = port
        self.app = create_app(self.cfg)
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=port, log_level="warning",
                                                    log_config=None, access_log=False))
        self.thread = threading.Thread(target=self.server.run, name="cyberhub-engine", daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def start(self, timeout: float = 60.0) -> bool:
        self.thread.start()
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.server.started:
                return True
            if not self.thread.is_alive():
                return False
            time.sleep(0.05)
        return False

    def stop(self, timeout: float = 20.0) -> None:
        self.server.should_exit = True
        self.thread.join(timeout)

    def state(self):
        return self.app.state


class Shell:
    def __init__(self, engine: Engine, args: argparse.Namespace):
        self.engine, self.args = engine, args
        self.window = None
        self.tray = None
        self.webview = None
        self.quitting = threading.Event()
        self.restart_after = False
        self.restart_elevated = False

    # ------------------------------------------------------------ hooks called by the engine (any thread)
    def show(self) -> None:
        if self.window is not None:
            try:
                self.window.show()
                self.window.restore()
            except Exception:                                        # pragma: no cover
                pass
        else:
            webbrowser.open(self.engine.url)

    def quit(self) -> None:
        self.quitting.set()
        threading.Thread(target=self._close_ui, daemon=True).start()

    def restart(self, elevated: bool = False) -> None:
        self.restart_after, self.restart_elevated = True, bool(elevated)
        self.quit()

    def _close_ui(self) -> None:
        time.sleep(0.3)                                              # let the HTTP answer leave first
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:                                        # pragma: no cover
                pass
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception:                                        # pragma: no cover
                pass

    def pick(self, kind: str, title: str, multiple: bool) -> list[str]:
        wv = self.webview
        if wv is None or self.window is None:
            raise RuntimeError("no window")
        fd = getattr(wv, "FileDialog", None)
        if fd is not None:
            dlg = {"folder": fd.FOLDER, "file": fd.OPEN, "save": fd.SAVE}[kind]
        else:                                                        # pywebview < 5.4
            dlg = {"folder": wv.FOLDER_DIALOG, "file": wv.OPEN_DIALOG, "save": wv.SAVE_DIALOG}[kind]
        res = self.window.create_file_dialog(dlg, allow_multiple=bool(multiple) and kind == "file")
        if not res:
            return []
        return [res] if isinstance(res, str) else [str(p) for p in res]

    def toast(self, payload: dict) -> bool:
        if self.tray is None or not getattr(self.tray, "HAS_NOTIFICATION", False):
            return False
        try:
            self.tray.notify(str(payload.get("body") or "")[:250] or " ", str(payload.get("title") or APP_TITLE)[:60])
            return True
        except Exception:
            return False

    def register_hooks(self) -> None:
        from .services import desktop
        desktop.SHELL_HOOKS.update({"show": self.show, "quit": self.quit, "restart": self.restart})
        desktop.SHELL_INFO.update({"elevated": is_elevated()})

    # ------------------------------------------------------------ tray
    def _icon_image(self):
        from PIL import Image, ImageDraw
        for cand in (self.engine.cfg.ui_dir / "assets" / "icon.png",):
            if cand.is_file():
                try:
                    return Image.open(cand).convert("RGBA")
                except OSError:
                    pass
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))               # fallback: a simple blue shield
        d = ImageDraw.Draw(img)
        d.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=(37, 99, 235, 255))
        d.line([(20, 32), (29, 42), (45, 22)], fill=(255, 255, 255, 255), width=6)
        return img

    def _setting(self, key: str, default=None):
        try:
            return self.engine.state().settings_store.get(key)
        except Exception:
            return default

    def start_tray(self) -> bool:
        if self.args.no_tray:
            return False
        try:
            import pystray
        except Exception:                                            # not installed / no desktop session
            return False
        st = self.engine.state

        def quick_scan(_icon=None, _item=None):
            try:
                st().scanner.start("quick", "tray")
            except Exception:
                pass

        def pause(_icon=None, _item=None):
            try:
                st().realtime.pause(15, "tray")
            except Exception:
                pass

        def resume(_icon=None, _item=None):
            try:
                st().realtime.resume("tray")
            except Exception:
                pass

        menu = pystray.Menu(
            pystray.MenuItem("Open Cyber Hub", lambda _i, _m: self.show(), default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Run a quick scan", quick_scan),
            pystray.MenuItem("Pause protection for 15 minutes", pause),
            pystray.MenuItem("Resume protection", resume),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Cyber Hub", lambda _i, _m: self.quit()),
        )
        try:
            self.tray = pystray.Icon("cyberhub", self._icon_image(), "Cyber Hub - protection is running", menu)
            self.tray.run_detached()
        except Exception:                                            # e.g. no system tray on this desktop
            self.tray = None
            return False
        from .services import desktop
        desktop.SHELL_INFO["tray"] = True
        desktop.SHELL_HOOKS["toast"] = self.toast
        try:                                                         # the engine is already up: hand it the hook
            st().notifications.on_toast = self.toast
        except Exception:
            pass
        return True

    # ------------------------------------------------------------ window
    def run_window(self) -> bool:
        """Blocks until the app quits. Returns False when no built-in window is available."""
        try:
            import webview
        except Exception:
            return False
        from .services import desktop
        self.webview = webview
        desktop.SHELL_INFO["shell"] = "pywebview"
        desktop.SHELL_HOOKS["pick"] = self.pick
        self.window = webview.create_window(APP_TITLE, self.engine.url, width=1320, height=860, min_size=(1040, 680),
                                            hidden=bool(self.args.minimized and self.tray is not None),
                                            background_color="#0B1220", text_select=True)

        def on_closing():
            if self.quitting.is_set():
                return True
            if self.tray is not None and self._setting("minimize_to_tray", True):
                self.window.hide()                                   # keep protecting from the tray
                return False
            self.quitting.set()
            return True

        self.window.events.closing += on_closing
        try:                                                         # reports / backups are saved through the page
            webview.settings["ALLOW_DOWNLOADS"] = True
        except Exception:                                            # pragma: no cover - older pywebview
            pass
        try:
            webview.start(private_mode=False, storage_path=str(self.engine.cfg.data_dir / "webview"))
        except Exception as e:                                       # WebView2 runtime missing, no display ...
            print(f"[Cyber Hub] Built-in window unavailable ({e}) - using the web browser", file=sys.stderr)
            self.window = None
            desktop.SHELL_INFO["shell"] = "none"
            desktop.SHELL_HOOKS.pop("pick", None)
            return False
        return True

    def run_browser(self) -> None:
        from .services import desktop
        desktop.SHELL_INFO["shell"] = "browser"
        if not self.args.minimized:
            webbrowser.open(self.engine.url)
        try:
            while not self.quitting.wait(0.5):
                if not self.engine.thread.is_alive():
                    break
        except KeyboardInterrupt:
            pass

    def run(self) -> None:
        self.register_hooks()
        self.start_tray()
        if self.args.browser or not self.run_window():
            if not self.quitting.is_set():
                self.run_browser()
        self.quitting.set()
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:                                        # pragma: no cover
                pass


def relaunch(elevated: bool = False) -> None:
    from .services.desktop import launch_command
    cmd = launch_command(minimized=False)
    if elevated and os.name == "nt":                                 # pragma: no cover - Windows only
        import ctypes
        params = " ".join(f'"{a}"' for a in cmd[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd[0], params, None, 1)
        return
    subprocess.Popen(cmd, close_fds=True)                            # noqa: S603 - our own launcher


def main(argv: list[str] | None = None) -> int:
    _fix_std_streams()
    ap = argparse.ArgumentParser(prog="CyberHub", description="Cyber Hub - developed by Syed Muhammad Tayyab")
    ap.add_argument("--port", type=int, default=int(os.environ.get("CYBERHUB_PORT", "8765")))
    ap.add_argument("--minimized", action="store_true", help="start in the tray")
    ap.add_argument("--browser", action="store_true", help="use the default web browser instead of the app window")
    ap.add_argument("--server-only", action="store_true", help="engine only: no window, no tray")
    ap.add_argument("--no-tray", action="store_true", help="no tray icon")
    args = ap.parse_args(argv)

    if running_instance(args.port):                                  # one engine per user
        if not args.server_only:
            if not activate_running(args.port):
                webbrowser.open(f"http://127.0.0.1:{args.port}/")
        return 0
    port = pick_port(args.port)
    engine = Engine(port)
    if not engine.start():
        print("[Cyber Hub] The engine could not start - see the log in the data folder", file=sys.stderr)
        return 1
    if args.server_only:
        print(f"[Cyber Hub] Engine running on {engine.url} (Ctrl+C to stop)")
        try:
            while engine.thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        engine.stop()
        return 0
    shell = Shell(engine, args)
    try:
        shell.run()
    finally:
        engine.stop()
    if shell.restart_after:
        relaunch(shell.restart_elevated)
    return 0


def _entry() -> None:                                                # console-script style entry
    raise SystemExit(main())


if __name__ == "__main__":
    _entry()

__all__ = ["main", "Engine", "Shell", "running_instance", "pick_port"]
