"""
Cyber Hub Backend - Part 20 tests: Desktop app
Developed by Syed Muhammad Tayyab

* About / run-at-sign-in / shell hooks through the API (in-memory start-up entry, no real registry writes)
* the real desktop launcher: engine in a background thread on a free port, single-instance detection,
  "activate" bringing the running window forward
* the UI is served and every API path the UI (and the frontend bridge) calls exists in the engine
* the build recipe points at files that exist
"""
import json
import re
import socket
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberhub import desktop_app
from cyberhub.config import APP_VERSION, BUILD_PART, TOTAL_PARTS, Settings
from cyberhub.main import create_app
from cyberhub.services import desktop

ROOT = Path(__file__).resolve().parents[1]
PW = "Cyb3r!Hub#2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched", "docs", "home"):
        (tmp_path / d).mkdir()
    for k, v in {"CYBERHUB_DATA_DIR": tmp_path / "data", "CYBERHUB_QUICK_SCAN_DIRS": tmp_path / "quick",
                 "CYBERHUB_FULL_SCAN_ROOTS": tmp_path / "full", "CYBERHUB_AUTOSTART_USER_DIR": tmp_path / "as-user",
                 "CYBERHUB_AUTOSTART_SYSTEM_DIR": tmp_path / "as-sys", "CYBERHUB_RTP_DEFAULT_DIRS": tmp_path / "watched",
                 "CYBERHUB_FIREWALL_BACKEND": "memory", "CYBERHUB_NETWORK_BACKEND": "memory",
                 "CYBERHUB_POSTURE_BACKEND": "memory", "CYBERHUB_CLIPBOARD_BACKEND": "memory",
                 "CYBERHUB_PV_KDF_N": "1024", "CYBERHUB_DP_KDF_N": "1024", "CYBERHUB_CLEANER_HOME": tmp_path / "home",
                 "CYBERHUB_CLEANER_LAYOUT": "linux", "CYBERHUB_FINDER_DEFAULT_DIRS": tmp_path / "docs"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.delenv("CYBERHUB_UI_DIR", raising=False)              # the real ui/ folder
    yield tmp_path
    desktop.SHELL_HOOKS.clear()
    desktop.SHELL_INFO.clear()
    desktop.SHELL_INFO.update({"shell": "none", "tray": False})


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
        cl.headers["X-CyberHub-Session"] = r.json()["session_token"]
        yield cl


def test_complete_and_about(c):
    info = c.get("/api/info").json()
    assert BUILD_PART == TOTAL_PARTS == 20 and APP_VERSION == "1.0.0"
    assert info["progress_percent"] == 100 and "desktop" in info["available_modules"]
    assert all(m.get("available", True) for m in info["modules"])
    a = TestClient(c.app, headers={"X-CyberHub-Token": c.headers["X-CyberHub-Token"]}).get("/api/about").json()
    assert a["developer"] == "Syed Muhammad Tayyab" and a["credit"] == "Developed by Syed Muhammad Tayyab"
    assert a["complete"] is True and a["version"] == "1.0.0" and a["github"].endswith("Syed-Muhammad-Tayyab")
    comp = a["components"]
    assert comp["schema_version"] >= 20 and comp["yara_rules"] >= 20 and comp["toasts"] == "memory"
    assert TestClient(c.app).get("/api/about").status_code == 401           # token still required


def test_autostart_follows_setting_and_entry(c):
    st = c.get("/api/desktop/status").json()
    assert st["shell"] == "none" and st["autostart"]["supported"] and st["autostart"]["backend"] == "memory"
    assert st["autostart"]["enabled"] is False and not st["can_pick_files"] and not st["can_quit"]
    on = c.put("/api/desktop/autostart", json={"enabled": True}).json()
    assert on["enabled"] and on["setting"] and "--minimized" in on["command"] and on["command"] == on["expected_command"]
    assert "CyberHub.pyw" in on["command"]
    assert c.get("/api/settings").json()["start_with_windows"] is True
    # somebody (a "cleaner" tool) removed the entry: status tells the truth
    c.app.state.desktop.autostart.remove()
    st = c.get("/api/desktop/status").json()["autostart"]
    assert st["enabled"] is False and st["setting"] is True
    off = c.put("/api/desktop/autostart", json={"enabled": False}).json()
    assert off["enabled"] is False and off["setting"] is False
    assert any("Start with Windows turned off" in a["title"] for a in c.get("/api/activity?limit=20").json()["items"])


def test_linux_autostart_file(tmp_path):
    a = desktop.LinuxAutostart(tmp_path)
    assert a.get() is None
    a.set(["/opt/cyber hub/CyberHub", "--minimized"])
    text = (tmp_path / "cyberhub.desktop").read_text()
    assert "Developed by Syed Muhammad Tayyab" in text and a.get() == "'/opt/cyber hub/CyberHub' --minimized"
    a.remove()
    assert a.get() is None


def test_shell_hooks(c):
    for path, body in (("/api/desktop/show", None), ("/api/desktop/pick", {"kind": "folder"}),
                       ("/api/desktop/restart", None), ("/api/desktop/quit", None)):
        r = c.post(path, json=body or {})
        assert r.status_code == 501 and "desktop window" in r.json()["detail"]
    calls = []
    desktop.SHELL_HOOKS.update({"show": lambda: calls.append("show"), "quit": lambda: calls.append("quit"),
                                "restart": lambda elevated: calls.append(("restart", elevated)),
                                "pick": lambda kind, title, multiple: [f"C:\\picked\\{kind}"]})
    assert c.post("/api/desktop/show").json() == {"shown": True}
    tok = {"X-CyberHub-Token": c.headers["X-CyberHub-Token"]}
    assert TestClient(c.app).post("/api/desktop/activate", headers=tok).json() == {"shown": True}   # no session needed
    assert c.post("/api/desktop/pick", json={"kind": "file", "title": "Pick"}).json() == {"paths": ["C:\\picked\\file"],
                                                                                          "cancelled": False}
    assert c.post("/api/desktop/pick", json={"kind": "nope"}).status_code == 422
    assert c.post("/api/desktop/restart?elevated=true").json() == {"restarting": True, "elevated": True}
    assert c.post("/api/desktop/quit").status_code == 202
    assert calls == ["show", "show", ("restart", True), "quit"]
    st = c.get("/api/desktop/status").json()
    assert st["can_pick_files"] and st["can_restart"] and st["can_quit"]
    # standard users can't quit / restart the protection
    c.post("/api/account/users", json={"username": "guest", "display_name": "G", "password": "Gu3st!Pass#2026",
                                       "role": "standard"})
    g = TestClient(c.app, headers=tok)
    g.headers["X-CyberHub-Session"] = g.post("/api/account/login", json={"username": "guest",
                                                                       "password": "Gu3st!Pass#2026"}).json()["session_token"]
    assert g.post("/api/desktop/quit").status_code == 403 and g.post("/api/desktop/restart").status_code == 403


def test_tray_toasts_go_through_the_hook(env):
    got = []
    desktop.SHELL_HOOKS["toast"] = lambda p: got.append(p["title"]) or True
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.app.state.notifications.notify("threat", "high", "Shown by the tray")
        cl.app.state.notifications.flush_toasts()
    assert got == ["Shown by the tray"]


def test_ui_is_served_with_author_credit(c):
    page = TestClient(c.app).get("/")
    assert page.status_code == 200 and "Developed by Syed Muhammad Tayyab" in page.text
    for asset in ("assets/app.css", "assets/core.js", "assets/app.js", "assets/icon.png", "assets/pages-manage.js"):
        assert TestClient(c.app).get("/" + asset).status_code == 200, asset


def _all_paths() -> list[str]:
    """Every HTTP + WebSocket path of every router (read from the routers themselves: newer FastAPI versions
    wrap included routers, so app.routes no longer lists them)."""
    import importlib
    import pkgutil

    import cyberhub.routers as pkg
    from fastapi import APIRouter
    out = []
    for m in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"cyberhub.routers.{m.name}")
        for obj in vars(mod).values():
            if isinstance(obj, APIRouter):
                out += [r.path for r in obj.routes if hasattr(r, "path")]
    return sorted(set(out))


def _routes(app) -> list[tuple[str, re.Pattern]]:
    return [("ANY", re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(p)) + "$")) for p in _all_paths()]


def test_every_api_path_the_ui_calls_exists(c):
    """Static cross-check: each '/api/...' path written in the UI / bridge must match a real engine route."""
    routes = _routes(c.app)
    paths = _all_paths()
    assert len(paths) > 350 and "/api/system/stream" in paths
    files = list((ROOT / "ui" / "assets").glob("*.js")) + [ROOT / "frontend-bridge" / "cyberhub-api.js"]
    missing, checked = [], 0
    for f in files:
        src = f.read_text(encoding="utf-8")
        for m in re.finditer(r"""["'`](/api/[^"'`?]*)""", src):
            raw = m.group(1)
            path = re.sub(r"\$\{[^}]*\}", "X", raw).rstrip("/")
            checked += 1
            if any(rx.match(path) for _, rx in routes):
                continue
            # a prefix the code completes at run time, e.g. "/api/firewall/findings/" + id + "/fix", a base like
            # "/api/firewall" handed to a helper that appends "/events", or a template cut at a nested quote
            stem = re.sub(r"\$\{.*$", "", raw)
            if any(p.startswith(stem if stem.endswith("/") else stem + "/") for p in paths):
                continue
            missing.append(f"{f.name}: {raw}")
    assert checked > 250, checked
    assert not missing, "\n".join(sorted(set(missing)))


def test_build_recipe_files_exist():
    spec = (ROOT / "packaging" / "CyberHub.spec").read_text()
    for rel in ("cyberhub/rules", "cyberhub/data", "ui", "ui/assets/icon.ico", "packaging/version_info.txt",
                "CyberHub.pyw"):
        assert (ROOT / rel).exists(), rel
    assert 'contents_directory="."' in spec and "console=False" in spec
    assert list((ROOT / "cyberhub" / "rules").glob("*.yar")) and (ROOT / "cyberhub/data/eff_large_wordlist.txt").stat().st_size > 50000
    iss = (ROOT / "packaging" / "CyberHub.iss").read_text()
    assert "Syed Muhammad Tayyab" in iss and "PrivilegesRequired=lowest" in iss and "--minimized" in iss
    assert "Syed Muhammad Tayyab" in (ROOT / "packaging" / "version_info.txt").read_text()
    for bat in ("start_cyberhub.bat", "build_windows.bat", "start_cyberhub_admin.bat"):
        b = (ROOT / bat).read_bytes()
        assert b"\r\n" in b and b"Syed Muhammad Tayyab" in b, bat


def test_launcher_runs_the_engine_and_stays_single_instance(env, monkeypatch):
    with socket.socket() as s:                                       # a port that is taken
        s.bind(("127.0.0.1", 0))
        s.listen()
        busy = s.getsockname()[1]
        assert desktop_app.port_free(busy) is False
        free = desktop_app.pick_port(busy)
        assert free != busy and desktop_app.port_free(free)
    port = free
    assert desktop_app.running_instance(port) is False
    eng = desktop_app.Engine(port)
    assert eng.start(timeout=60), "engine did not start"
    try:
        assert desktop_app.running_instance(port) is True
        h = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=5).read())
        assert h["status"] == "ok" and h["version"] == "1.0.0"
        # a second launch only raises the running window
        shown = []
        desktop.SHELL_HOOKS["show"] = lambda: shown.append(1)
        assert desktop_app.main(["--port", str(port)]) == 0
        assert shown == [1]
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()
        assert "Cyber Hub" in html and "Developed by Syed Muhammad Tayyab" in html
    finally:
        eng.stop()
    assert not eng.thread.is_alive()
    assert desktop_app.running_instance(port) is False
