"""
Cyber Hub Backend - Part 4 tests: Processes & Startup
Developed by Syed Muhammad Tayyab
"""
import hashlib
import os
import sqlite3
import subprocess
import sys
import time

import psutil
import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import startup as st
from cyberhub.services import threat_flags as tf
from cyberhub.services.platform_tools import CACHE
from cyberhub.services.signatures import parse_ps_result, publisher_from_subject

PW = "Cyb3r!Hub#2026"
IS_POSIX = os.name == "posix"


@pytest.fixture()
def dirs(tmp_path, monkeypatch):
    user, system = tmp_path / "autostart-user", tmp_path / "autostart-system"
    user.mkdir(); system.mkdir()
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(user))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(system))
    return user, system


@pytest.fixture()
def c(tmp_path, monkeypatch, dirs):
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
        cl.headers["X-CyberHub-Session"] = r.json()["session_token"]
        yield cl
    CACHE.clear()


@pytest.fixture()
def sleeper():
    procs = []

    def spawn(code="import time; time.sleep(60)"):
        p = subprocess.Popen([sys.executable, "-c", code])
        procs.append(p)
        time.sleep(0.3)
        return p
    yield spawn
    for p in procs:
        try:
            psutil.Process(p.pid).kill()
        except psutil.Error:
            pass
        p.wait(timeout=5)


def desktop(folder, name, exec_, extra=""):
    (folder / name).write_text(f"[Desktop Entry]\nType=Application\nName={name[:-8]}\nExec={exec_}\n{extra}")


# ================================================================== access
def test_requires_session_and_admin_for_actions(c, sleeper):
    assert c.get("/api/processes", headers={"X-CyberHub-Session": ""}).status_code == 401
    assert c.get("/api/startup", headers={"X-CyberHub-Session": ""}).status_code == 401
    c.post("/api/account/users", json={"username": "guest1", "display_name": "G", "password": PW,
                                       "role": "standard"})
    tok = c.post("/api/account/login", json={"username": "guest1", "password": PW}).json()["session_token"]
    h = {"X-CyberHub-Session": tok}
    assert c.get("/api/processes?limit=5", headers=h).status_code == 200      # standard users can look
    p = sleeper()
    assert c.post(f"/api/processes/{p.pid}/end", headers=h).status_code == 403
    assert c.post(f"/api/processes/{p.pid}/suspend", headers=h).status_code == 403
    assert c.post("/api/startup/accept-all", headers=h).status_code == 403
    assert psutil.pid_exists(p.pid)


# ================================================================== list / tree / details
def test_list_shape_search_and_sort(c):
    j = c.get("/api/processes?sort=memory&limit=10").json()
    assert j["total"] >= 1 and len(j["items"]) <= 10
    for k in ("processes", "threads", "flagged", "by_risk", "by_status", "signatures"):
        assert k in j["summary"]
    mem = [r["memory_mb"] for r in j["items"]]
    assert mem == sorted(mem, reverse=True)
    row = j["items"][0]
    for k in ("pid", "ppid", "name", "exe", "status", "cpu_percent", "risk_level", "flags", "protected", "create_time"):
        assert k in row
    me = c.get(f"/api/processes?search={os.getpid()}").json()
    assert any(r["pid"] == os.getpid() for r in me["items"])
    assert c.get("/api/processes?sort=bogus").status_code == 422


def test_tree_contains_child_under_parent(c, sleeper):
    p = sleeper()
    tree = c.get("/api/processes/tree").json()

    def find(nodes, pid):
        for n in nodes:
            if n["pid"] == pid:
                return n
            hit = find(n["children"], pid)
            if hit:
                return hit
    me = find(tree["tree"], os.getpid())
    assert me and any(ch["pid"] == p.pid for ch in me["children"])
    assert me["descendants"] >= 1 and me["subtree_memory_mb"] >= me["memory_mb"]


def test_details_and_hash(c, sleeper):
    p = sleeper()
    d = c.get(f"/api/processes/{p.pid}?hash=true").json()
    assert d["pid"] == p.pid and d["parent"]["pid"] == os.getpid()
    assert "time.sleep" in d["cmdline"] and d["protected"] is False
    assert d["actions"] == {"end": True, "suspend": True, "priority": True}
    exe = psutil.Process(p.pid).exe()
    assert d["sha256"] == hashlib.sha256(open(exe, "rb").read()).hexdigest()
    assert d["signature"]["status"] in ("unsupported", "signed", "unsigned", "error")
    assert c.get("/api/processes/99999999").status_code == 404


def test_summary(c):
    j = c.get("/api/processes/summary").json()
    assert j["processes"] > 0 and "engine_elevated" in j and "top_risk" in j


# ================================================================== protection
def test_protected_processes_refused(c):
    r = c.post(f"/api/processes/{os.getpid()}/end")
    assert r.status_code == 403 and "Cyber Hub" in r.json()["detail"]
    assert c.post(f"/api/processes/{os.getpid()}/suspend").status_code == 403
    if IS_POSIX and psutil.pid_exists(1):
        assert c.post("/api/processes/1/end").status_code == 403
    assert c.post("/api/processes/99999999/end").status_code == 404


def test_pid_reuse_guard(c, sleeper):
    p = sleeper()
    r = c.post(f"/api/processes/{p.pid}/end", json={"create_time": 12345.0})
    assert r.status_code == 409 and psutil.pid_exists(p.pid)


# ================================================================== actions
@pytest.mark.skipif(not IS_POSIX, reason="status names differ on Windows")
def test_suspend_resume_priority_end(c, sleeper):
    p = sleeper()
    ct = psutil.Process(p.pid).create_time()
    assert c.post(f"/api/processes/{p.pid}/suspend", json={"create_time": ct}).json()["status"] == "stopped"
    assert c.post(f"/api/processes/{p.pid}/resume").json()["status"] in ("sleeping", "running")
    assert c.put(f"/api/processes/{p.pid}/priority", json={"priority": "below_normal"}).json()["priority"] == "below_normal"
    assert c.put(f"/api/processes/{p.pid}/priority", json={"priority": "realtime"}).status_code == 422
    r = c.post(f"/api/processes/{p.pid}/end", json={"create_time": ct}).json()
    assert r["result"] == "ended" and p.pid in r["ended"]
    p.wait(timeout=5)
    hist = c.get("/api/processes/actions").json()["items"]
    assert [h["action"] for h in hist[:4]] == ["ended", "priority -> below_normal", "resumed", "suspended"]
    acts = c.get("/api/activity?category=process").json()["items"]
    assert any("ended" in a["title"] for a in acts)


@pytest.mark.skipif(not IS_POSIX, reason="SIGTERM handling is POSIX")
def test_graceful_end_refused_then_force(c, sleeper):
    p = sleeper("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)")
    r = c.post(f"/api/processes/{p.pid}/end").json()            # program ignores the polite request
    assert r["result"] == "still_running" and r["hint"]
    r = c.post(f"/api/processes/{p.pid}/end", json={"force": True}).json()
    assert r["result"] == "ended"
    p.wait(timeout=5)


def test_end_tree(c, sleeper):
    code = ("import subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); time.sleep(60)")
    p = sleeper(code)
    time.sleep(0.5)
    kids = psutil.Process(p.pid).children()
    assert kids
    r = c.post(f"/api/processes/{p.pid}/end", json={"tree": True}).json()
    assert r["result"] == "ended" and {p.pid, kids[0].pid} <= set(r["ended"])
    p.wait(timeout=5)
    assert not psutil.pid_exists(kids[0].pid) or psutil.Process(kids[0].pid).status() == "zombie"


# ================================================================== risk flags
def test_threat_flags():
    assert tf.path_flags(r"C:\Users\syed\AppData\Local\Temp\x.exe") == ["suspicious_location"]
    assert tf.path_flags(r"C:\Users\syed\Downloads\setup.exe") == ["suspicious_location"]
    assert tf.path_flags("/tmp/miner") == ["suspicious_location"]
    assert tf.path_flags(r"C:\Program Files\Google\Chrome\chrome.exe") == []
    assert tf.is_masquerading("svchost.exe", r"C:\Users\Public\svchost.exe")
    assert not tf.is_masquerading("svchost.exe", r"C:\Windows\System32\svchost.exe")
    assert tf.is_masquerading("explorer.exe", r"C:\Windows\System32\explorer.exe")
    assert not tf.is_masquerading("chrome.exe", r"D:\x\chrome.exe")
    f = tf.command_flags("powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")
    assert {"encoded_command", "hidden_window", "script_launcher"} <= set(f)
    assert tf.command_flags('"C:\\Program Files\\App\\app.exe" --minimized') == []
    s = tf.score(["masquerade", "suspicious_location"])
    assert s["risk_level"] == "high" and s["risk_score"] == 95 and len(s["reasons"]) == 2
    assert tf.score([])["risk_level"] == "none"
    assert tf.score(["unsigned"])["risk_level"] == "low"


def test_signature_parsing_and_non_windows(c):
    info = parse_ps_result({"status": "Valid", "subject": "CN=Google LLC, O=Google LLC, L=Mountain View, C=US",
                            "issuer": "CN=DigiCert Trusted G4 Code Signing, O=DigiCert Inc", "is_os": False})
    assert info["status"] == "signed" and info["publisher"] == "Google LLC" and info["issuer"] == "DigiCert Inc"
    assert parse_ps_result({"status": "HashMismatch"})["status"] == "tampered"
    assert parse_ps_result({"status": "NotSigned"})["status"] == "unsigned"
    assert publisher_from_subject('CN="Acme, Inc."') == "Acme, Inc."
    if IS_POSIX:
        app = c.app
        out = app.state.signatures.check_many([sys.executable, "/no/such/file.exe"])
        assert out[sys.executable]["status"] == "unsupported"
        assert out["/no/such/file.exe"]["status"] == "not_found"


# ================================================================== startup helpers
def test_parse_command(tmp_path, monkeypatch):
    spaced = tmp_path / "My Apps" / "tool.exe"
    spaced.parent.mkdir(); spaced.write_text("x")
    assert st.parse_command(f'"{spaced}" --tray') == (str(spaced), "--tray")
    assert st.parse_command(f"{spaced} --tray") == (str(spaced), "--tray")
    monkeypatch.setenv("CHTESTDIR", str(tmp_path))
    exe, _ = st.parse_command("$CHTESTDIR/My Apps/tool.exe -q" if IS_POSIX else "%CHTESTDIR%\\My Apps\\tool.exe -q")
    assert os.path.normpath(exe) == os.path.normpath(str(spaced))
    exe, args = st.parse_command(r'rundll32.exe "C:\Users\Public\evil.dll",DllMain')
    assert exe == r"C:\Users\Public\evil.dll"
    assert st.parse_command(None) == (None, "")


def test_startup_approved_bytes():
    assert st.approved_is_enabled(None) and st.approved_is_enabled(bytes([2]) + bytes(11))
    off = st.approved_value(False, now=1_700_000_000)
    assert len(off) == 12 and off[0] == 3 and not st.approved_is_enabled(off)
    assert st.approved_is_enabled(st.approved_value(True)) and st.approved_is_enabled(bytes([6, 0, 0, 0]))


def test_set_desktop_hidden():
    base = "[Desktop Entry]\nName=A\nExec=a\n"
    off = st.set_desktop_hidden(base, True)
    assert "Hidden=true" in off and not st._desktop_enabled(st.parse_desktop(off))
    on = st.set_desktop_hidden(off, False)
    assert on.count("Hidden=") == 1 and st._desktop_enabled(st.parse_desktop(on))
    multi = "[Desktop Entry]\nName=A\nX-GNOME-Autostart-enabled=false\n[Desktop Action x]\nName=B\n"
    on = st.set_desktop_hidden(multi, False)
    d = st.parse_desktop(on)
    assert st._desktop_enabled(d) and on.index("Hidden=false") < on.index("[Desktop Action x]")


# ================================================================== startup API (XDG provider)
def _xdg(c, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    return c.get(f"/api/startup?source=xdg_autostart&refresh=true&{q}").json()


def test_startup_baseline_new_item_and_watch(c, dirs):
    user, system = dirs
    CACHE.clear()
    c.app.state.db.execute("DELETE FROM startup_seen")
    desktop(user, "notes.desktop", "/usr/bin/gnome-notes")
    j = _xdg(c)
    assert j["total"] == 1 and j["items"][0]["is_new"] is False          # first scan = trusted baseline
    desktop(user, "updater.desktop", "/tmp/.x/updater --silent")
    j = _xdg(c)
    new = next(i for i in j["items"] if i["name"] == "updater")
    assert new["is_new"] and "new_item" in new["flags"] and "suspicious_location" in new["flags"]
    assert j["items"][0]["name"] == "updater"                             # riskiest first
    assert j["summary"]["new"] == 1
    assert c.get("/api/startup?state=new&source=xdg_autostart").json()["total"] == 1

    w = c.post("/api/startup/watch/check").json()
    assert [i["name"] for i in w["new"]] == ["updater"]
    assert c.post("/api/startup/watch/check").json()["new"] == []        # alert only once
    acts = c.get("/api/activity?category=startup").json()["items"]
    assert any(a["title"] == "New startup item: updater" for a in acts)

    assert c.post(f"/api/startup/{new['id']}/accept").json() == {"accepted": 1}
    assert next(i for i in _xdg(c)["items"] if i["name"] == "updater")["is_new"] is False

    (user / "notes.desktop").unlink()
    w = c.post("/api/startup/watch/check").json()
    assert "notes" in w["removed"]


def test_startup_disable_enable_user_and_system(c, dirs):
    user, system = dirs
    desktop(user, "chat.desktop", "/usr/bin/chat")
    desktop(system, "tray.desktop", "/usr/bin/tray")
    items = {i["name"]: i for i in _xdg(c)["items"]}
    chat, tray = items["chat"], items["tray"]
    assert chat["enabled"] and chat["scope"] == "user" and tray["scope"] == "machine"

    r = c.post(f"/api/startup/{chat['id']}/disable").json()
    assert r["enabled"] is False and r["changed"] is True
    assert "Hidden=true" in (user / "chat.desktop").read_text()
    assert c.post(f"/api/startup/{chat['id']}/disable").json()["changed"] is False
    r = c.post(f"/api/startup/{chat['id']}/enable").json()
    assert r["enabled"] is True

    r = c.post(f"/api/startup/{tray['id']}/disable").json()               # system entry -> user override
    assert r["enabled"] is False and (user / "tray.desktop").exists()
    assert "Hidden=true" not in (system / "tray.desktop").read_text()      # original untouched
    assert c.get(f"/api/startup/{tray['id']}").json()["overrides_system"] is True

    ch = c.get("/api/startup/changes").json()["items"]
    assert [x["action"] for x in ch[:3]] == ["disable", "enable", "disable"]
    assert c.get("/api/startup?source=xdg_autostart&state=disabled").json()["total"] == 1
    assert c.post("/api/startup/doesnotexist/disable").status_code == 404


def test_startup_summary_and_sources(c, dirs):
    user, _ = dirs
    desktop(user, "a.desktop", "/usr/bin/a")
    s = c.get("/api/startup/summary").json()
    for k in ("total", "enabled", "disabled", "new", "flagged", "by_source", "by_risk", "engine_elevated"):
        assert k in s
    assert "xdg_autostart" in s["by_source"]
    assert {x["id"] for x in c.get("/api/startup/sources").json()} >= {"registry_run", "service", "scheduled_task"}


# ================================================================== settings / schema / info
def test_part4_settings(c):
    s = c.get("/api/settings").json()
    assert s["startup_watch_enabled"] is True and s["startup_watch_interval_minutes"] == 10
    assert c.patch("/api/settings", json={"startup_watch_interval_minutes": 0}).status_code == 422
    assert c.patch("/api/settings", json={"startup_watch_interval_minutes": 30}).status_code == 200


def test_migration_from_v4(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)")
    for v, d, sql in MIGRATIONS[:4]:
        con.executescript(sql)
        con.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    con.commit(); con.close()
    db = Database(path)
    assert db.migrate() == MIGRATIONS[-1][0]
    names = {r["name"] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"file_signatures", "process_actions", "startup_seen", "startup_changes"} <= names
    db.close()


def test_info_reports_part4(c):
    j = c.get("/api/info").json()
    assert j["build_part"] >= 4 and j["progress_percent"] >= 20 and "processes" in j["available_modules"]
