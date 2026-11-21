"""
Cyber Hub Backend - Part 7 tests: Real-time Protection
Developed by Syed Muhammad Tayyab

Real OS file notifications (inotify here, ReadDirectoryChangesW on Windows) drive
these tests. USB drives are simulated by swapping the drive lister for a fake
that "plugs in" temp folders. EICAR is assembled at runtime by malware_db.
"""
import hashlib
import io
import os
import shutil
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.main import create_app
from cyberhub.services.drives import inspect_drive
from cyberhub.services.malware_db import EICAR
from cyberhub.services.platform_tools import CACHE

PW = "Cyb3r!Hub#2026"
BAD = b"pretend this is a dropper"
BAD_SHA = hashlib.sha256(BAD).hexdigest()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("watched", "quick", "full", "usb1", "usb2", "extra"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    monkeypatch.setenv("CYBERHUB_RTP_DEFAULT_DIRS", str(tmp_path / "watched"))
    return tmp_path


class FakeDrives:
    def __init__(self):
        self.drives = []

    def plug(self, path, label="KINGSTON", serial="1A2B3C4D"):
        self.drives.append({"mountpoint": str(path), "device": "/dev/sdz1", "fstype": "vfat", "label": label,
                            "serial": serial, "bus": "USB", "model": "DataTraveler", "total_bytes": 16 * 2 ** 30,
                            "device_key": f"serial:{serial}"})

    def unplug(self, path):
        self.drives = [d for d in self.drives if d["mountpoint"] != str(path)]

    def __call__(self):
        return list(self.drives)


def _login(cl):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": "syed", "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def fake():
    return FakeDrives()


@pytest.fixture()
def c(env, fake):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.post("/api/scan/signatures", json={"hash": BAD_SHA, "name": "Trojan.Dropper", "severity": "high"})
        rt = cl.app.state.realtime
        rt.settle_seconds, rt.control_interval, rt.drive_lister = 0.3, 0.2, fake
        rt.start()
        yield cl
    CACHE.clear()


def wait_for(fn, timeout=12.0, every=0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise AssertionError("condition not met in time")


def events(c, **q):
    return c.get("/api/realtime/events", params=q).json()["items"]


def event_for(c, path, status=None):
    def f():
        for e in events(c, limit=1000):
            if e["path"] == str(path) and (status is None or e["status"] == status):
                return e
    return wait_for(f)


def make_zip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return b.getvalue()


# ======================================================================= status
def test_status_defaults(c, env):
    s = c.get("/api/realtime/status").json()
    assert s["enabled"] and s["state"] == "on" and s["protected"] and s["engine"] == "watchdog"
    f = s["folders"][0]
    assert f["path"] == str(env / "watched") and f["status"] == "watching" and f["kind"] == "default"
    assert s["settings"]["rtp_action"] == "quarantine" and s["settings"]["rtp_usb_scan"] == "auto"


def test_info_schema_and_settings(c):
    j = c.get("/api/info").json()
    assert j["build_part"] >= 7 and j["progress_percent"] >= 35 and "realtime" in j["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 8
    s = c.get("/api/settings").json()
    assert s["realtime_protection"] is True and s["rtp_max_file_mb"] == 100 and s["rtp_burst_threshold"] == 300


# ======================================================================= files
def test_threat_dropped_is_quarantined(c, env):
    p = env / "watched" / "eicar.com"
    p.write_bytes(EICAR)
    e = event_for(c, p, "infected")
    assert e["action"] == "quarantined" and e["quarantine_id"] and e["threat_name"] and e["origin"] == "folder"
    assert e["watch_root"] == str(env / "watched") and e["event"] in ("created", "modified", "moved")
    assert not p.exists()
    det = c.get("/api/scan/detections", params={"status": "quarantined"}).json()
    det = det if isinstance(det, list) else det.get("items", det)
    assert any(d["path"] == str(p) for d in det)
    q = c.get(f"/api/quarantine/{e['quarantine_id']}").json()
    assert q["source"] == "realtime" and q["status"] == "quarantined"
    acts = c.get("/api/activity", params={"category": "realtime"}).json()["items"]
    assert any(a["title"].startswith("Threat blocked") for a in acts)
    st = c.get("/api/realtime/status").json()
    assert st["counters"]["threats"] == 1 and st["last_threat"]["path"] == str(p)


def test_clean_file_logged_and_kept(c, env):
    p = env / "watched" / "notes.txt"
    p.write_text("hello")
    e = event_for(c, p)
    assert e["status"] == "clean" and e["action"] == "none" and e["sha256"] and p.exists()


def test_subfolder_and_hash_signature(c, env):
    d = env / "watched" / "a" / "b"
    d.mkdir(parents=True)
    time.sleep(0.3)
    p = d / "setup.exe"
    p.write_bytes(BAD)
    e = event_for(c, p, "infected")
    assert e["threat_name"] == "Trojan.Dropper" and e["severity"] == "high"


def test_threat_inside_zip(c, env):
    p = env / "watched" / "invoice.zip"
    p.write_bytes(make_zip({"readme.txt": b"hi", "payload/eicar.com": EICAR}))
    e = event_for(c, p, "infected")
    assert e["action"] == "quarantined" and not p.exists()


def test_partial_download_renamed(c, env):
    tmp = env / "watched" / "tool.exe.crdownload"
    tmp.write_bytes(BAD)
    time.sleep(1.0)
    assert not [e for e in events(c) if e["path"] == str(tmp)]           # in-progress downloads are ignored
    final = env / "watched" / "tool.exe"
    os.rename(tmp, final)
    e = event_for(c, final, "infected")
    assert e["event"] == "moved"


def test_folder_moved_in_is_expanded(c, env):
    src = env / "extra" / "unzipped"
    (src / "deep").mkdir(parents=True)
    (src / "deep" / "e.com").write_bytes(EICAR)
    (src / "ok.txt").write_text("fine")
    shutil.move(str(src), str(env / "watched" / "unzipped"))
    e = event_for(c, env / "watched" / "unzipped" / "deep" / "e.com", "infected")
    assert e["action"] == "quarantined"


def test_alert_only_mode(c, env):
    assert c.patch("/api/settings", json={"rtp_action": "alert"}).status_code == 200
    p = env / "watched" / "keep.com"
    p.write_bytes(EICAR)
    e = event_for(c, p, "infected")
    assert e["action"] == "alerted" and p.exists()
    det = c.get("/api/scan/detections").json()
    det = det if isinstance(det, list) else det.get("items", det)
    assert any(d["path"] == str(p) and d["status"] == "active" for d in det)


def test_alert_mode_still_honours_global_auto_quarantine(c, env):
    c.patch("/api/settings", json={"rtp_action": "alert", "scan_auto_quarantine": "all"})
    p = env / "watched" / "auto.com"
    p.write_bytes(EICAR)
    e = event_for(c, p, "infected")
    assert e["action"] == "quarantined" and not p.exists()


def test_large_file_skipped(c, env):
    c.patch("/api/settings", json={"rtp_max_file_mb": 1})
    p = env / "watched" / "big.bin"
    p.write_bytes(b"\0" * (2 * 1024 * 1024))
    e = event_for(c, p)
    assert e["status"] == "skipped" and e["reason"] == "too_large"


def test_excluded_path_skipped(c, env):
    sub = env / "watched" / "dev"
    sub.mkdir()
    c.put("/api/scan/exclusions", json={"paths": [str(sub)], "extensions": []})
    time.sleep(0.3)
    p = sub / "eicar.com"
    p.write_bytes(EICAR)
    e = event_for(c, p)
    assert e["status"] == "skipped" and e["reason"] == "excluded" and p.exists()


def test_restored_file_not_requarantined(c, env):
    p = env / "watched" / "mine.com"
    p.write_bytes(EICAR)
    e = event_for(c, p, "infected")
    r = c.post(f"/api/quarantine/{e['quarantine_id']}/restore", json={})
    assert r.status_code == 200, r.text
    assert p.exists()

    def second():
        evs = [x for x in events(c, status="infected") if x["path"] == str(p)]
        return evs if len(evs) >= 2 else None
    evs = wait_for(second)
    assert evs[0]["action"] == "alerted" and p.exists()


def test_clean_files_not_logged_when_disabled(c, env):
    c.patch("/api/settings", json={"rtp_log_clean_files": False})
    (env / "watched" / "a.txt").write_text("x")
    (env / "watched" / "b.com").write_bytes(EICAR)
    event_for(c, env / "watched" / "b.com", "infected")
    assert not [e for e in events(c) if e["status"] == "clean"]
    assert c.get("/api/realtime/status").json()["counters"]["files_scanned"] >= 2


# ======================================================================= control
def test_disable_pause_resume(c, env):
    s = c.post("/api/realtime/disable").json()
    assert s["state"] == "off" and not s["enabled"]
    p = env / "watched" / "while_off.com"
    p.write_bytes(EICAR)
    time.sleep(1.2)
    assert p.exists() and not [e for e in events(c) if e["path"] == str(p)]
    s = c.post("/api/realtime/enable").json()
    assert s["state"] == "on"
    s = c.post("/api/realtime/pause", json={"minutes": 5}).json()
    assert s["state"] == "snoozed" and s["snoozed_until"] and s["enabled"]
    assert all(f["status"] == "snoozed" for f in s["folders"])
    s = c.post("/api/realtime/resume").json()
    assert s["state"] == "on" and s["snoozed_until"] is None
    p2 = env / "watched" / "after.com"
    p2.write_bytes(EICAR)
    assert event_for(c, p2, "infected")["action"] == "quarantined"


def test_snooze_expires(c, env):
    rt = c.app.state.realtime
    c.post("/api/realtime/pause", json={"minutes": 1})
    from datetime import datetime, timedelta, timezone
    rt._snoozed_until = datetime.now(timezone.utc) + timedelta(seconds=0.5)
    wait_for(lambda: rt.status()["state"] == "on", 6)
    acts = c.get("/api/activity", params={"category": "realtime"}).json()["items"]
    assert any(a["title"] == "Real-time protection resumed" for a in acts)


def test_setting_switch_is_picked_up(c, env):
    c.patch("/api/settings", json={"realtime_protection": False})
    wait_for(lambda: c.get("/api/realtime/status").json()["state"] == "off", 8)
    c.patch("/api/settings", json={"realtime_protection": True})
    wait_for(lambda: c.get("/api/realtime/status").json()["state"] == "on", 8)


def test_standard_user_limits(c, env):
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    std = TestClient(c.app)
    std.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
    std.headers["X-CyberHub-Session"] = std.post("/api/account/login", json={"username": "kid", "password": PW}
                                                 ).json()["session_token"]
    assert std.get("/api/realtime/status").status_code == 200
    assert std.post("/api/realtime/disable").status_code == 403
    assert std.post("/api/realtime/pause", json={"minutes": 5}).status_code == 403
    assert std.post("/api/realtime/folders", json={"path": str(env / "extra")}).status_code == 403
    r = std.patch("/api/settings", json={"realtime_protection": False})
    assert r.status_code == 403 and "realtime_protection" in r.json()["detail"]
    assert std.patch("/api/settings", json={"theme": "light"}).status_code == 200
    assert std.post("/api/settings/reset").status_code == 403
    assert std.post("/api/realtime/enable").status_code == 200


def test_custom_folders(c, env):
    r = c.post("/api/realtime/folders", json={"path": str(env / "extra")})
    assert r.status_code == 201
    assert any(f["path"] == str(env / "extra") and f["status"] == "watching" for f in r.json()["folders"])
    assert c.post("/api/realtime/folders", json={"path": str(env / "extra")}).status_code == 409
    assert c.post("/api/realtime/folders", json={"path": str(env / "nope")}).status_code == 404
    assert c.post("/api/realtime/folders", json={"path": str(env / "data")}).status_code == 422
    p = env / "extra" / "x.com"
    p.write_bytes(EICAR)
    assert event_for(c, p, "infected")["watch_root"] == str(env / "extra")
    r = c.delete("/api/realtime/folders", params={"path": str(env / "extra")})
    assert r.status_code == 200 and r.json()["custom"] == []
    assert c.delete("/api/realtime/folders", params={"path": str(env / "extra")}).status_code == 404


def test_default_folders_toggle(c, env):
    c.patch("/api/settings", json={"rtp_watch_default_folders": False})
    c.app.state.realtime._reconcile()
    s = c.get("/api/realtime/status").json()
    assert s["folders"] == [] and s["state"] == "on_no_folders"


def test_missing_default_folder_reported(c, env):
    shutil.rmtree(env / "watched")
    rt = c.app.state.realtime
    rt._stop_observer()
    rt._watches.clear()
    rt._reconcile()
    f = c.get("/api/realtime/folders").json()["folders"][0]
    assert f["status"] == "missing"


# ======================================================================= USB
def test_usb_insert_checks_and_autoscan(c, env, fake):
    usb = env / "usb1"
    (usb / "autorun.inf").write_text("[autorun]\nopen=evil.exe\nicon=x.ico\n")
    (usb / "evil.exe").write_bytes(BAD)
    for n in ("Photos", "Work", "Music"):
        (usb / f".{n}").mkdir()
        (usb / f"{n}.lnk").write_bytes(b"L\0\0\0")
    (usb / ".Photos" / "eicar.com").write_bytes(EICAR)
    fake.plug(usb)
    rt = c.app.state.realtime
    dev = wait_for(lambda: next(iter(c.get("/api/realtime/usb", params={"connected": True}).json()["devices"]), None))
    assert dev["label"] == "KINGSTON" and dev["connected"] and dev["insert_count"] == 1 and dev["mountpoint"] == str(usb)
    codes = {w["code"]: w for w in dev["warnings"]}
    assert codes["autorun"]["severity"] == "high" and "evil.exe" in codes["autorun"]["detail"]
    assert "shortcut_virus" in codes and "root_programs" in codes
    jid = wait_for(lambda: c.get("/api/realtime/usb").json()["devices"][0]["last_scan_job"])
    job = wait_for(lambda: (j := c.get(f"/api/scan/jobs/{jid}").json())["status"] == "completed" and j)
    assert job["threats_found"] >= 2 and job["started_by"] == "realtime"
    acts = c.get("/api/activity", params={"category": "device"}).json()["items"]
    assert any(a["title"] == "USB drive connected: KINGSTON" and a["severity"] == "high" for a in acts)
    assert any(f["kind"] == "usb" and f["status"] == "watching" for f in rt.folders())
    # new file written to the drive while plugged in
    p = usb / "new.com"
    p.write_bytes(EICAR)
    assert event_for(c, p, "infected")["origin"] == "usb"
    # unplug
    fake.unplug(usb)
    wait_for(lambda: not c.get("/api/realtime/usb", params={"connected": True}).json()["devices"])
    assert not any(f["kind"] == "usb" for f in rt.folders())
    acts = c.get("/api/activity", params={"category": "device"}).json()["items"]
    assert any(a["title"].startswith("USB drive removed") for a in acts)
    assert c.get("/api/realtime/summary").json()["totals"]["usb_inserts"] == 1


def test_usb_trust_notify_and_forget(c, env, fake):
    c.patch("/api/settings", json={"rtp_usb_scan": "notify"})
    rt = c.app.state.realtime
    seq, _ = rt.events_since(10 ** 12)
    fake.plug(env / "usb2", label="SANDISK", serial="99")
    dev = wait_for(lambda: next(iter(c.get("/api/realtime/usb").json()["devices"]), None))
    assert dev["last_scan_job"] is None and dev["warnings"] == []
    _, evs = rt.events_since(seq)
    ins = next(e for e in evs if e["type"] == "usb_inserted")
    assert ins["suggest_scan"] is True and ins["first_time"] is True and ins["scan_job"] is None
    r = c.post(f"/api/realtime/usb/{dev['id']}/scan")
    assert r.status_code == 202 and r.json()["kind"] == "custom"
    assert c.patch(f"/api/realtime/usb/{dev['id']}", json={"trusted": True}).json()["trusted"] is True
    assert c.delete(f"/api/realtime/usb/{dev['id']}").status_code == 409          # still plugged in
    fake.unplug(env / "usb2")
    wait_for(lambda: not c.get("/api/realtime/usb", params={"connected": True}).json()["devices"])
    assert c.post(f"/api/realtime/usb/{dev['id']}/scan").status_code == 409
    # trusted drive in auto mode: no automatic scan, insert counter grows
    c.patch("/api/settings", json={"rtp_usb_scan": "auto"})
    jobs_before = len(c.get("/api/scan/jobs").json())
    fake.plug(env / "usb2", label="SANDISK", serial="99")
    d2 = wait_for(lambda: next(iter(c.get("/api/realtime/usb", params={"connected": True}).json()["devices"]), None))
    assert d2["insert_count"] == 2 and d2["id"] == dev["id"]
    time.sleep(0.5)
    assert len(c.get("/api/scan/jobs").json()) == jobs_before
    fake.unplug(env / "usb2")
    wait_for(lambda: not c.get("/api/realtime/usb", params={"connected": True}).json()["devices"])
    assert c.delete(f"/api/realtime/usb/{dev['id']}").json()["deleted"] == 1
    assert c.delete(f"/api/realtime/usb/{dev['id']}").status_code == 404


def test_inspect_drive_unit(tmp_path):
    assert inspect_drive(str(tmp_path)) == []
    (tmp_path / "autorun.inf").write_text("[autorun]\nlabel=My stick\n")
    w = inspect_drive(str(tmp_path))
    assert w[0]["code"] == "autorun" and w[0]["severity"] == "medium"
    (tmp_path / ".Docs").mkdir()
    (tmp_path / "Docs.lnk").write_bytes(b"x")
    assert any(x["code"] == "shortcut_virus" for x in inspect_drive(str(tmp_path)))
    assert inspect_drive(str(tmp_path / "gone"))[0]["code"] == "unreadable"


# ======================================================================= burst / feed / misc
def test_mass_change_burst_alert(c, env):
    c.patch("/api/settings", json={"rtp_burst_threshold": 25})
    d = env / "watched"
    for i in range(60):
        (d / f"doc{i}.txt").write_text("x")
    for i in range(60):
        os.rename(d / f"doc{i}.txt", d / f"doc{i}.txt.locked")
    acts = wait_for(lambda: [a for a in c.get("/api/activity", params={"category": "realtime"}).json()["items"]
                             if a["title"] == "Unusual burst of file changes"])
    assert acts[0]["severity"] == "high" and len(acts) == 1               # cooldown: one alert
    assert c.get("/api/realtime/summary").json()["totals"]["bursts"] == 1


def test_websocket_feed(c, env):
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    with c.websocket_connect(f"/api/realtime/stream?token={tok}&session={ses}") as ws:
        hello = ws.receive_json()
        assert hello["hello"] and hello["status"]["state"] == "on"
        (env / "watched" / "ws.com").write_bytes(EICAR)
        end = time.time() + 12
        seen = set()
        while time.time() < end and "threat_blocked" not in seen:
            m = ws.receive_json()
            seen |= {e["type"] for e in m["events"]}
        assert "threat_blocked" in seen
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/realtime/stream?token=bad&session={ses}") as ws:
            ws.receive_json()


def test_summary_events_filters_and_clear(c, env):
    (env / "watched" / "s1.txt").write_text("1")
    (env / "watched" / "s2.com").write_bytes(EICAR)
    event_for(c, env / "watched" / "s2.com", "infected")
    event_for(c, env / "watched" / "s1.txt", "clean")
    s = c.get("/api/realtime/summary", params={"days": 7}).json()
    assert len(s["by_day"]) == 7 and s["totals"]["threats"] == 1 and s["totals"]["files_scanned"] >= 2
    assert s["threats_by_action"] == {"quarantined": 1} and s["top_threats"][0]["n"] == 1
    assert all(e["status"] == "infected" for e in events(c, status="infected"))
    assert events(c, origin="usb") == []
    assert c.get("/api/realtime/events", params={"status": "weird"}).status_code == 422
    assert c.delete("/api/realtime/events").json()["deleted"] >= 2
    assert events(c) == []


def test_event_retention_prune(c, env):
    rt = c.app.state.realtime
    c.patch("/api/settings", json={"rtp_event_retention": 100})
    for i in range(130):
        rt._save_event({"path": f"/x/{i}", "event": "created", "origin": "folder", "watch_root": "/x",
                        "status": "clean", "reason": None, "threat_name": None, "severity": None, "detection_id": None,
                        "quarantine_id": None, "action": "none", "size": 1, "sha256": None, "downloaded_from": None,
                        "duration_ms": 1})
    rt.prune()
    assert c.get("/api/realtime/events").json()["total"] == 100


def test_self_test(c):
    r = c.post("/api/realtime/self-test").json()
    assert r["ok"] and r["file_events"] and r["latency_ms"] is not None and r["scan_engine"]["passed"]


def test_requires_session(c):
    tok = c.headers["X-CyberHub-Token"]
    anon = TestClient(c.app)
    assert anon.get("/api/realtime/status", headers={"X-CyberHub-Token": tok}).status_code == 401
    assert anon.get("/api/realtime/status").status_code == 401
