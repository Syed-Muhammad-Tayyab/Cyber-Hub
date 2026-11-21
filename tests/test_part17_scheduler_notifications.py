"""
Cyber Hub Backend - Part 17 tests: Scheduler & Notifications
Developed by Syed Muhammad Tayyab

* Toasts go to the in-memory toaster (conftest), so every "would Windows have shown this?" rule is asserted.
* The scheduler's clock is replaced (svc.clock), so "tomorrow 13:00" happens instantly; real scans, posture
  checks, reports and backups run through the real Part 5 / 11 / 19 services against temp folders.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import notifications as nt
from cyberhub.services import scheduler as sch

PW = "Cyb3r!Hub#2026"
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched", "docs", "home"):
        (tmp_path / d).mkdir()
    for k, v in {"CYBERHUB_DATA_DIR": tmp_path / "data", "CYBERHUB_UI_DIR": tmp_path / "no-ui",
                 "CYBERHUB_QUICK_SCAN_DIRS": tmp_path / "quick", "CYBERHUB_FULL_SCAN_ROOTS": tmp_path / "full",
                 "CYBERHUB_AUTOSTART_USER_DIR": tmp_path / "as-user", "CYBERHUB_AUTOSTART_SYSTEM_DIR": tmp_path / "as-sys",
                 "CYBERHUB_RTP_DEFAULT_DIRS": tmp_path / "watched", "CYBERHUB_FIREWALL_BACKEND": "memory",
                 "CYBERHUB_NETWORK_BACKEND": "memory", "CYBERHUB_POSTURE_BACKEND": "memory",
                 "CYBERHUB_CLIPBOARD_BACKEND": "memory", "CYBERHUB_PV_KDF_N": "1024", "CYBERHUB_DP_KDF_N": "1024",
                 "CYBERHUB_CLEANER_HOME": tmp_path / "home", "CYBERHUB_CLEANER_LAYOUT": "linux",
                 "CYBERHUB_FINDER_DEFAULT_DIRS": tmp_path / "docs"}.items():
        monkeypatch.setenv(k, str(v))
    return tmp_path


def _login(cl, user="syed", pw=PW):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": pw})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": pw})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        yield cl


def standard_client(c):
    r = c.post("/api/account/users", json={"username": "guest", "display_name": "Guest", "password": "Gu3st!Pass#2026",
                                           "role": "standard"})
    assert r.status_code == 201, r.text
    s = TestClient(c.app)
    s.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
    r = s.post("/api/account/login", json={"username": "guest", "password": "Gu3st!Pass#2026"})
    s.headers["X-CyberHub-Session"] = r.json()["session_token"]
    return s


def nc(c):
    return c.app.state.notifications


def sv(c):
    return c.app.state.scheduler


def toasts(c):
    nc(c).flush_toasts()
    return nc(c).toaster.shown


# ====================================================================== pure helpers
def test_quiet_hours_and_next_run_maths():
    at = lambda h, m=0: datetime(2026, 11, 15, h, m)                                    # noqa: E731
    assert nt.in_quiet_hours("22:00", "07:00", at(23)) and nt.in_quiet_hours("22:00", "07:00", at(6, 59))
    assert not nt.in_quiet_hours("22:00", "07:00", at(7)) and not nt.in_quiet_hours("22:00", "07:00", at(12))
    assert nt.in_quiet_hours("09:00", "17:00", at(9)) and not nt.in_quiet_hours("09:00", "17:00", at(17))
    assert not nt.in_quiet_hours("08:00", "08:00", at(8))                               # empty range = never

    def local(y, mo, d, h=0, mi=0):
        return datetime(y, mo, d, h, mi).astimezone().astimezone(timezone.utc)

    def as_local(dt):
        return dt.astimezone().replace(tzinfo=None)

    sun = local(2026, 11, 15, 10, 0)                                                    # a Sunday
    assert as_local(sch.next_run({"kind": "daily", "at_time": "13:00"}, sun)) == datetime(2026, 11, 15, 13, 0)
    assert as_local(sch.next_run({"kind": "daily", "at_time": "09:00"}, sun)) == datetime(2026, 11, 16, 9, 0)
    assert as_local(sch.next_run({"kind": "daily", "at_time": "10:00"}, sun)) == datetime(2026, 11, 16, 10, 0)  # strictly after
    assert as_local(sch.next_run({"kind": "weekly", "at_time": "09:00", "weekdays": "0"}, sun)) == datetime(2026, 11, 16, 9, 0)
    assert as_local(sch.next_run({"kind": "weekly", "at_time": "09:00", "weekdays": "6"}, sun)) == datetime(2026, 11, 22, 9, 0)
    assert as_local(sch.next_run({"kind": "weekly", "at_time": "11:00", "weekdays": "2,6"}, sun)) == datetime(2026, 11, 15, 11, 0)
    assert as_local(sch.next_run({"kind": "monthly", "at_time": "08:00", "month_day": 31}, sun)) == datetime(2026, 11, 30, 8, 0)
    assert as_local(sch.next_run({"kind": "monthly", "at_time": "08:00", "month_day": 1}, sun)) == datetime(2026, 12, 1, 8, 0)
    feb = local(2027, 2, 1, 0, 0)
    assert as_local(sch.next_run({"kind": "monthly", "at_time": "08:00", "month_day": 30}, feb)) == datetime(2027, 2, 28, 8, 0)
    assert sch.next_run({"kind": "interval", "every_minutes": 90}, sun) == sun + timedelta(minutes=90)
    future = sch._iso(sun + timedelta(hours=1))
    assert sch.next_run({"kind": "once", "run_at": future}, sun) == sun + timedelta(hours=1)
    assert sch.next_run({"kind": "once", "run_at": future}, sun + timedelta(hours=2)) is None
    assert sch.describe({"kind": "weekly", "at_time": "09:00", "weekdays": "0,1,2,3,4"}) == "Weekdays at 09:00"
    assert sch.describe({"kind": "monthly", "at_time": "08:00", "month_day": 22}) == "Monthly on the 22nd at 08:00"
    assert sch.describe({"kind": "interval", "every_minutes": 120}) == "Every 2 hour(s)"
    with pytest.raises(sch.SchedulerError):
        sch._hhmm("25:00")


# ====================================================================== notification center
def test_info_and_migration(c):
    info = c.get("/api/info").json()
    assert "scheduler" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 85
    assert c.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 18
    tables = {r["name"] for r in c.app.state.db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"notifications", "notify_state", "schedules", "schedule_runs"} <= tables
    st = c.get("/api/notifications/status").json()
    assert st["toasts"]["backend"] == "memory" and st["toasts"]["available"] and st["unread"] == 0
    assert {s["id"] for s in st["sources"]} == set(nt.SOURCES)


def test_upgrade_from_part16_database_starts_at_now(env):
    """A Part 16 database full of old events must not flood the new notification center."""
    (env / "data").mkdir()
    db = Database(env / "data" / "cyberhub.db")
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))")
    for ver, d, sql in MIGRATIONS:
        if ver <= 17:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db.execute("INSERT INTO firewall_events(kind, severity, title) VALUES ('firewall_off','critical','Old alert')")
    db.execute("INSERT INTO activity_log(category, severity, title) VALUES ('threat','high','Old threat')")
    assert db.schema_version() == 17
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0]
        assert cl.post("/api/notifications/collect").json()["created"] == 0
        cl.app.state.db.execute("INSERT INTO firewall_events(kind, severity, title) VALUES "
                                "('firewall_off','critical','New alert')")
        assert cl.post("/api/notifications/collect").json()["created"] == 1
        items = cl.get("/api/notifications").json()["items"]
        assert [i["title"] for i in items] == ["New alert"]


def test_collects_module_events_once_with_links_and_owners(c):
    db = c.app.state.db
    guest = standard_client(c)
    gid = db.fetchone("SELECT id FROM users WHERE username='guest'")["id"]
    base = c.post("/api/notifications/collect").json()["created"]                   # account events of the setup
    db.execute("INSERT INTO firewall_events(kind, severity, title, detail) VALUES (?,?,?,?)",
               ("firewall_off", "critical", "Firewall was turned off", "Public profile"))
    db.execute("INSERT INTO network_events(kind, severity, title) VALUES ('new_device','medium','New device joined')")
    db.execute("INSERT INTO posture_events(kind, severity, title) VALUES ('fix_applied','info','Fix applied')")
    db.execute("INSERT INTO pv_events(user_id, kind, severity, title) VALUES (?,?,?,?)",
               (gid, "breach_found", "high", "A saved password is in a breach"))
    db.execute("INSERT INTO platform_events(user_id, kind, severity, title) VALUES (NULL,'new_breach','low','New breach')")
    c.app.state.activity.record("realtime", "Threat blocked: EICAR", "C:/dl/x.com was quarantined", severity="high",
                                source="realtime")
    c.app.state.activity.record("firewall", "duplicate of the firewall event", severity="critical")   # not mapped
    c.app.state.activity.record("threat", "Info only", severity="info")
    made = c.post("/api/notifications/collect").json()["created"]
    assert made == 5                                    # firewall, network, guest's vault, platform, real-time
    assert c.post("/api/notifications/collect").json()["created"] == 0  # never twice

    mine = c.get("/api/notifications?limit=100").json()
    titles = {i["title"]: i for i in mine["items"]}
    assert "A saved password is in a breach" not in titles              # belongs to guest
    assert "Fix applied" not in titles and "Info only" not in titles and "duplicate of the firewall event" not in titles
    fw = titles["Firewall was turned off"]
    assert fw["source"] == "firewall" and fw["link"] == "firewall" and fw["shared"] and fw["severity"] == "critical"
    assert fw["source_name"] == "Firewall" and not fw["read"]
    assert titles["New device joined"]["link"] == "network" and titles["New breach"]["link"] == "platforms"
    rt = titles["Threat blocked: EICAR"]
    assert rt["source"] == "realtime" and rt["link"] == "protection" and rt["source_table"] == "activity_log"

    theirs = {i["title"] for i in guest.get("/api/notifications?limit=100").json()["items"]}
    assert "A saved password is in a breach" in theirs and "Firewall was turned off" in theirs
    assert base >= 0 and mine["unread"] == mine["total"]

    # filters
    assert {i["title"] for i in c.get("/api/notifications?source=firewall").json()["items"]} == {"Firewall was turned off"}
    hi = c.get("/api/notifications?min_severity=high").json()["items"]
    assert {i["severity"] for i in hi} <= {"high", "critical"} and len(hi) >= 2
    assert c.get("/api/notifications?search=device").json()["total"] == 1
    assert c.get("/api/notifications?search=100%25").json()["total"] == 0           # wildcards are literal
    assert c.get("/api/notifications?source=nope").status_code == 422
    one = c.get(f"/api/notifications/{fw['id']}").json()
    assert one["title"] == fw["title"]
    assert c.get(f"/api/notifications/{db.fetchone('SELECT id FROM notifications WHERE user_id=?', (gid,))['id']}"
                 ).status_code == 404                                   # can't read another user's


def test_read_dismiss_clear_and_summary(c):
    n = nc(c)
    ids = [n.notify("threat", sev, f"T-{sev}", user_id=None)["id"] for sev in ("low", "medium", "high", "critical")]
    n.notify("passwords", "high", "mine", user_id=1)
    s = c.get("/api/notifications/summary").json()
    assert s["unread"] == 5 and s["worst_unread"] == "critical" and s["unread_by_severity"]["high"] == 2
    assert {x["source"]: x["n"] for x in s["by_source"]} == {"threat": 4, "passwords": 1}
    assert s["by_day"][0]["n"] == 5 and s["by_day"][0]["serious"] == 3

    r = c.post("/api/notifications/read", json={"ids": ids[:2]}).json()
    assert r == {"updated": 2, "unread": 3}
    assert c.get("/api/notifications?status=unread").json()["total"] == 3
    assert c.post("/api/notifications/unread", json={"ids": ids[:1]}).json()["unread"] == 4
    assert c.post("/api/notifications/dismiss", json={"ids": ids[2:]}).json()["unread"] == 2     # dismissed = read
    assert c.get("/api/notifications").json()["total"] == 3                                      # open
    assert c.get("/api/notifications?status=dismissed").json()["total"] == 2
    assert c.get("/api/notifications?status=all").json()["total"] == 5
    assert c.post("/api/notifications/read", json={}).json()["unread"] == 0                      # all

    guest = standard_client(c)
    assert guest.delete("/api/notifications").json()["deleted"] == 0     # a standard user can't delete shared ones
    assert c.delete("/api/notifications?dismissed_only=true").json()["deleted"] == 2
    assert c.delete("/api/notifications").json()["deleted"] == 3
    assert c.get("/api/notifications?status=all").json()["total"] == 0


def test_toast_rules(c):
    n = nc(c)
    st = c.app.state.settings_store
    assert n.notify("threat", "info", "below the center floor") is None                 # center keeps low+
    assert n.notify("threat", "low", "kept, no toast")["toast"] == "none"               # toast floor = medium
    assert n.notify("threat", "high", "Threat found", "C:/x.exe")["toast"] == "pending"
    shown = toasts(c)
    assert shown == [{"title": "Threat found", "body": "C:/x.exe", "severity": "high", "tag": shown[0]["tag"]}]
    assert c.get("/api/notifications?search=Threat found").json()["items"][0]["toast"] == "shown"

    st.update({"notify_muted_sources": ["network"]})
    assert n.notify("network", "critical", "muted source")["toast"] == "muted"
    st.update({"notify_muted_sources": [], "notify_toasts": False})
    assert n.notify("network", "critical", "toasts off")["toast"] == "off"
    st.update({"notify_toasts": True, "notifications_enabled": False})
    assert n.notify("network", "critical", "all off")["toast"] == "off"
    st.update({"notifications_enabled": True})

    # quiet hours: always "now" by making the window the whole day except this minute's opposite
    now = datetime.now()
    start = (now - timedelta(hours=1)).strftime("%H:%M")
    end = (now + timedelta(hours=1)).strftime("%H:%M")
    st.update({"notify_quiet_hours": True, "notify_quiet_start": start, "notify_quiet_end": end})
    assert c.get("/api/notifications/status").json()["quiet_now"] is True
    assert n.notify("firewall", "high", "during quiet hours")["toast"] == "quiet"
    assert n.notify("firewall", "critical", "critical passes")["toast"] == "pending"
    st.update({"notify_quiet_allow_critical": False})
    assert n.notify("firewall", "critical", "critical waits too")["toast"] == "quiet"
    st.update({"notify_quiet_hours": False})

    # rate limit: 2 already shown in this minute
    st.update({"notify_toast_max_per_minute": 3})
    assert n.notify("intel", "high", "third")["toast"] == "pending"
    assert n.notify("intel", "high", "fourth")["toast"] == "rate"
    assert len(toasts(c)) == 3

    # a failing toaster is recorded, the notification stays
    n._toast_times.clear()
    n.toaster.fail = True
    row = n.notify("intel", "high", "toaster broken")
    n.flush_toasts()
    assert c.get(f"/api/notifications/{row['id']}").json()["toast"] == "failed"
    n.toaster.fail = False

    # the test button ignores every rule
    st.update({"notify_toasts": False})
    t = c.post("/api/notifications/test").json()
    assert t["shown"] is True and t["notification"]["kind"] == "test" and toasts(c)[-1]["severity"] == "low"

    # settings validation
    assert c.patch("/api/settings", json={"notify_quiet_start": "7pm"}).status_code == 422
    assert c.patch("/api/settings", json={"notify_quiet_start": "24:00"}).status_code == 422
    assert c.patch("/api/settings", json={"notify_muted_sources": ["nope"]}).status_code == 422
    assert c.patch("/api/settings", json={"notify_toast_min_severity": "info"}).status_code == 422
    assert c.patch("/api/settings", json={"notify_quiet_start": "21:30"}).status_code == 200


def test_tray_hook_takes_over_toasts(c):
    n = nc(c)
    got = []
    n.on_toast = lambda p: got.append(p) or True
    n.notify("threat", "high", "via tray", "body")
    n.flush_toasts()
    assert got[0]["title"] == "via tray" and not n.toaster.shown
    assert c.get("/api/notifications/status").json()["toasts"]["backend"] == "tray"
    n.on_toast = lambda p: False                                         # tray refused -> normal toast
    n._toast_times.clear()
    n.notify("threat", "high", "fallback")
    assert toasts(c)[-1]["title"] == "fallback"


def test_real_detection_reaches_the_center(c):
    """End to end with Part 5: an EICAR file found by a custom scan becomes a notification with a toast."""
    f = c.env / "quick" / "eicar.com"
    f.write_text(EICAR)
    c.post("/api/notifications/collect")
    job = c.post("/api/scan/custom", json={"paths": [str(c.env / "quick")]}).json()
    for _ in range(200):
        j = c.get(f"/api/scan/jobs/{job['id']}").json()
        if j["status"] not in ("queued", "running"):
            break
        time.sleep(0.05)
    assert j["status"] == "completed" and j["threats_found"] == 1
    assert c.post("/api/notifications/collect").json()["created"] >= 1
    items = c.get("/api/notifications?source=threat").json()["items"]
    assert any("scan" in i["title"].lower() and i["severity"] == "medium" for i in items)
    assert any("scan" in t["title"].lower() for t in toasts(c))


def test_stream_pushes_new_notifications(c):
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    with pytest.raises(Exception):
        with c.websocket_connect("/api/notifications/stream?token=bad&session=" + ses) as ws:
            ws.receive_json()
    with c.websocket_connect(f"/api/notifications/stream?token={tok}&session={ses}") as ws:
        first = ws.receive_json()
        assert first["type"] == "notifications" and first["unread"] == 0 and first["items"] == []
        nc(c).notify("firewall", "critical", "live one")
        msg = ws.receive_json()
        assert msg["items"][0]["title"] == "live one" and msg["unread"] == 1 and msg["worst_unread"] == "critical"


# ====================================================================== scheduler
def test_defaults_actions_and_status(c):
    lst = c.get("/api/scheduler/schedules").json()
    by = {s["builtin"]: s for s in lst["items"]}
    assert set(by) == {"quick_scan_daily", "full_scan_weekly", "report_weekly", "backup_weekly", "clean_weekly",
                       "finder_monthly"}
    assert by["quick_scan_daily"]["enabled"] and by["quick_scan_daily"]["when"] == "Every day at 13:00"
    assert by["quick_scan_daily"]["next_run_at"] and by["quick_scan_daily"]["catch_up"]
    assert not by["full_scan_weekly"]["enabled"] and by["full_scan_weekly"]["when"] == "Every Sunday at 11:00"
    assert by["report_weekly"]["params"] == {"type": "summary", "format": "pdf", "days": 7}
    assert not by["clean_weekly"]["enabled"] and by["clean_weekly"]["params"] == {"categories": ["temp"]}
    acts = {a["id"]: a for a in c.get("/api/scheduler/actions").json()["items"]}
    assert set(acts) == set(sch.ACTIONS) and all(a["available"] for a in acts.values())
    assert acts["scan_full"]["heavy"] and acts["privacy_clean"]["per_user"]
    st = c.get("/api/scheduler/status").json()
    assert st["enabled"] and st["schedules"] == 6 and st["active"] == 2 and st["next"]["name"]
    assert st["weekdays"][0] == "Monday" and st["on_battery"] is False
    up = c.get("/api/scheduler/upcoming?hours=168").json()["items"]
    assert sum(1 for u in up if u["name"] == "Daily quick scan") == 7 and up == sorted(up, key=lambda u: u["at"])

    # deleting a built-in schedule is permanent: it is not re-created at the next start
    c.delete(f"/api/scheduler/schedules/{by['finder_monthly']['id']}")
    c.app.state.scheduler._seed_defaults()
    assert len(c.get("/api/scheduler/schedules").json()["items"]) == 5


def test_create_validate_update_delete(c):
    bad = [
        ({"name": "", "action": "scan_quick", "kind": "daily", "at_time": "10:00"}, "name"),
        ({"name": "x", "action": "format_c", "kind": "daily", "at_time": "10:00"}, "Unknown action"),
        ({"name": "x", "action": "scan_quick", "kind": "hourly"}, "kind"),
        ({"name": "x", "action": "scan_quick", "kind": "daily", "at_time": "10"}, "14:30"),
        ({"name": "x", "action": "scan_quick", "kind": "interval", "every_minutes": 2}, "between 5"),
        ({"name": "x", "action": "scan_full", "kind": "interval", "every_minutes": 30}, "hourly"),
        ({"name": "x", "action": "scan_quick", "kind": "weekly", "at_time": "10:00", "weekdays": []}, "weekdays"),
        ({"name": "x", "action": "scan_quick", "kind": "weekly", "at_time": "10:00", "weekdays": [7]}, "weekdays"),
        ({"name": "x", "action": "scan_quick", "kind": "monthly", "at_time": "10:00", "month_day": 0}, "month_day"),
        ({"name": "x", "action": "scan_quick", "kind": "once", "run_at": "2020-01-01T00:00:00"}, "future"),
        ({"name": "x", "action": "scan_custom", "kind": "daily", "at_time": "10:00"}, "paths"),
        ({"name": "x", "action": "security_report", "kind": "daily", "at_time": "10:00", "params": {"type": "nope"}},
         "report type"),
        ({"name": "x", "action": "scan_quick", "kind": "daily", "at_time": "10:00", "enabled": "yes"}, "true or false"),
    ]
    for body, needle in bad:
        r = c.post("/api/scheduler/schedules", json=body)
        assert r.status_code == 422 and needle in r.json()["detail"], (body, r.text)
    assert c.post("/api/scheduler/schedules", json={"name": "x", "bogus": 1}).status_code == 422
    # cookies / history can't be cleaned unattended
    prof = c.env / "home" / ".config" / "google-chrome" / "Default"
    prof.mkdir(parents=True)
    (prof / "Preferences").write_text("{}")
    (prof / "Cookies").write_text("x")
    r = c.post("/api/scheduler/schedules", json={"name": "x", "action": "privacy_clean", "kind": "daily",
                                                 "at_time": "10:00", "params": {"categories": ["chrome_cookies"]}})
    assert r.status_code == 422 and "always need a click" in r.json()["detail"], r.text
    r = c.post("/api/scheduler/schedules", json={"name": "cache", "action": "privacy_clean", "kind": "daily",
                                                 "at_time": "10:00", "params": {"categories": ["chrome_cache"]}})
    assert r.status_code == 201 and r.json()["params"] == {"categories": ["chrome_cache"]}

    r = c.post("/api/scheduler/schedules", json={"name": "  Night check ", "action": "posture_check", "kind": "weekly",
                                                 "at_time": "23:15", "weekdays": [4, 0, 4]})
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["name"] == "Night check" and s["weekdays"] == [0, 4] and s["when"] == "Every Monday, Friday at 23:15"
    assert s["created_by"] == "syed" and s["next_run_at"] and s["group"] == "Device security"
    u = c.patch(f"/api/scheduler/schedules/{s['id']}", json={"enabled": False}).json()
    assert u["enabled"] is False and u["next_run_at"] is None and u["at_time"] == "23:15"
    u = c.patch(f"/api/scheduler/schedules/{s['id']}", json={"enabled": True, "kind": "interval",
                                                             "every_minutes": 60}).json()
    assert u["when"] == "Every hour" and u["at_time"] is None and u["weekdays"] == [] and u["next_run_at"]
    assert c.get(f"/api/scheduler/schedules/{s['id']}").json()["runs"] == []

    guest = standard_client(c)
    assert guest.get("/api/scheduler/schedules").status_code == 200
    assert guest.post("/api/scheduler/schedules", json={"name": "x", "action": "scan_quick", "kind": "daily",
                                                        "at_time": "10:00"}).status_code == 403
    assert guest.delete(f"/api/scheduler/schedules/{s['id']}").status_code == 403
    assert guest.post(f"/api/scheduler/schedules/{s['id']}/run").status_code == 403
    assert guest.patch("/api/settings", json={"scheduler_enabled": False}).status_code == 403

    assert c.delete(f"/api/scheduler/schedules/{s['id']}").json()["deleted"]
    assert c.get(f"/api/scheduler/schedules/{s['id']}").status_code == 404
    assert c.delete(f"/api/scheduler/schedules/{s['id']}").status_code == 404


def _only(c, **body):
    """Disable the seeded schedules and create one test schedule."""
    c.app.state.db.execute("UPDATE schedules SET enabled=0, next_run_at=NULL")
    r = c.post("/api/scheduler/schedules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_due_schedule_runs_a_real_scan_and_reschedules(c):
    (c.env / "quick" / "eicar.com").write_text(EICAR)
    (c.env / "quick" / "ok.txt").write_text("hello")
    s = _only(c, name="Lunch scan", action="scan_custom", kind="daily", at_time="13:00",
              params={"paths": [str(c.env / "quick")]})
    svc = sv(c)
    planned = sch._parse(s["next_run_at"])
    assert svc.tick() == {"started": [], "skipped": [], "postponed": []}             # not yet
    svc.clock = lambda: planned + timedelta(seconds=30)
    out = svc.tick()
    assert out["started"] == [s["id"]] and svc.wait_idle(30)
    run = c.get("/api/scheduler/runs").json()["items"][0]
    assert run["status"] == "ok" and run["trigger"] == "schedule" and run["planned_at"] == s["next_run_at"]
    assert run["result"]["threats_found"] == 1 and run["result"]["files_scanned"] == 2
    assert "1 threat(s) found" in run["detail"] and run["duration_seconds"] is not None
    after = c.get(f"/api/scheduler/schedules/{s['id']}").json()
    assert after["last_status"] == "ok" and sch._parse(after["next_run_at"]) == planned + timedelta(days=1)
    assert after["runs"][0]["id"] == run["id"]
    assert svc.tick()["started"] == []                                               # not twice for one slot
    assert c.get("/api/scan/jobs").json()["items"][0]["started_by"] == "scheduler"
    assert c.get("/api/activity?category=scheduler").json()["items"][0]["title"] == "Lunch scan: done"


def test_missed_runs_catch_up_or_skip(c):
    s = _only(c, name="No catch-up", action="firewall_check", kind="daily", at_time="06:00", catch_up=False)
    svc = sv(c)
    planned = sch._parse(s["next_run_at"])
    svc.clock = lambda: planned + timedelta(days=3, hours=2)                          # PC was off for three days
    out = svc.tick()
    assert out["skipped"] == [s["id"]] and out["started"] == []
    runs = c.get(f"/api/scheduler/runs?schedule_id={s['id']}").json()["items"]
    assert len(runs) == 1 and runs[0]["status"] == "skipped" and "off or asleep" in runs[0]["detail"]
    nxt = sch._parse(c.get(f"/api/scheduler/schedules/{s['id']}").json()["next_run_at"])
    assert nxt > svc.clock() and nxt - svc.clock() <= timedelta(days=1)               # next real slot, not 3 make-ups

    c.patch(f"/api/scheduler/schedules/{s['id']}", json={"catch_up": True})
    planned = sch._parse(c.get(f"/api/scheduler/schedules/{s['id']}").json()["next_run_at"])
    svc.clock = lambda: planned + timedelta(days=2)
    assert svc.tick()["started"] == [s["id"]] and svc.wait_idle(30)
    runs = c.get(f"/api/scheduler/runs?schedule_id={s['id']}").json()["items"]
    assert runs[0]["status"] == "ok" and runs[0]["trigger"] == "catch_up" and "Score" in runs[0]["detail"]
    assert len(runs) == 2                                                             # exactly one catch-up run
    assert c.get("/api/scheduler/runs?status=skipped").json()["total"] == 1


def test_battery_postpones_heavy_jobs_only(c):
    s = _only(c, name="Full", action="scan_full", kind="daily", at_time="02:00")
    light = c.post("/api/scheduler/schedules", json={"name": "Light", "action": "network_check", "kind": "daily",
                                                     "at_time": "02:00"}).json()
    svc = sv(c)
    planned = sch._parse(s["next_run_at"])
    svc.clock = lambda: planned + timedelta(seconds=5)
    svc.on_battery = lambda: True
    out = svc.tick()
    assert out["postponed"] == [s["id"]] and out["started"] == [light["id"]] and svc.wait_idle(30)
    full = c.get(f"/api/scheduler/schedules/{s['id']}").json()
    assert sch._parse(full["next_run_at"]) == svc.clock() + timedelta(minutes=30) or \
        abs((sch._parse(full["next_run_at"]) - planned - timedelta(minutes=30)).total_seconds()) < 60
    assert "battery" in full["last_detail"] and c.get("/api/scheduler/status").json()["on_battery"] is True
    c.patch("/api/settings", json={"scheduler_skip_on_battery": False})
    svc.clock = lambda: planned + timedelta(minutes=31)
    assert svc.tick()["started"] == [s["id"]] and svc.wait_idle(60)
    assert c.get(f"/api/scheduler/schedules/{s['id']}").json()["last_status"] == "ok"


def test_once_schedule_switch_and_failures_notify(c):
    svc = sv(c)
    when = datetime.now(timezone.utc) + timedelta(hours=2)
    s = _only(c, name="One time", action="extensions_audit", kind="once", run_at=when.isoformat())
    assert s["when"].startswith("Once, ")
    # master switch off: nothing runs
    c.patch("/api/settings", json={"scheduler_enabled": False})
    svc.clock = lambda: when + timedelta(seconds=1)
    assert svc.tick() == {"started": [], "skipped": [], "postponed": []}
    c.patch("/api/settings", json={"scheduler_enabled": True})
    assert svc.tick()["started"] == [s["id"]] and svc.wait_idle(30)
    after = c.get(f"/api/scheduler/schedules/{s['id']}").json()
    assert after["enabled"] is False and after["next_run_at"] is None and after["last_status"] == "ok"

    # a failing job: custom scan of a folder that disappeared
    gone = c.env / "gone"
    gone.mkdir()
    f = c.post("/api/scheduler/schedules", json={"name": "Scan gone", "action": "scan_custom", "kind": "daily",
                                                 "at_time": "10:00", "params": {"paths": [str(gone)]}}).json()
    gone.rmdir()
    run = c.post(f"/api/scheduler/schedules/{f['id']}/run?wait=true")
    assert run.status_code == 202
    last = c.get(f"/api/scheduler/runs?schedule_id={f['id']}").json()["items"][0]
    assert last["status"] == "failed" and last["trigger"] == "manual" and "Not found" in last["detail"]
    assert last["started_by"] == "syed"
    n = c.get("/api/notifications?source=scheduler").json()["items"]
    assert n and n[0]["title"] == "Scheduled job failed: Scan gone" and n[0]["link"] == "scheduler"
    assert c.get("/api/scheduler/status").json()["runs_7_days"].get("failed") == 1


def test_run_now_report_backup_clean_and_overlap(c):
    by = {s["builtin"]: s for s in c.get("/api/scheduler/schedules").json()["items"]}
    # report (Part 19) as the owner
    assert c.post(f"/api/scheduler/schedules/{by['report_weekly']['id']}/run?wait=true").status_code == 202
    run = c.get(f"/api/scheduler/runs?schedule_id={by['report_weekly']['id']}").json()["items"][0]
    assert run["status"] == "ok", run
    rep = c.get("/api/reports").json()["items"][0]
    assert rep["id"] == run["result"]["report_id"] and rep["source"] == "schedule" and rep["format"] == "pdf"
    assert any(i["kind"] == "report_ready" for i in c.get("/api/notifications?source=reports").json()["items"])
    # backup (device mode, no password)
    assert c.post(f"/api/scheduler/schedules/{by['backup_weekly']['id']}/run?wait=true").status_code == 202
    run = c.get(f"/api/scheduler/runs?schedule_id={by['backup_weekly']['id']}").json()["items"][0]
    assert run["status"] == "ok", run
    assert c.get("/api/backup").json()["items"][0]["mode"] == "device"
    # privacy clean-up (Part 13) with an old temp file
    import os
    tmpd = c.env / "home" / ".cache"
    tmpd.mkdir(parents=True, exist_ok=True)
    assert c.post(f"/api/scheduler/schedules/{by['clean_weekly']['id']}/run?wait=true").status_code == 202
    run = c.get(f"/api/scheduler/runs?schedule_id={by['clean_weekly']['id']}").json()["items"][0]
    assert run["status"] == "ok" and run["detail"].startswith("Freed "), run
    assert os.path.isdir(tmpd)
    # sensitive-file search
    (c.env / "docs" / "keys.txt").write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                                             "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
    assert c.post(f"/api/scheduler/schedules/{by['finder_monthly']['id']}/run?wait=true").status_code == 202
    run = c.get(f"/api/scheduler/runs?schedule_id={by['finder_monthly']['id']}").json()["items"][0]
    assert run["status"] == "ok" and "sensitive file" in run["detail"], run

    # overlap guard
    svc = sv(c)
    import threading
    gate = threading.Event()
    orig = svc._do
    svc._do = lambda *a, **k: (gate.wait(5), ("slow", None))[1]
    sid = by["quick_scan_daily"]["id"]
    assert c.post(f"/api/scheduler/schedules/{sid}/run").status_code == 202
    assert c.get(f"/api/scheduler/schedules/{sid}").json()["running"] is True
    r = c.post(f"/api/scheduler/schedules/{sid}/run")
    assert r.status_code == 409 and "already running" in r.json()["detail"]
    planned = sch._parse(by["quick_scan_daily"]["next_run_at"])
    svc.clock = lambda: planned + timedelta(seconds=1)
    assert sid in svc.tick()["skipped"]
    gate.set()
    assert svc.wait_idle(10)
    svc._do = orig
    statuses = [r["status"] for r in c.get(f"/api/scheduler/runs?schedule_id={sid}").json()["items"]]
    assert sorted(statuses) == ["ok", "skipped"]


def test_interrupted_runs_and_cleanup(c):
    db = c.app.state.db
    sid = c.get("/api/scheduler/schedules").json()["items"][0]["id"]
    db.execute("INSERT INTO schedule_runs(schedule_id, name, action, status) VALUES (?,?,?,?)",
               (sid, "x", "scan_quick", "running"))
    db.execute("INSERT INTO schedule_runs(schedule_id, name, action, status, started_at, finished_at) VALUES (?,?,?,?,?,?)",
               (sid, "old", "scan_quick", "ok", "2020-01-01T00:00:00.000Z", "2020-01-01T00:01:00.000Z"))
    sv(c)._recover()
    runs = {r["name"]: r for r in c.get("/api/scheduler/runs").json()["items"]}
    assert runs["x"]["status"] == "interrupted" and "closed" in runs["x"]["detail"]
    assert runs["old"]["duration_seconds"] == 60.0
    assert sv(c).cleanup() == 1 and c.get("/api/scheduler/runs").json()["total"] == 1
    db.execute("INSERT INTO notifications(ts, source, severity, title) VALUES ('2020-01-01T00:00:00.000Z','system','low','old')")
    assert nc(c).cleanup() == 1
