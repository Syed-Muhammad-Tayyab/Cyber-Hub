"""
Cyber Hub Backend - Part 18 tests: Security Score & Dashboard
Developed by Syed Muhammad Tayyab

The score is built from the real Part 5-16 services (simulated Windows PC / firewall / network from their own
tests), so these tests change real state - an EICAR file, the firewall switched off, a fixed posture check -
and assert that the number, the caps, the recommendations and the history follow.
"""
import time

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS
from cyberhub.main import create_app
from cyberhub.services import security_score as ss

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


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
        cl.headers["X-CyberHub-Session"] = r.json()["session_token"]
        cl.env = env
        yield cl


def score(c, refresh=True):
    r = c.get(f"/api/score?refresh={'true' if refresh else 'false'}")
    assert r.status_code == 200, r.text
    return r.json()


def cat(s, cid):
    return next(x for x in s["categories"] if x["id"] == cid)


def rec_ids(s):
    return {r["id"] for r in s["recommendations"]}


def wait_scan(c, job):
    for _ in range(400):
        j = c.get(f"/api/scan/jobs/{job['id']}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_helpers():
    assert [ss.grade_of(x) for x in (100, 95, 94, 90, 85, 75, 60, 45, 10)] == ["A+", "A+", "A", "A", "B", "C", "D", "E", "F"]
    assert [ss.status_of(x) for x in (None, 95, 90, 89, 70, 69, 50, 49, 0)] == \
        ["not_set_up", "protected", "protected", "good", "good", "attention", "attention", "at_risk", "at_risk"]
    assert sum(w for _, _, w, _ in ss.CATEGORIES) == 100 and len({c[0] for c in ss.CATEGORIES}) == 9


def test_score_shape_weights_and_unused_modules(c):
    info = c.get("/api/info").json()
    assert "score" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 90
    assert c.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 19
    s = score(c)
    assert [x["id"] for x in s["categories"]] == [x[0] for x in ss.CATEGORIES]
    assert 0 <= s["score"] <= 100 and s["grade"] == ss.grade_of(s["score"]) and s["status_text"]
    # modules the user hasn't set up neither help nor hurt
    for cid in ("passwords", "accounts", "web"):
        x = cat(s, cid)
        assert x["score"] is None and x["status"] == "not_set_up" and x["note"] and x["issues"] == 0
    scored = [x for x in s["categories"] if x["score"] is not None]
    assert s["scored_categories"] == len(scored) == 6
    raw = round(sum(x["score"] * x["weight"] for x in scored) / sum(x["weight"] for x in scored))
    assert s["raw_score"] == raw
    # the category numbers are the modules' own numbers
    assert cat(s, "device")["score"] == c.get("/api/posture/checks").json()["score"]
    assert cat(s, "firewall")["score"] == c.get("/api/firewall/analysis").json()["score"]
    assert cat(s, "data")["score"] == c.get("/api/data/health").json()["score"]
    assert cat(s, "intel")["score"] == c.get("/api/intel/health").json()["score"]
    # the simulated PC has a failing device-security section -> cap at 59 with the reason
    assert cat(s, "device")["status"] == "at_risk" and s["raw_score"] > 59
    assert s["score"] == 59 and s["caps"] == [{"limit": 59, "reason": "Device security is at risk"}]
    assert s["headline"].endswith("important problem(s) to fix") and s["counts"]["high"] >= 1
    # recommendations: sorted by severity, each with a page; module fixes carry the exact API call
    sev = [ss.SEVERITIES.index(r["severity"]) for r in s["recommendations"]]
    assert sev == sorted(sev, reverse=True) and all(r["link"] for r in s["recommendations"])
    ids = rec_ids(s)
    assert {"protection:never_scanned", "passwords:setup", "accounts:setup", "data:never_searched",
            "intel:no_feeds", "account:recovery_codes"} <= ids
    never = next(r for r in s["recommendations"] if r["id"] == "protection:never_scanned")
    assert never["action"] == {"label": "Run a quick scan", "method": "POST", "path": "/api/scan/quick", "body": None,
                               "admin": False}
    assert s["recommendations_total"] == len(s["recommendations"]) == sum(s["counts"].values())
    f = c.get("/api/score/recommendations?severity=high&category=device").json()
    assert f["total"] >= 1 and all(r["severity"] == "high" and r["category"] == "device" for r in f["items"])
    assert c.get("/api/score").status_code == 200 and TestClient(c.app).get("/api/score").status_code == 401


def test_recommended_actions_really_work_and_raise_the_score(c):
    s0 = score(c)
    d0 = cat(s0, "device")["score"]
    fixable = [r for r in s0["recommendations"] if r["category"] == "device" and r["action"]]
    assert len(fixable) >= 5
    done = 0
    for r in fixable:
        a = r["action"]
        res = c.request(a["method"], a["path"], json=a["body"])
        if res.status_code == 428:                                    # fix with side effects: confirm it
            res = c.request(a["method"], a["path"], json={"confirm": True})
        assert res.status_code == 200, (r["id"], res.text)
        done += 1
    s1 = score(c)
    assert cat(s1, "device")["score"] > d0 and cat(s1, "device")["issues"] == cat(s0, "device")["issues"] - done
    assert not ({r["id"] for r in fixable} & rec_ids(s1))
    assert s1["raw_score"] > s0["raw_score"]
    # the scan recommendation: run it, the recommendation disappears and protection goes up
    p0 = cat(s1, "protection")["score"]
    a = next(r for r in s1["recommendations"] if r["id"] == "protection:never_scanned")["action"]
    assert wait_scan(c, c.request(a["method"], a["path"]).json())["status"] == "completed"
    s2 = score(c)
    assert "protection:never_scanned" not in rec_ids(s2) and cat(s2, "protection")["score"] > p0
    assert cat(s2, "protection")["facts"]["last_scan"] and cat(s2, "protection")["facts"]["days_since_last_scan"] == 0


def test_active_threat_and_protection_switches(c):
    wait_scan(c, c.post("/api/scan/quick").json())
    base = cat(score(c), "protection")
    assert base["score"] == 100 and base["issues"] == 0 and base["facts"]["realtime"] == "on"
    # the EICAR test file is a "low" threat: worth a look, the area is no longer fully protected
    (c.env / "quick" / "eicar.com").write_text(EICAR)
    assert wait_scan(c, c.post("/api/scan/custom", json={"paths": [str(c.env / "quick")]}).json())["threats_found"] == 1
    s = score(c)
    p = cat(s, "protection")
    assert p["score"] <= 84 and p["status"] == "good" and p["worst"] == "medium" and p["facts"]["active_threats"] == 1
    # a known-bad file of high severity puts the whole PC "at risk"
    import hashlib
    bad = c.env / "quick" / "invoice.exe"
    bad.write_bytes(b"MZ-not-really-malware-" * 20)
    r = c.post("/api/scan/signatures", json={"hash": hashlib.sha256(bad.read_bytes()).hexdigest(),
                                             "name": "Trojan.Test.Tayyab", "severity": "high"})
    assert r.status_code in (200, 201), r.text
    assert wait_scan(c, c.post("/api/scan/custom", json={"paths": [str(bad)]}).json())["threats_found"] == 1
    s = score(c)
    p = cat(s, "protection")
    assert p["score"] <= 49 and p["status"] == "at_risk" and p["worst"] == "critical"
    assert p["facts"]["active_threats"] == 2 and s["score"] <= 59
    assert s["headline"] == "1 critical problem(s) need your attention now"
    top = s["recommendations"][0]
    assert top["id"] == "protection:active_threats" and top["severity"] == "critical"
    r = c.request(top["action"]["method"], top["action"]["path"], json=top["action"]["body"])
    assert r.status_code == 200 and r.json()["succeeded"] == 2, r.text   # "Quarantine all" from the dashboard
    p = cat(score(c), "protection")
    assert p["score"] == 100 and p["facts"]["active_threats"] == 0 and not bad.exists()

    assert c.post("/api/realtime/disable").status_code == 200
    s = score(c)
    p = cat(s, "protection")
    assert p["score"] <= 84 and "protection:realtime_off" in rec_ids(s) and p["facts"]["realtime"] == "off"
    a = next(r for r in s["recommendations"] if r["id"] == "protection:realtime_off")["action"]
    assert c.request(a["method"], a["path"]).status_code == 200
    assert cat(score(c), "protection")["score"] == 100
    c.patch("/api/settings", json={"yara_enabled": False, "heuristics_enabled": False})
    s = score(c)
    assert {"protection:yara_off", "protection:heuristics_off"} <= rec_ids(s) and cat(s, "protection")["score"] < 100


def test_firewall_off_is_a_critical_finding_with_one_click_fix(c):
    s0 = score(c)
    assert cat(s0, "firewall")["score"] == 100
    assert c.patch("/api/firewall/profiles/public", json={"enabled": False}).status_code == 200
    s = score(c)
    fw = cat(s, "firewall")
    assert fw["score"] < 100 and fw["worst"] == "critical" and s["counts"]["critical"] >= 1
    r = next(x for x in s["recommendations"] if x["category"] == "firewall" and x["severity"] == "critical")
    assert "OFF" in r["title"] and r["action"]["label"] == "Turn on"
    assert c.request(r["action"]["method"], r["action"]["path"]).status_code == 200
    assert cat(score(c), "firewall")["score"] == 100


def test_failing_module_is_reported_not_guessed(c):
    svc = c.app.state.score
    orig = svc.network.analyze
    svc.network.analyze = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("probe exploded"))
    s = score(c)
    n = cat(s, "network")
    assert n["score"] is None and n["status"] == "unavailable" and "probe exploded" in n["note"]
    assert s["scored_categories"] == 5 and 0 < s["score"] <= 100
    svc.network.analyze = orig
    assert cat(score(c), "network")["score"] is not None
    d = c.app.state.score
    saved = (d.scanner, d.posture)
    d.scanner = d.posture = None
    s = score(c)
    assert cat(s, "protection")["note"] == "Module not loaded" and cat(s, "device")["status"] == "unavailable"
    d.scanner, d.posture = saved


def test_history_cache_and_drop_notification(c):
    db = c.app.state.db
    s = score(c)
    assert s["change"] is None
    h = c.get("/api/score/history?days=7").json()
    assert len(h["points"]) == 1 and h["last"] == s["score"] and h["points"][0]["categories"]["device"] is not None
    score(c)                                                           # unchanged within the hour: no new point
    assert len(c.get("/api/score/history").json()["points"]) == 1
    # the short cache: a change is not seen without refresh
    c.post("/api/realtime/disable")
    assert cat(score(c, refresh=False), "protection") == cat(s, "protection")
    s2 = score(c)
    assert cat(s2, "protection")["score"] < cat(s, "protection")["score"]
    assert len(c.get("/api/score/history").json()["points"]) == 2      # category changed -> new point
    # a real drop raises a notification for that user
    c.patch("/api/settings", json={"score_alert_drop": 5})
    db.execute("UPDATE security_scores SET score=95 WHERE id=(SELECT MAX(id) FROM security_scores)")
    s3 = score(c)
    assert s3["change"]["from"] == 95 and s3["change"]["delta"] == s3["score"] - 95
    n = c.get("/api/notifications?source=system").json()["items"]
    assert n and n[0]["kind"] == "score_drop" and f"from 95 to {s3['score']}" in n[0]["title"] and n[0]["link"] == "dashboard"
    assert c.app.state.score.record_all() == 1
    db.execute("INSERT INTO security_scores(ts, user_id, score, grade, status) VALUES ('2020-01-01T00:00:00.000Z',1,50,'E','attention')")
    assert c.app.state.score.cleanup() == 1
    assert c.patch("/api/settings", json={"score_alert_drop": 101}).status_code == 422


def test_dashboard_one_call_and_isolation(c):
    wait_scan(c, c.post("/api/scan/quick").json())
    c.app.state.notifications.notify("firewall", "high", "Something happened")
    d = c.get("/api/dashboard?days=7").json()
    assert set(d) >= {"score", "score_history", "tiles", "threats", "scans", "realtime", "system", "network",
                      "activity", "notifications", "schedule", "user", "generated_at"}
    assert d["user"]["username"] == "syed" and d["score"]["score"] == c.get("/api/score").json()["score"]
    assert [t["id"] for t in d["tiles"]] == [x[0] for x in ss.CATEGORIES] and all("status_text" in t for t in d["tiles"])
    assert d["scans"]["status"] != "never_scanned" and d["scans"]["last_scan"] and d["scans"]["signatures"] >= 1
    assert d["threats"]["active"] == 0 and d["threats"]["days"] == 7
    assert d["realtime"]["enabled"] is True
    assert d["system"]["stats"]["memory_total_gb"] > 0 and d["system"]["device"]["hostname"]
    assert d["network"]["firewall"]["score"] == 100 and d["network"]["network"]["connections"]["total"] >= 0
    assert d["notifications"]["unread"] == 1 and d["notifications"]["latest"][0]["title"] == "Something happened"
    assert d["schedule"]["status"]["active"] == 2 and len(d["schedule"]["upcoming"]) >= 1
    assert d["activity"]["latest"] and d["activity"]["summary"]["days"] == 7
    # one broken module leaves an error in its block and nothing else changes
    th = c.app.state.score.threat_history
    orig = th.summary
    th.summary = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("history broken"))
    d2 = c.get("/api/dashboard").json()
    th.summary = orig
    assert "history broken" in d2["threats"]["error"] and d2["score"]["score"] == d["score"]["score"]
    assert d2["scans"]["status"] == d["scans"]["status"]
    assert c.get("/api/dashboard?days=0").status_code == 422


def test_dashboard_stream(c):
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    with c.websocket_connect(f"/api/dashboard/stream?token={tok}&session={ses}&interval=1") as ws:
        m = ws.receive_json()
        assert m["type"] == "dashboard" and m["score"] == c.get("/api/score").json()["score"]
        assert len(m["tiles"]) == 9 and "cpu_percent" in m["stats"] and m["unread"] == 0
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/dashboard/stream?token={tok}&session=nope") as ws:
            ws.receive_json()
