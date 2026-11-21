"""
Cyber Hub Backend - Part 9 tests: Firewall & Network Protection
Developed by Syed Muhammad Tayyab

The API tests drive the in-memory Windows-like firewall (CYBERHUB_FIREWALL_BACKEND
=memory), so every block / rule / profile change is real state that can be read
back. The Windows and ufw backends are tested separately with fake PowerShell /
ufw runners: the parsers get real-shaped output, and the tests check that user
input only ever reaches PowerShell through environment variables.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.main import create_app
from cyberhub.services import fwlog
from cyberhub.services.firewall import (FirewallError, parse_address, parse_port_ranges, parse_port_spec,
                                        rule_flags)
from cyberhub.services.firewall_backends import (PS_ADD_RULE, PS_PROFILES, PS_RULES, PS_SET_PROFILE,
                                                 BackendError, MemoryFirewall, UfwFirewall, WindowsFirewall,
                                                 parse_ufw_numbered, parse_ufw_verbose, pick_backend)
from cyberhub.services.platform_tools import CACHE

PW = "Cyb3r!Hub#2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("apps", "quick", "full", "watched"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    monkeypatch.setenv("CYBERHUB_RTP_DEFAULT_DIRS", str(tmp_path / "watched"))
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "memory")
    return tmp_path


@pytest.fixture(autouse=True)
def no_tmp_guard(monkeypatch):
    """pytest's files live under /tmp, which the guard (rightly) treats as a malware location."""
    from cyberhub.services import firewall as fwmod
    monkeypatch.setattr(fwmod, "SUSPICIOUS_DIRS", tuple(d for d in fwmod.SUSPICIOUS_DIRS if d != "/tmp/"))


def _login(cl, user="syed"):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        yield cl


def fw(c):
    return c.app.state.firewall


def mem(c) -> MemoryFirewall:
    return c.app.state.firewall.backend


def make_app(env, name="app.exe", sub="apps") -> str:
    p = env / sub / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"MZ fake program " + name.encode())
    return str(p)


def as_standard(c):
    """Log the client in as a standard (non-admin) user; returns a restore function."""
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    admin = c.headers["X-CyberHub-Session"]
    r = c.post("/api/account/login", json={"username": "kid", "password": PW})
    c.headers["X-CyberHub-Session"] = r.json()["session_token"]

    def back():
        c.headers["X-CyberHub-Session"] = admin
    return back


# ====================================================================== status & profiles
def test_status_and_info(c):
    s = c.get("/api/firewall/status").json()
    assert s["backend"]["name"] == "memory" and s["can_modify"] is True
    assert s["state"] == "on" and s["shields_up"] is False
    assert {p["name"] for p in s["profiles"]} == {"domain", "private", "public"}
    assert next(p for p in s["profiles"] if p["name"] == "private")["active"] is True      # HomeWiFi is private
    assert s["rules"]["total"] == 5 and s["rules"]["policy_managed"] == 1
    assert 0 <= s["score"] <= 100 and s["grade"]
    j = c.get("/api/info").json()
    assert j["build_part"] >= 9 and j["progress_percent"] >= 45 and "firewall" in j["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 10


def test_requires_session(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        assert cl.get("/api/firewall/status").status_code == 401


def test_profile_toggle_and_permissions(c):
    r = c.patch("/api/firewall/profiles/public", json={"enabled": False})
    assert r.status_code == 200
    pub = next(p for p in r.json()["profiles"] if p["name"] == "public")
    assert pub["enabled"] is False
    assert c.get("/api/firewall/status").json()["state"] == "partial"
    ev = c.get("/api/firewall/events").json()["items"]
    assert ev[0]["kind"] == "firewall_off" and ev[0]["severity"] == "high" and ev[0]["username"] == "syed"
    acts = c.get("/api/activity?category=firewall").json()["items"]
    assert any("turned OFF" in a["title"] for a in acts)

    back = as_standard(c)
    try:
        assert c.patch("/api/firewall/profiles/public", json={"enabled": True}).status_code == 200   # raising
        assert c.patch("/api/firewall/profiles/public", json={"enabled": False}).status_code == 403
        assert c.patch("/api/firewall/profiles/public", json={"default_inbound": "allow"}).status_code == 403
        assert c.post("/api/firewall/shields-up", json={"on": True}).status_code == 200
        assert c.post("/api/firewall/shields-up", json={"on": False}).status_code == 403
    finally:
        back()
    s = c.get("/api/firewall/status").json()
    assert s["state"] == "on" and s["shields_up"] is True
    assert all(not p["allow_inbound_rules"] for p in mem(c)._profiles.values())
    assert c.post("/api/firewall/shields-up", json={"on": False}).status_code == 200
    assert c.patch("/api/firewall/profiles/bogus", json={"enabled": True}).status_code == 404
    assert c.patch("/api/firewall/profiles/public", json={}).status_code == 400
    assert c.patch("/api/firewall/profiles/public", json={"default_inbound": "maybe"}).status_code == 422


def test_profile_all_and_logging(c):
    r = c.patch("/api/firewall/profiles/all", json={"log_blocked": True, "notify_on_listen": True})
    assert r.status_code == 200 and all(p["log_blocked"] for p in r.json()["profiles"])


def test_not_elevated_gives_clear_403(c, env):
    mem(c).elevated = False
    r = c.post("/api/firewall/block/app", json={"path": make_app(env)})
    assert r.status_code == 403 and "start_cyberhub_admin.bat" in r.json()["detail"]
    assert c.patch("/api/firewall/profiles/public", json={"enabled": True}).status_code == 403
    a = c.get("/api/firewall/analysis").json()
    assert any(f["id"] == "not_elevated" for f in a["findings"])
    assert c.get("/api/firewall/status").json()["can_modify"] is False
    assert c.get("/api/firewall/blocks").json()["total"] == 0


# ====================================================================== rules
def test_rules_list_filters_and_flags(c):
    j = c.get("/api/firewall/rules").json()
    assert j["total"] == 5 and j["counts"]["inbound_allow"] == 1        # only DHCP-In is enabled + allow + in
    names = [r["name"] for r in j["items"]]
    assert names == sorted(names, key=str.lower)
    assert c.get("/api/firewall/rules?direction=out").json()["total"] == 1
    assert c.get("/api/firewall/rules?action=block").json()["total"] == 1
    assert c.get("/api/firewall/rules?enabled=false").json()["total"] == 2
    assert c.get("/api/firewall/rules?search=remote desktop").json()["total"] == 1
    assert c.get("/api/firewall/rules?search=3389").json()["total"] == 1
    assert c.get("/api/firewall/rules?origin=policy").json()["total"] == 1
    assert c.get("/api/firewall/rules?profile=public").json()["total"] == 4
    r = c.get("/api/firewall/rules/RemoteDesktop-UserMode-In-TCP").json()
    assert r["direction"] == "in" and r["local_ports"] == "3389" and r["cyberhub"] is False
    assert c.get("/api/firewall/rules/nope").status_code == 404


def test_rule_toggle_permissions(c):
    rid = "RemoteDesktop-UserMode-In-TCP"
    back = as_standard(c)
    try:
        r = c.patch(f"/api/firewall/rules/{rid}", json={"enabled": True})       # ALLOW on = lowers protection
        assert r.status_code == 403
        assert c.patch("/api/firewall/rules/CoreNet-DHCP-In", json={"enabled": False}).status_code == 200
    finally:
        back()
    r = c.patch(f"/api/firewall/rules/{rid}", json={"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert any(f["code"] == "exposed_service" and f["severity"] == "high" for f in r.json()["flags"])
    flagged = c.get("/api/firewall/rules?flagged=true&sort=risk").json()
    assert flagged["items"][0]["id"] == rid
    r = c.patch("/api/firewall/rules/CorpPolicy-Block-Telnet", json={"enabled": False})
    assert r.status_code == 409 and "Group Policy" in r.json()["detail"]
    ev = c.get("/api/firewall/events?kind=rule_enabled").json()["items"]
    assert ev and ev[0]["severity"] == "medium"


def test_delete_rule_rules(c, env):
    r = c.delete("/api/firewall/rules/FPS-SMB-In-TCP")
    assert r.status_code == 409 and "force" in r.json()["detail"]
    assert c.delete("/api/firewall/rules/FPS-SMB-In-TCP?force=true").status_code == 200
    assert "FPS-SMB-In-TCP" not in mem(c)._rules
    b = c.post("/api/firewall/block/app", json={"path": make_app(env)}).json()
    r = c.delete(f"/api/firewall/rules/{b['rule_ids'][0]}")
    assert r.status_code == 409 and f"#{b['id']}" in r.json()["detail"]
    back = as_standard(c)
    try:
        assert c.delete("/api/firewall/rules/CoreNet-DHCP-In?force=true").status_code == 403
    finally:
        back()


# ====================================================================== blocks
def test_block_app_both_directions_and_unblock(c, env):
    path = make_app(env, "game.exe")
    r = c.post("/api/firewall/block/app", json={"path": path, "reason": "kids"})
    assert r.status_code == 201
    b = r.json()
    assert b["kind"] == "app" and b["label"] == "game.exe" and b["status"] == "active" and b["already"] is False
    assert b["rule_ids"] == [f"CyberHub-B{b['id']}-in", f"CyberHub-B{b['id']}-out"]
    assert b["sha256"] and b["temporary"] is False
    for rid in b["rule_ids"]:
        rule = mem(c)._rules[rid]
        assert rule["program"] == path and rule["action"] == "block" and rule["group"] == "Cyber Hub"
    listed = c.get("/api/firewall/rules?origin=cyberhub").json()["items"]
    assert {x["id"] for x in listed} == set(b["rule_ids"]) and all(x["block_id"] == b["id"] for x in listed)
    again = c.post("/api/firewall/block/app", json={"path": path}).json()
    assert again["already"] is True and again["id"] == b["id"]
    assert c.get("/api/firewall/status").json()["blocks"]["by_kind"]["app"] == 1

    back = as_standard(c)
    try:
        assert c.delete(f"/api/firewall/blocks/{b['id']}").status_code == 403
        assert c.post("/api/firewall/block/app", json={"path": make_app(env, "other.exe")}).status_code == 201
    finally:
        back()
    r = c.delete(f"/api/firewall/blocks/{b['id']}")
    assert r.status_code == 200 and r.json()["status"] == "removed" and r.json()["ended_by"] == "syed"
    assert not any(k.startswith(f"CyberHub-B{b['id']}-") for k in mem(c)._rules)
    assert c.delete(f"/api/firewall/blocks/{b['id']}").status_code == 409
    assert c.get("/api/firewall/blocks?status=removed").json()["total"] == 1
    kinds = [e["kind"] for e in c.get("/api/firewall/events").json()["items"]]
    assert "block_created" in kinds and "block_removed" in kinds


def test_block_app_guards(c, env):
    assert c.post("/api/firewall/block/app", json={"path": "relative.exe"}).status_code == 400
    assert c.post("/api/firewall/block/app", json={"path": str(env / "missing.exe")}).status_code == 404
    r = c.post("/api/firewall/block/app", json={"path": sys.executable})
    assert r.status_code == 403 and "Cyber Hub" in r.json()["detail"]
    svc = make_app(env, "svchost.exe", "win")
    r = c.post("/api/firewall/block/app", json={"path": svc})
    assert r.status_code == 403 and "force" in r.json()["detail"]
    assert c.post("/api/firewall/block/app", json={"path": svc, "force": True}).status_code == 201
    back = as_standard(c)
    try:
        assert c.post("/api/firewall/block/app", json={"path": make_app(env, "x.exe"), "force": True}
                      ).status_code == 403
    finally:
        back()
    mem(c).fail = BackendError(400, "simulated failure")
    r = c.post("/api/firewall/block/app", json={"path": make_app(env, "y.exe")})
    assert r.status_code == 400
    assert c.get("/api/firewall/blocks?status=current").json()["total"] == 1   # failed block left nothing behind


def test_partial_failure_rolls_back(c, env):
    m = mem(c)
    real = m.add_rule
    calls = {"n": 0}

    def flaky(spec):
        calls["n"] += 1
        if calls["n"] == 2:
            raise BackendError(400, "out of rules")
        real(spec)
    m.add_rule = flaky
    r = c.post("/api/firewall/block/app", json={"path": make_app(env)})
    assert r.status_code == 400
    assert not any(k.startswith("CyberHub-") for k in m._rules)
    assert c.get("/api/firewall/blocks").json()["total"] == 0


def test_block_process(c, env):
    exe = env / "apps" / "sleeper"
    shutil.copy(shutil.which("sleep"), exe)
    os.chmod(exe, 0o755)
    p = subprocess.Popen([str(exe), "30"])
    try:
        time.sleep(0.2)
        r = c.post("/api/firewall/block/process", json={"pid": p.pid, "direction": "out"})
        assert r.status_code == 201, r.text
        b = r.json()
        assert b["target"] == str(exe) and b["rule_ids"] == [f"CyberHub-B{b['id']}-out"]
        assert f"PID {p.pid}" in b["reason"]
        r = c.post("/api/firewall/block/process", json={"pid": p.pid, "create_time": 1.0})
        assert r.status_code == 409
        assert c.post("/api/firewall/block/process", json={"pid": os.getpid()}).status_code == 403
    finally:
        p.kill()
        p.wait()
    assert c.post("/api/firewall/block/process", json={"pid": 999999}).status_code == 404


def test_block_ip(c):
    r = c.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.7", "198.51.100.0/24",
                                                             "203.0.113.20-203.0.113.30", "203.0.113.7"]})
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["target"] == "203.0.113.7,198.51.100.0/24,203.0.113.20-203.0.113.30"
    assert b["label"] == "203.0.113.7 +2 more" and b["warnings"] == []
    rule = mem(c)._rules[b["rule_ids"][0]]
    assert rule["remote_addresses"] == b["target"] and rule["program"] is None
    r = c.post("/api/firewall/block/ip", json={"addresses": ["192.168.1.50"], "direction": "in"})
    assert r.status_code == 201 and "local network" in r.json()["warnings"][0]
    same = c.post("/api/firewall/block/ip", json={"addresses": ["198.51.100.0/24", "203.0.113.20-203.0.113.30",
                                                                "203.0.113.7"]}).json()
    assert same["already"] is True and same["id"] == b["id"]
    for bad in (["127.0.0.1"], ["0.0.0.0"], ["::1"], ["not-an-ip"], ["10.0.0.9-10.0.0.1"], ["1.2.3.4-::5"],
                ["127.0.0.0/30"]):
        assert c.post("/api/firewall/block/ip", json={"addresses": bad}).status_code == 400, bad
    r = c.post("/api/firewall/block/ip", json={"addresses": ["64.0.0.0/4"]})
    assert r.status_code == 400 and "force" in r.json()["detail"]
    assert c.post("/api/firewall/block/ip", json={"addresses": ["64.0.0.0/4"], "force": True}).status_code == 201
    assert c.post("/api/firewall/block/ip", json={"addresses": []}).status_code == 422


def test_parse_address_own_ip():
    import ipaddress
    own = {ipaddress.ip_address("192.168.1.10")}
    with pytest.raises(FirewallError):
        parse_address("192.168.1.10", own=own)
    with pytest.raises(FirewallError):
        parse_address("192.168.1.0/24", own=own)
    n, w = parse_address("192.168.1.0/24", force=True, own=own)
    assert n == "192.168.1.0/24" and w
    with pytest.raises(FirewallError):
        parse_address("192.168.1.5-192.168.1.20", own=own)
    assert parse_address("2001:db8::1", own=set())[0] == "2001:db8::1"
    assert parse_address("203.0.113.9/24", own=set())[0] == "203.0.113.0/24"
    assert "multicast" in parse_address("239.1.1.1", own=set())[1][0]


def test_block_port(c):
    r = c.post("/api/firewall/block/port", json={"ports": "445", "protocol": "both"})
    assert r.status_code == 201
    b = r.json()
    assert b["label"] == "TCP/UDP 445 (SMB file sharing)"
    assert b["rule_ids"] == [f"CyberHub-B{b['id']}-in-tcp", f"CyberHub-B{b['id']}-in-udp"]
    assert mem(c)._rules[b["rule_ids"][0]]["local_ports"] == "445"
    r = c.post("/api/firewall/block/port", json={"ports": "6000-6010, 7000", "direction": "out"})
    assert r.status_code == 201 and mem(c)._rules[r.json()["rule_ids"][0]]["remote_ports"] == "6000-6010,7000"
    r = c.post("/api/firewall/block/port", json={"ports": "443", "direction": "out"})
    assert r.status_code == 400 and "HTTPS" in r.json()["detail"]
    r = c.post("/api/firewall/block/port", json={"ports": "1-100", "direction": "both"})
    assert r.status_code == 400 and "DNS" in r.json()["detail"]
    assert c.post("/api/firewall/block/port", json={"ports": "443", "direction": "out", "force": True}
                  ).status_code == 201
    for bad in ("0", "70000", "90-80", "abc", ",".join(str(i) for i in range(1, 30))):
        assert c.post("/api/firewall/block/port", json={"ports": bad}).status_code == 400, bad
    assert c.post("/api/firewall/block/port", json={"ports": "22", "protocol": "icmp"}).status_code == 422


def test_temporary_block_expires(c, env):
    b = c.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.99"], "minutes": 30}).json()
    assert b["temporary"] is True and 1700 < b["remaining_seconds"] <= 1800
    assert c.get("/api/firewall/status").json()["blocks"]["expiring_24h"] == 1
    assert fw(c).expire_due() == []
    c.app.state.db.execute("UPDATE firewall_blocks SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?", (b["id"],))
    assert fw(c).expire_due() == [b["id"]]
    got = c.get(f"/api/firewall/blocks/{b['id']}").json()
    assert got["status"] == "expired" and got["remaining_seconds"] is None
    assert not any(k.startswith(f"CyberHub-B{b['id']}-") for k in mem(c)._rules)
    assert c.get("/api/firewall/events?kind=block_expired").json()["total"] == 1


def test_verify_and_repair_missing_block(c, env):
    b = c.post("/api/firewall/block/app", json={"path": make_app(env)}).json()
    mem(c).delete_rule(b["rule_ids"][1])                       # someone deletes our rule behind our back
    v = c.post("/api/firewall/blocks/verify").json()
    assert v["missing"] == [b["id"]]
    assert c.get(f"/api/firewall/blocks/{b['id']}").json()["status"] == "missing"
    ev = c.get("/api/firewall/events?severity=high").json()["items"]
    assert ev and ev[0]["kind"] == "block_missing" and ev[0]["acknowledged"] is False
    a = c.get("/api/firewall/analysis").json()
    f = next(x for x in a["findings"] if x["id"] == f"block_missing:{b['id']}")
    assert f["fix"]["action"] == "repair_block"
    r = c.post(f"/api/firewall/blocks/{b['id']}/repair")
    assert r.status_code == 200 and r.json()["recreated"] == 1 and r.json()["status"] == "active"
    assert b["rule_ids"][1] in mem(c)._rules
    assert c.post("/api/firewall/blocks/verify").json()["missing"] == []


def test_allow_app(c, env):
    path = make_app(env, "server.exe", "prog")
    back = as_standard(c)
    try:
        assert c.post("/api/firewall/allow/app", json={"path": path}).status_code == 403
    finally:
        back()
    r = c.post("/api/firewall/allow/app", json={"path": path})
    assert r.status_code == 201
    a = r.json()
    assert a["kind"] == "allow_app" and a["profiles"] == ["private"] and a["rule_ids"] == [f"CyberHub-A{a['id']}-in"]
    rule = mem(c)._rules[a["rule_ids"][0]]
    assert rule["action"] == "allow" and rule["profiles"] == ["private"]
    temp = make_app(env, "evil.exe", "Downloads")
    r = c.post("/api/firewall/allow/app", json={"path": temp})
    assert r.status_code == 403 and "Downloads" in r.json()["detail"]
    assert c.post("/api/firewall/allow/app", json={"path": path, "profiles": ["moon"]}).status_code == 400


# ====================================================================== analysis & fixes
def test_analysis_and_fixes(c, env):
    m = mem(c)
    base = c.get("/api/firewall/analysis").json()
    m._profiles["public"]["enabled"] = False
    m._profiles["private"]["default_inbound"] = "allow"
    m._rules["RemoteDesktop-UserMode-In-TCP"]["enabled"] = True
    m.add_rule({"id": "Bad-AllowAll", "name": "Totally legit", "direction": "in", "action": "allow"})
    m.add_rule({"id": "Old-App", "name": "Old app", "direction": "in", "action": "allow",
                "program": str(env / "gone" / "old.exe")})
    m.add_rule({"id": "Temp-App", "name": "Temp app", "direction": "in", "action": "allow",
                "program": make_app(env, "t.exe", "Downloads")})
    fw(c).invalidate()
    a = c.get("/api/firewall/analysis").json()
    ids = {f["id"]: f for f in a["findings"]}
    assert ids["profile_off:public"]["severity"] == "critical"
    assert ids["inbound_allow:private"]["severity"] == "high"
    assert ids["allow_all:Bad-AllowAll"]["severity"] == "high"
    assert ids["exposed_service:RemoteDesktop-UserMode-In-TCP"]["severity"] == "high"
    assert ids["suspicious_location:Temp-App"]["severity"] == "medium"
    assert ids["orphaned_rules"]["rule_ids"] == ["Old-App"] and ids["orphaned_rules"]["fix_requires_admin"]
    assert a["score"] < base["score"] and a["grade"] == "At risk"
    assert a["findings"][0]["severity"] == "critical"
    st = c.get("/api/firewall/status").json()
    assert st["findings"]["critical"] == 1 and st["score"] == a["score"]

    back = as_standard(c)
    try:
        assert c.post("/api/firewall/findings/profile_off:public/fix").status_code == 200
        assert c.post("/api/firewall/findings/allow_all:Bad-AllowAll/fix").status_code == 200
        assert c.post("/api/firewall/findings/orphaned_rules/fix").status_code == 403
    finally:
        back()
    assert m._profiles["public"]["enabled"] is True and m._rules["Bad-AllowAll"]["enabled"] is False
    r = c.post("/api/firewall/findings/orphaned_rules/fix")
    assert r.status_code == 200 and "Old-App" not in m._rules and r.json()["changes"] == 1
    for fid in ("inbound_allow:private", "exposed_service:RemoteDesktop-UserMode-In-TCP",
                "suspicious_location:Temp-App"):
        assert c.post(f"/api/firewall/findings/{fid}/fix").status_code == 200, fid
    after = c.get("/api/firewall/analysis?refresh=true").json()
    assert after["score"] > a["score"] and not any(f["severity"] in ("critical", "high") for f in after["findings"])
    assert c.post("/api/firewall/findings/profile_off:public/fix").status_code == 404


def test_rule_flag_helpers(tmp_path):
    base = {"enabled": True, "direction": "in", "action": "allow", "profiles": ["domain", "private", "public"],
            "program": None, "service": None, "package": None, "protocol": "tcp", "remote_addresses": "any"}
    assert rule_flags(base | {"local_ports": "3389"})[0]["code"] == "exposed_service"
    assert rule_flags(base | {"local_ports": "3389", "remote_addresses": "LocalSubnet"}) == []
    assert rule_flags(base | {"local_ports": "3000-3400", "profiles": ["private"]})[0]["severity"] == "medium"
    assert rule_flags(base | {"local_ports": "8080"}) == []
    assert rule_flags(base | {"local_ports": "3389", "enabled": False}) == []
    assert rule_flags(base | {"local_ports": "any", "protocol": "any"})[0]["code"] == "allow_all"
    assert rule_flags(base | {"local_ports": "any", "program": r"%SystemRoot%\system32\svchost.exe"}) == []
    assert parse_port_ranges("RPC,135,5000-5010") == [(135, 135), (5000, 5010)]
    assert parse_port_ranges("Any") is None
    assert parse_port_spec(" 80, 443,80 ,6000-6010") == ["80", "443", "6000-6010"]


# ====================================================================== watch
def test_watch_baseline_and_alerts(c, env):
    first = c.post("/api/firewall/watch").json()
    assert first["baseline"] is True and first["rules"] == 5
    quiet = c.post("/api/firewall/watch").json()
    assert quiet["new"] == quiet["removed"] == quiet["changed"] == quiet["alerts"] == 0

    # Cyber Hub's own changes never trigger alerts
    b = c.post("/api/firewall/block/app", json={"path": make_app(env)}).json()
    c.patch("/api/firewall/profiles/domain", json={"log_blocked": True})
    c.patch("/api/firewall/rules/CoreNet-DHCP-In", json={"enabled": False})
    w = c.post("/api/firewall/watch").json()
    assert w["new"] == w["changed"] == w["alerts"] == 0 and w["profile_changes"] == []

    m = mem(c)
    before = c.get("/api/firewall/events").json()["last_id"]
    m.add_rule({"id": "Malware-RDP", "name": "Windows Update Helper", "direction": "in", "action": "allow",
                "protocol": "tcp", "local_ports": ["3389"], "program": make_app(env, "upd.exe", "Downloads")})
    m.add_rule({"id": "Quiet-Out", "name": "Some outbound rule", "direction": "out", "action": "allow"})
    m._rules["CorpPolicy-Block-Telnet"]["enabled"] = False
    m._profiles["public"]["enabled"] = False
    m.delete_rule("FPS-SMB-In-TCP")
    m.delete_rule(b["rule_ids"][0])
    w = c.post("/api/firewall/watch").json()
    assert w["new"] == 2 and w["changed"] == 1 and w["removed"] == 2 and w["blocks_missing"] == [b["id"]]
    ev = {e["kind"] + ":" + (e["rule_id"] or ""): e for e in
          c.get(f"/api/firewall/events?after_id={before}").json()["items"]}
    assert ev["rule_added:Malware-RDP"]["severity"] == "high" and not ev["rule_added:Malware-RDP"]["acknowledged"]
    assert "Remote Desktop" in ev["rule_added:Malware-RDP"]["detail"]
    assert ev["rule_added:Quiet-Out"]["severity"] == "info"
    assert ev["rule_changed:CorpPolicy-Block-Telnet"]["severity"] == "medium"
    assert ev["firewall_off:"]["severity"] == "critical"
    assert ev["rule_removed:FPS-SMB-In-TCP"]["severity"] == "info"
    assert ev["block_missing:"]["block_id"] == b["id"]
    assert w["alerts"] >= 4
    acts = [a["title"] for a in c.get("/api/activity?category=firewall&limit=50").json()["items"]]
    assert any("Windows Update Helper" in t for t in acts) and any("outside Cyber Hub" in t for t in acts)
    assert not any("Some outbound rule" in t for t in acts)                   # info-only stays out of activity
    unread = c.get("/api/firewall/events?unacknowledged=true").json()["total"]
    assert unread >= 4 and c.get("/api/firewall/status").json()["unacknowledged_alerts"] == unread
    assert c.post("/api/firewall/events/ack", json={}).json()["acknowledged"] == unread
    assert c.get("/api/firewall/status").json()["unacknowledged_alerts"] == 0
    assert c.post("/api/firewall/watch").json()["alerts"] == 0               # baseline moved on


def test_watch_mass_change_summarised(c):
    c.post("/api/firewall/watch")
    m = mem(c)
    for i in range(60):
        m.add_rule({"id": f"Bulk-{i}", "name": f"Bulk {i}", "direction": "out", "action": "allow"})
    w = c.post("/api/firewall/watch").json()
    assert w["new"] == 60
    assert c.get("/api/firewall/events?kind=rules_added").json()["total"] == 1
    assert c.get("/api/firewall/events?kind=rule_added").json()["total"] == 0


def test_watch_setting_admin_only(c):
    back = as_standard(c)
    try:
        r = c.patch("/api/settings", json={"firewall_watch_enabled": False})
        assert r.status_code == 403
    finally:
        back()
    assert c.patch("/api/settings", json={"firewall_watch_enabled": False}).status_code == 200
    assert c.patch("/api/settings", json={"firewall_watch_interval_minutes": 0}).status_code in (400, 422)


# ====================================================================== events / summary
def test_events_polling_and_summary(c, env):
    c.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.1"]})
    e1 = c.get("/api/firewall/events").json()
    last = e1["last_id"]
    assert c.get(f"/api/firewall/events?after_id={last}").json()["total"] == 0
    c.post("/api/firewall/block/port", json={"ports": "23"})
    new = c.get(f"/api/firewall/events?after_id={last}").json()
    assert new["total"] == 1 and "Telnet" in new["items"][0]["title"]
    s = c.get("/api/firewall/summary?days=7").json()
    assert len(s["per_day"]) == 7 and s["per_day"][-1]["blocks_created"] == 2
    assert s["blocks"]["by_kind"]["ip"] == 1 and s["blocks"]["by_kind"]["port"] == 1
    assert s["rules"]["cyberhub"] == 3 and s["score"] is not None
    assert s["events_by_kind"]["block_created"] == 2 and len(s["top_blocked"]) == 2
    back = as_standard(c)
    try:
        assert c.delete("/api/firewall/events").status_code == 403
    finally:
        back()
    assert c.delete("/api/firewall/events").json()["deleted"] >= 2


# ====================================================================== packet log
def _win_line(ts, action, proto, src, dst, sport, dport, path, pid=0):
    return (f"{ts:%Y-%m-%d %H:%M:%S} {action} {proto} {src} {dst} {sport} {dport} 52 S 1234567 0 64240 - - - "
            f"{path} {pid}\n")


def test_packet_log_windows_format(c, env):
    t0 = datetime.now() - timedelta(hours=3)
    lines = ("#Version: 1.5\n#Software: Microsoft Windows Firewall\n#Time Format: Local\n"
             "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack "
             "tcpwin icmptype icmpcode info path pid\n")
    lines += _win_line(t0 - timedelta(hours=30), "DROP", "TCP", "203.0.113.200", "192.168.1.10", 1, 22, "RECEIVE")
    lines += _win_line(t0, "DROP", "TCP", "203.0.113.5", "192.168.1.10", 51544, 3389, "RECEIVE")
    lines += _win_line(t0 + timedelta(seconds=1), "DROP", "TCP", "203.0.113.5", "192.168.1.10", 51545, 445,
                       "RECEIVE")
    lines += _win_line(t0 + timedelta(minutes=5), "ALLOW", "UDP", "192.168.1.10", "8.8.8.8", 53000, 53, "SEND",
                       4242)
    lines += _win_line(t0 + timedelta(minutes=6), "DROP", "UDP", "192.168.1.10", "239.255.255.250", 1900, 1900,
                       "SEND")
    for i in range(12):
        lines += _win_line(t0 + timedelta(hours=1, seconds=i), "DROP", "TCP", "198.51.100.66", "192.168.1.10",
                           40000 + i, 1000 + i, "RECEIVE")
    log = env / "pfirewall.log"
    log.write_text(lines)
    assert c.get("/api/firewall/log").status_code == 404                 # this firewall has no log configured
    c.patch("/api/settings", json={"firewall_log_path": str(log)})
    r = c.get("/api/firewall/log?hours=24").json()
    assert r["path"] == str(log) and r["drops"] == 15 and r["allows"] == 1     # the 30 h old line is outside
    assert r["inbound_drops"] == 14 and r["outbound_drops"] == 1
    assert r["top_sources"][0]["address"] == "198.51.100.66"
    assert {p["port"]: p["service"] for p in r["top_ports"]}[3389] == "Remote Desktop"
    assert r["port_scan_suspects"][0]["address"] == "198.51.100.66"
    assert r["port_scan_suspects"][0]["distinct_ports"] == 12 and len(r["port_scan_suspects"]) == 1
    assert len(r["by_hour"]) >= 24 and sum(h["drops"] for h in r["by_hour"]) == 15
    assert r["recent_drops"][0]["src"] == "198.51.100.66"
    assert c.get("/api/firewall/log?hours=48").json()["drops"] == 16
    c.patch("/api/settings", json={"firewall_log_path": str(env / "nope.log")})
    assert c.get("/api/firewall/log").status_code == 404


def test_log_parser_formats():
    now = datetime(2026, 11, 12, 12, 0, 0)
    ufw = ("Nov 12 10:16:01 pc kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=10.0.0.2 LEN=52 "
           "PROTO=TCP SPT=5 DPT=22 WINDOW=1")
    e = fwlog.parse_line(ufw, now)
    assert e["action"] == "drop" and e["direction"] == "in" and e["dport"] == 22 and e["ts"].hour == 10
    assert fwlog.parse_line(ufw.replace("[UFW BLOCK]", "[UFW AUDIT]"), now) is None
    dec = fwlog.parse_line(ufw.replace("Nov 12", "Dec 31"), now)
    assert dec["ts"].year == 2025                                          # last year's line
    out = fwlog.parse_line("2026-11-12T10:00:00.1+00:00 pc kernel: [UFW ALLOW] IN= OUT=eth0 SRC=10.0.0.2 "
                           "DST=1.1.1.1 PROTO=UDP SPT=5 DPT=53", now)
    assert out["action"] == "allow" and out["direction"] == "out"
    assert fwlog.parse_line("2026-11-12 10:00:00 INFO-EVENTS-LOST - - - - - - - - - - - - - 10", now) is None
    assert fwlog.parse_line("#Fields: date time", now) is None
    s = fwlog.summarize([ufw], 24, now=now)
    assert s["drops"] == 1 and s["top_ports"][0]["service"] == "SSH"
    assert fwlog.summarize([ufw], 1, now=now)["drops"] == 0                # outside the window


def test_read_tail(tmp_path):
    p = tmp_path / "big.log"
    p.write_text("".join(f"line {i}\n" for i in range(1000)))
    lines = fwlog.read_tail(p, 100)
    assert lines[-1] == "line 999" and all(x.startswith("line ") for x in lines) and len(lines) < 20


# ====================================================================== snapshots & reset
def test_snapshots_restore_and_reset(c, env):
    b = c.post("/api/firewall/block/app", json={"path": make_app(env)}).json()
    s = c.post("/api/firewall/snapshots", json={"note": "known good"})
    assert s.status_code == 201
    snap = s.json()
    assert snap["exists"] and snap["rules"] == 7 and snap["auto"] is False and snap["sha256"]

    c.patch("/api/firewall/profiles/public", json={"enabled": False})
    c.delete(f"/api/firewall/blocks/{b['id']}")
    back = as_standard(c)
    try:
        assert c.post(f"/api/firewall/snapshots/{snap['id']}/restore").status_code == 403
        assert c.post("/api/firewall/reset", json={"confirm": True}).status_code == 403
    finally:
        back()
    r = c.post(f"/api/firewall/snapshots/{snap['id']}/restore")
    assert r.status_code == 200 and r.json()["safety_snapshot"] > snap["id"]
    assert mem(c)._profiles["public"]["enabled"] is True
    assert b["rule_ids"][0] in mem(c)._rules                               # rules came back with the policy
    assert c.post("/api/firewall/watch").json()["alerts"] == 0             # restore re-baselined the watch
    snaps = c.get("/api/firewall/snapshots").json()["snapshots"]
    assert len(snaps) == 2 and snaps[0]["auto"] is True

    # a tampered file is refused
    f = env / "data" / "firewall" / snap["file"]
    f.write_text(f.read_text().replace("Cyber Hub", "Evil Hub"))
    r = c.post(f"/api/firewall/snapshots/{snap['id']}/restore")
    assert r.status_code == 409 and "modified" in r.json()["detail"]

    b2 = c.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.50"]}).json()
    assert c.post("/api/firewall/reset", json={"confirm": False}).status_code == 400
    r = c.post("/api/firewall/reset", json={"confirm": True}).json()
    assert r["reset"] is True and r["blocks_ended"] >= 1 and r["safety_snapshot"]
    assert c.get(f"/api/firewall/blocks/{b2['id']}").json()["status"] == "removed"
    assert not any(k.startswith("CyberHub-") for k in mem(c)._rules)
    assert c.get("/api/firewall/events?kind=policy_reset").json()["items"][0]["severity"] == "high"
    assert c.post("/api/firewall/watch").json()["alerts"] == 0
    assert c.delete(f"/api/firewall/snapshots/{snap['id']}").status_code == 200
    assert not f.exists()


def test_auto_snapshot_pruning(c):
    c.patch("/api/settings", json={"firewall_snapshot_keep": 2})
    for _ in range(4):
        fw(c).create_snapshot("syed", "auto", auto=True)
    manual = c.post("/api/firewall/snapshots", json={}).json()
    snaps = c.get("/api/firewall/snapshots").json()["snapshots"]
    assert sum(1 for s in snaps if s["auto"]) == 2 and any(s["id"] == manual["id"] for s in snaps)
    assert len(os.listdir(fw(c).snap_dir)) == 3


# ====================================================================== unavailable backend
def test_no_firewall_backend(env, monkeypatch):
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "none")
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        s = cl.get("/api/firewall/status").json()
        assert s["state"] == "unavailable" and s["backend"]["available"] is False and s["can_modify"] is False
        assert cl.get("/api/firewall/rules").status_code == 501
        assert cl.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.1"]}).status_code == 501
        assert cl.get("/api/firewall/blocks").json()["total"] == 0
        assert cl.get("/api/firewall/summary").json()["rules"] is None
        assert cl.get("/api/firewall/events").json()["total"] == 0


def test_pick_backend(monkeypatch):
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "memory")
    assert pick_backend().name == "memory"
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "none")
    assert pick_backend().name == "none"
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "ufw")
    assert pick_backend().name == "ufw"
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "windows")
    assert pick_backend().name == "windows"


# ====================================================================== Windows backend (fake PowerShell)
class FakePS:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, script, timeout=8.0, env=None):
        self.calls.append((script, dict(env or {})))
        for key, ans in self.answers.items():
            if key in script:
                return ans(env) if callable(ans) else ans
        return {"ok": True}


WIN_PROFILES_JSON = {"ok": True, "profiles": [
    {"name": "Domain", "enabled": "True", "inbound": "Block", "outbound": "Allow", "allow_inbound_rules": "True",
     "notify": "True", "log_allowed": "False", "log_blocked": "False",
     "log_file": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log", "log_max_kb": "4096"},
    {"name": "Private", "enabled": "True", "inbound": "NotConfigured", "outbound": "NotConfigured",
     "allow_inbound_rules": "NotConfigured", "notify": "False", "log_allowed": "False", "log_blocked": "True",
     "log_file": "", "log_max_kb": "NotConfigured"},
    {"name": "Public", "enabled": "False", "inbound": "Allow", "outbound": "Allow", "allow_inbound_rules": "False",
     "notify": "True", "log_allowed": "False", "log_blocked": "False", "log_file": "", "log_max_kb": "16384"}],
    "networks": [{"name": "Starbucks", "interface": "Wi-Fi", "category": "Public", "ipv4": "Internet"},
                 {"name": "corp.local", "interface": "Ethernet", "category": "DomainAuthenticated",
                  "ipv4": "Internet"}]}

WIN_RULES_JSON = {"ok": True, "rules": [
    {"id": "RemoteDesktop-UserMode-In-TCP", "name": "Remote Desktop - User Mode (TCP-In)", "description": "",
     "group": "Remote Desktop", "enabled": "True", "direction": "Inbound", "action": "Allow", "profile": "Any",
     "store": "Local", "program": "%SystemRoot%\\system32\\svchost.exe", "package": "", "service": "termservice",
     "protocol": "TCP", "lport": "3389", "rport": "Any", "laddr": "Any", "raddr": "Any"},
    {"id": "{6A3E2E58-1111}", "name": "Spotify", "description": None, "group": "", "enabled": "False",
     "direction": "Outbound", "action": "Block", "profile": "Domain, Private", "store": "GroupPolicy",
     "program": "C:\\Users\\me\\AppData\\Roaming\\Spotify\\Spotify.exe", "package": None, "service": "Any",
     "protocol": "Any", "lport": "Any", "rport": "", "laddr": "Any", "raddr": "LocalSubnet"},
    {"id": "", "name": "broken row"}]}


def test_windows_backend_parsing():
    ps = FakePS({"Get-NetFirewallProfile": WIN_PROFILES_JSON, "Get-NetFirewallRule": WIN_RULES_JSON})
    b = WindowsFirewall(ps=ps, cmd=lambda *a, **k: (0, "Ok.", ""), elevated=lambda: True)
    assert b.available() == (True, None) and b.can_modify()
    profs = {p["name"]: p for p in b.profiles()}
    assert profs["domain"]["enabled"] and profs["domain"]["default_inbound"] == "block"
    assert profs["private"]["default_inbound"] == "block" and profs["private"]["allow_inbound_rules"] is True
    assert profs["private"]["notify_on_listen"] is False and profs["private"]["log_blocked"] is True
    assert profs["private"]["log_max_kb"] == 4096 and profs["public"]["log_max_kb"] == 16384
    assert profs["public"]["enabled"] is False and profs["public"]["default_inbound"] == "allow"
    assert profs["public"]["allow_inbound_rules"] is False
    nets = b.networks()
    assert nets[0]["profile"] == "public" and nets[1]["profile"] == "domain" and nets[0]["internet"]
    rules = b.rules()
    assert len(rules) == 2
    rdp, sp = rules
    assert rdp["direction"] == "in" and rdp["action"] == "allow" and rdp["enabled"] is True
    assert rdp["profiles"] == ["domain", "private", "public"] and rdp["protocol"] == "tcp"
    assert rdp["local_ports"] == "3389" and rdp["remote_addresses"] == "any" and rdp["service"] == "termservice"
    assert rdp["editable"] is True and rdp["source"] == "local"
    assert sp["direction"] == "out" and sp["action"] == "block" and sp["enabled"] is False
    assert sp["profiles"] == ["domain", "private"] and sp["service"] is None and sp["remote_ports"] == "any"
    assert sp["source"] == "group_policy" and sp["editable"] is False and sp["remote_addresses"] == "LocalSubnet"
    assert "pfirewall.log" in b.default_log_path()


def test_windows_backend_never_formats_user_input_into_script():
    ps = FakePS({})
    b = WindowsFirewall(ps=ps, cmd=lambda *a, **k: (0, "Ok.", ""), elevated=lambda: True)
    evil = "C:\\x'; Remove-Item -Recurse C:\\ ;'.exe"
    b.add_rule({"id": "CyberHub-B1-in", "name": "Cyber Hub - Block x", "direction": "in", "action": "block",
                "profiles": ["any"], "program": evil, "protocol": "tcp", "local_ports": ["445", "6000-6010"],
                "remote_addresses": ["203.0.113.5", "10.0.0.0/8"]})
    script, env = ps.calls[-1]
    assert script == PS_ADD_RULE and evil not in script
    assert env["CH_PROGRAM"] == evil and env["CH_DIR"] == "Inbound" and env["CH_ACTION"] == "Block"
    assert env["CH_PROTO"] == "TCP" and env["CH_LPORT"] == "445,6000-6010" and env["CH_PROFILES"] == "Any"
    assert env["CH_RADDR"] == "203.0.113.5,10.0.0.0/8" and env["CH_GROUP"] == "Cyber Hub"
    b.add_rule({"id": "CyberHub-A2-in", "name": "allow", "direction": "in", "action": "allow",
                "profiles": ["private"], "program": "C:\\a.exe"})
    assert ps.calls[-1][1]["CH_PROFILES"] == "Private" and "CH_PROTO" not in ps.calls[-1][1]
    b.set_profile(["public", "private"], {"enabled": False, "default_inbound": "block", "allow_inbound_rules": False,
                                          "log_blocked": True})
    script, env = ps.calls[-1]
    assert script == PS_SET_PROFILE
    assert env == {"CH_PROFILE": "Public,Private", "CH_ENABLED": "False", "CH_IN": "Block", "CH_AIR": "False",
                   "CH_LOGB": "True"}
    b.set_rule_enabled("{GUID}'; evil", True)
    assert ps.calls[-1][1] == {"CH_ID": "{GUID}'; evil", "CH_ENABLED": "True"} and "evil" not in ps.calls[-1][0]
    for s in (PS_PROFILES, PS_RULES, PS_ADD_RULE, PS_SET_PROFILE):
        assert "ConvertTo-Json" in s and "catch" in s


def test_windows_backend_errors_and_netsh():
    ps = FakePS({"New-NetFirewallRule": {"ok": False, "error": "Access is denied."},
                 "Remove-NetFirewallRule": {"ok": False, "error": "No MSFT_NetFirewallRule objects found with "
                                                                  "property 'Name' equal to 'x'"},
                 "Set-NetFirewallRule": {"ok": False, "error": "The parameter is incorrect"},
                 "Get-NetFirewallProfile": None})
    calls = []

    def cmd(args, timeout=5.0, env=None):
        calls.append(args)
        return (1, "The requested operation requires elevation (Run as administrator).", "") if args[2] == "reset" \
            else (0, "Ok.", "")
    b = WindowsFirewall(ps=ps, cmd=cmd, elevated=lambda: False)
    assert b.can_modify() is False
    with pytest.raises(BackendError) as e:
        b.add_rule({"id": "x", "name": "x", "direction": "out", "action": "block"})
    assert e.value.status == 403 and "start_cyberhub_admin.bat" in e.value.message
    with pytest.raises(BackendError) as e:
        b.delete_rule("x")
    assert e.value.status == 404
    with pytest.raises(BackendError) as e:
        b.set_rule_enabled("x", False)
    assert e.value.status == 400 and "parameter" in e.value.message
    with pytest.raises(BackendError) as e:
        b.profiles()
    assert e.value.status == 502
    assert b.networks() == []
    b.export_policy("C:\\data\\fw.wfw")
    assert calls[-1] == ["netsh", "advfirewall", "export", "C:\\data\\fw.wfw"]
    with pytest.raises(BackendError) as e:
        b.reset()
    assert e.value.status == 403


# ====================================================================== ufw backend (fake runner)
UFW_NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ssh
[ 2] Anywhere                   DENY IN     203.0.113.5                # CyberHub-B3-in
[ 3] 445/tcp                    DENY IN     Anywhere                   # CyberHub-B4-in-tcp
[ 4] 1.2.3.4 443/tcp            DENY OUT    Anywhere                   (out) # CyberHub-B5-out
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh
[ 6] 445/tcp (v6)               DENY IN     Anywhere (v6)              # CyberHub-B4-in-tcp
[ 7] Anywhere on eth0           ALLOW IN    192.168.1.0/24
"""
UFW_VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
"""


class FakeUfw:
    def __init__(self, numbered=UFW_NUMBERED, verbose=UFW_VERBOSE, fail=None):
        self.numbered, self.verbose, self.fail = numbered, verbose, fail
        self.calls = []

    def __call__(self, args, timeout=5.0, env=None):
        self.calls.append(args)
        if self.fail:
            return 1, "", self.fail
        if args[1:] == ["status", "numbered"]:
            return 0, self.numbered, ""
        if args[1:] == ["status", "verbose"]:
            return 0, self.verbose, ""
        return 0, "Rule added", ""


def test_ufw_parsing():
    rules = parse_ufw_numbered(UFW_NUMBERED)
    assert len(rules) == 7
    by = {(r["number"]): r for r in rules}
    assert by[1]["id"] == "ssh" and by[1]["local_ports"] == "22" and by[1]["protocol"] == "tcp"
    assert by[2]["id"] == "CyberHub-B3-in" and by[2]["remote_addresses"] == "203.0.113.5" and \
        by[2]["action"] == "block" and by[2]["group"] == "Cyber Hub"
    assert by[4]["direction"] == "out" and by[4]["remote_addresses"] == "1.2.3.4" and by[4]["remote_ports"] == "443"
    assert by[4]["local_addresses"] == "any"
    assert by[6]["v6"] is True and by[6]["id"] == by[3]["id"]
    assert by[7]["id"].startswith("ufw:") and by[7]["remote_addresses"] == "192.168.1.0/24"
    p = parse_ufw_verbose(UFW_VERBOSE)
    assert p["enabled"] and p["default_inbound"] == "block" and p["default_outbound"] == "allow" and p["log_blocked"]
    off = parse_ufw_verbose("Status: inactive\n")
    assert off["enabled"] is False


def test_ufw_commands():
    run = FakeUfw()
    b = UfwFirewall(cmd=run, root=lambda: True)
    assert b.profile_names == ["all"] and not b.supports_programs and b.can_modify()
    b.add_rule({"id": "CyberHub-B9-in", "name": "x", "direction": "in", "action": "block",
                "remote_addresses": ["203.0.113.0/24", "198.51.100.7"]})
    adds = [c for c in run.calls if "comment" in c]
    assert adds[0] == ["ufw", "insert", "1", "deny", "in", "from", "203.0.113.0/24", "to", "any", "comment",
                       "CyberHub-B9-in"]
    assert adds[1][6] == "198.51.100.7"
    b.add_rule({"id": "CyberHub-B10-out-tcp", "name": "x", "direction": "out", "action": "block", "protocol": "tcp",
                "remote_ports": ["6000-6010"]})
    assert run.calls[-1] == ["ufw", "insert", "1", "deny", "out", "to", "any", "port", "6000:6010", "proto", "tcp",
                             "comment", "CyberHub-B10-out-tcp"]
    with pytest.raises(BackendError) as e:
        b.add_rule({"id": "x", "name": "x", "direction": "in", "action": "block", "program": "/usr/bin/curl"})
    assert e.value.status == 501
    with pytest.raises(BackendError):
        b.add_rule({"id": "x", "name": "x", "direction": "in", "action": "block", "remote_addresses": ["1.1.1.1-1.1.1.9"]})
    with pytest.raises(BackendError):
        b.add_rule({"id": "x", "name": "x", "direction": "in", "action": "block", "local_ports": ["1-9"]})
    run.calls.clear()
    b.delete_rule("CyberHub-B4-in-tcp")
    assert run.calls[1:] == [["ufw", "--force", "delete", "6"], ["ufw", "--force", "delete", "3"]]
    with pytest.raises(BackendError) as e:
        b.delete_rule("nope")
    assert e.value.status == 404
    with pytest.raises(BackendError) as e:
        b.set_rule_enabled("ssh", False)
    assert e.value.status == 501
    run.calls.clear()
    b.set_profile(["all"], {"enabled": True, "default_inbound": "block", "log_blocked": False})
    assert run.calls == [["ufw", "--force", "enable"], ["ufw", "default", "deny", "incoming"],
                         ["ufw", "logging", "off"]]
    with pytest.raises(BackendError):
        b.set_profile(["all"], {"allow_inbound_rules": False})
    empty = FakeUfw(numbered="Status: active\n")
    UfwFirewall(cmd=empty, root=lambda: True).add_rule({"id": "c", "name": "x", "direction": "in", "action": "block",
                                                        "remote_addresses": ["203.0.113.1"]})
    assert empty.calls[-1][:3] == ["ufw", "deny", "in"]                       # no "insert 1" into an empty list
    nr = UfwFirewall(cmd=FakeUfw(fail="ERROR: You need to be root to run this script"), root=lambda: False)
    with pytest.raises(BackendError) as e:
        nr.profiles()
    assert e.value.status == 403


def test_ufw_snapshot_roundtrip(tmp_path):
    d = tmp_path / "etc-ufw"
    d.mkdir()
    (d / "user.rules").write_text("*filter\n# rules v4\nCOMMIT\n")
    (d / "user6.rules").write_text("*filter\n# rules v6\nCOMMIT\n")
    run = FakeUfw()
    b = UfwFirewall(cmd=run, root=lambda: True, rules_dir=d)
    snap = tmp_path / "s.json"
    b.export_policy(snap)
    (d / "user.rules").write_text("changed")
    b.import_policy(snap)
    assert "rules v4" in (d / "user.rules").read_text() and run.calls[-1] == ["ufw", "reload"]


def test_ufw_service_end_to_end(env, monkeypatch):
    """The service on top of ufw: IP blocks work, app blocks give a clear 501, profile is 'all'."""
    from cyberhub.services import firewall as fwmod
    run = FakeUfw()
    monkeypatch.setattr(fwmod, "pick_backend", lambda: UfwFirewall(cmd=run, root=lambda: True))
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        s = cl.get("/api/firewall/status").json()
        assert s["backend"]["name"] == "ufw" and [p["name"] for p in s["profiles"]] == ["all"]
        r = cl.post("/api/firewall/block/app", json={"path": sys.executable})
        assert r.status_code == 501
        r = cl.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.77"], "direction": "in"})
        assert r.status_code == 201 and any(c[-1] == r.json()["rule_ids"][0] for c in run.calls)
        assert cl.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.1-203.0.113.5"]}).status_code == 400
        assert cl.patch("/api/firewall/profiles/all", json={"log_blocked": True}).status_code == 200
        assert cl.patch("/api/firewall/profiles/public", json={"enabled": True}).status_code == 404
        assert not any(f["id"].startswith("notify_off") for f in cl.get("/api/firewall/analysis").json()["findings"])


def test_background_loop(c, env):
    import asyncio
    from cyberhub.services.firewall import firewall_loop
    b = c.post("/api/firewall/block/ip", json={"addresses": ["203.0.113.61"], "minutes": 5}).json()
    c.app.state.db.execute("UPDATE firewall_blocks SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?", (b["id"],))

    async def run():
        t = asyncio.create_task(firewall_loop(fw(c), c.app.state.settings_store, tick=0.05, first_delay=0))
        await asyncio.sleep(0.5)
        t.cancel()
    asyncio.run(run())
    assert c.get(f"/api/firewall/blocks/{b['id']}").json()["status"] == "expired"
    assert c.get("/api/firewall/status").json()["last_watch"]              # the watch ran (baseline)
