"""
Cyber Hub Backend - Part 11 tests: Windows Security Posture
Developed by Syed Muhammad Tayyab

The API tests drive MemoryPosture (CYBERHUB_POSTURE_BACKEND=memory): a Windows
PC kept in the SAME raw shape the PowerShell probe prints, so every request
goes through the real Windows parser, evaluator, fix / verify / rollback /
undo code and the real Part 9 firewall service (in-memory firewall). The
Windows backend is tested with a fake PowerShell runner (user values only in
$env:CH_*, allow-listed registry paths), the Linux backend with a fake file
tree, and every PowerShell script is parse-checked when pwsh is installed.
"""
import asyncio
import copy
import json
import os
import shutil
import sqlite3
import subprocess
import time
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import posture as pmod
from cyberhub.services.posture import (PostureError, evaluate, exclusion_risk, posture_loop, score_of,
                                       windows_support)
from cyberhub.services.posture_backends import (ALL_SCRIPTS, PS_COLLECT, PS_REG_SET, REG_TARGETS, BackendError,
                                                LinuxPosture, MemoryPosture, NoPosture, WindowsPosture, av_state,
                                                bitlocker_state, check_op, default_raw, normalize_windows,
                                                pick_backend)
from cyberhub.services.platform_tools import CACHE

PW = "Cyb3r!Hub#2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    monkeypatch.setenv("CYBERHUB_RTP_DEFAULT_DIRS", str(tmp_path / "watched"))
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_NETWORK_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "memory")
    return tmp_path


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


def ps(c) -> pmod.PostureService:
    return c.app.state.posture


def mem(c) -> MemoryPosture:
    return c.app.state.posture.backend


def raw(c) -> dict:
    ps(c).invalidate()
    return mem(c).raw


def chk(c, cid):
    return c.get(f"/api/posture/checks/{cid}?refresh=true").json()


def as_standard(c):
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    admin = c.headers["X-CyberHub-Session"]
    r = c.post("/api/account/login", json={"username": "kid", "password": PW})
    c.headers["X-CyberHub-Session"] = r.json()["session_token"]

    def back():
        c.headers["X-CyberHub-Session"] = admin
    return back


def facts(**over):
    r = default_raw()
    for path, v in over.items():
        sec, key = path.split("__")
        r[sec][key] = v
    return normalize_windows(r, True)


def ev(f, **ctx):
    ctx.setdefault("now", datetime(2026, 11, 12, tzinfo=timezone.utc))
    return {x["id"]: x for x in evaluate(f, ctx)}


# ====================================================================== parsers & pure logic
def test_normalize_default_raw():
    f = normalize_windows(default_raw(), False)
    assert f["platform"] == "windows" and f["elevated"] is False
    assert f["os"]["build"] == 26200 and f["os"]["portable"] is True and f["os"]["firmware"] == "uefi"
    assert f["av"]["defender"]["realtime"] is True and f["av"]["defender"]["full_scan_age_days"] is None  # 65535
    assert f["av"]["prefs"]["exclusions"]["readable"] and len(f["av"]["prefs"]["exclusions"]["path"]) == 2
    assert [v["state"] for v in f["bitlocker"]["volumes"]] == ["off", "off"]
    assert f["tpm"]["version"] == "2.0" and f["secure_boot"] == {"uefi": True, "enabled": True}
    users = {u["name"]: u for u in f["accounts"]["users"]}
    assert users["Guest"]["builtin"] == "guest" and users["Administrator"]["builtin"] == "admin"
    assert users["syed"]["admin"] is True and users["kid"]["admin"] is False
    assert users["DefaultAccount"]["builtin"] == "system"
    assert f["hardening"]["smb1"] is False and f["hardening"]["ss_secure"] == 0
    assert f["rdp"]["enabled"] is True and f["update"]["pending_reboot"] is True


def test_definition_updates_do_not_count_as_windows_updates():
    f = normalize_windows(default_raw(), True)
    last = datetime.fromisoformat(f["update"]["last_install"])
    assert (datetime.now(timezone.utc) - last).days == 52          # not the 9-day-old Defender update
    r = default_raw()
    r["update"]["history"] = [{"title": "Security Intelligence Update for Microsoft Defender Antivirus - "
                                        "KB2267602", "date": "2026-11-11T08:00:00Z", "result": 2}]
    r["update"]["hotfix_last"] = None
    r["update"]["last_install"] = "2026-06-01T00:00:00Z"
    assert normalize_windows(r, True)["update"]["last_install"].startswith("2026-06-01")


@pytest.mark.parametrize("row,state", [
    ({"protection": "On", "status": "FullyEncrypted", "protectors": ["Tpm"]}, "on"),
    ({"protection": "Off", "status": "FullyDecrypted"}, "off"),
    ({"protection": "Off", "status": "FullyEncrypted", "protectors": ["Tpm", "RecoveryPassword"]}, "suspended"),
    ({"protection": "Off", "status": "FullyEncrypted", "protectors": []}, "waiting_activation"),
    ({"protection": "On", "status": "EncryptionInProgress", "protectors": ["Tpm"]}, "encrypting"),
    ({"protection": "Off", "status": "DecryptionInProgress"}, "decrypting"),
    ({"shell": 1}, "on"), ({"shell": 2}, "off"), ({"shell": 5}, "suspended"), ({"shell": 8}, "waiting_activation"),
    ({"shell": 0}, "unencryptable"), ({"shell": 99}, "unknown"),
])
def test_bitlocker_states(row, state):
    assert bitlocker_state(row) == state


def test_security_center_product_state():
    assert av_state(397568) == (True, True)          # 0x61100 - on, up to date
    assert av_state(393472) == (False, True)         # 0x60100 - off
    assert av_state(397584) == (True, False)         # 0x61110 - on, signatures out of date
    assert av_state(None) == (None, None)


def test_exclusions_hidden_from_standard_engine():
    r = default_raw()
    r["prefs"]["ex_path"] = ["N/A: Must be an administrator to view exclusions"]
    f = normalize_windows(r, False)
    assert f["av"]["prefs"]["exclusions"]["readable"] is False
    assert ev(f)["defender_exclusions"]["status"] == "unknown"


@pytest.mark.parametrize("kind,value,risky", [
    ("path", "C:\\", True), ("path", "C:", True), ("path", "D:\\*", True), ("path", "*", True),
    ("path", r"C:\Windows\Temp", True), ("path", r"C:\Users\syed", True), ("path", r"C:\Users\syed\Downloads\\", True),
    ("path", r"%TEMP%", True), ("path", r"C:\Users\syed\AppData\Local\Temp\x", True), ("path", r"C:\ProgramData", True),
    ("path", r"D:\Projects\build", False), ("path", r"C:\Program Files\Steam\steamapps", False),
    ("process", "powershell.exe", True), ("process", r"C:\Windows\System32\cmd.exe", True),
    ("process", "node.exe", False), ("extension", ".exe", True), ("extension", "ps1", True),
    ("extension", "*", True), ("extension", ".vhdx", False), ("extension", "iso", True),
])
def test_exclusion_risk(kind, value, risky):
    assert bool(exclusion_risk(kind, value)) is risky


def test_cyberhub_own_folder_exclusion_is_not_flagged():
    own = (r"c:\users\syed\appdata\local\cyberhub",)
    assert exclusion_risk("path", r"C:\Users\syed\AppData\Local\CyberHub\quarantine", own) is None
    assert exclusion_risk("path", r"C:\Users\syed\AppData\Local", own)          # its parent still is


def test_windows_lifecycle():
    d = date(2026, 11, 12)
    pro24 = windows_support({"build": 26100, "display_version": "24H2", "edition_id": "Professional",
                             "product_type": 1}, d)
    assert pro24["end"] == "2026-10-13" and pro24["days_left"] < 0
    ent24 = windows_support({"build": 26100, "display_version": "24H2", "edition_id": "Enterprise",
                             "product_type": 1}, d)
    assert ent24["end"] == "2027-10-12" and ent24["days_left"] > 300
    assert windows_support({"build": 26200, "display_version": "25H2", "edition_id": "Core",
                            "product_type": 1}, d)["end"] == "2027-10-12"
    by_build = windows_support({"build": 22631, "display_version": "", "edition_id": "Education", "product_type": 1}, d)
    assert by_build["version"] == "Windows 11 23H2" and by_build["days_left"] == -2
    w10 = windows_support({"build": 19045, "edition_id": "Professional", "product_type": 1}, d)
    assert w10["product"] == "Windows 10" and w10["end"] == "2025-10-14" and w10["days_left"] < 0
    assert windows_support({"build": 29500, "display_version": "27H2", "product_type": 1}, d)["newer"]
    assert windows_support({"build": 26100, "edition_id": "EnterpriseS", "product_type": 1}, d)["end"] is None
    assert windows_support({"build": 26100, "product_type": 3}, d) is None                    # server


def test_os_supported_check():
    f = facts(os__display_version="24H2", os__build="26100")
    c = ev(f)["os_supported"]
    assert c["status"] == "fail" and c["severity"] == "high" and "2026-10-13" in c["value"]
    assert c["manual"]["open"] == "windows_update"
    near = ev(facts(), now=datetime(2027, 9, 1, tzinfo=timezone.utc))["os_supported"]      # 25H2 ends 2027-10-12
    assert near["status"] == "fail" and near["severity"] == "low" and "ends in 41 days" in near["value"]
    assert ev(facts())["os_supported"]["status"] == "pass"


def test_score_curve_and_caps():
    mk = lambda sev, st="fail": {"status": st, "severity": sev, "ignored": None}
    assert score_of([]) == (100, "Protected")
    assert score_of([mk("low")])[0] == 98
    assert score_of([mk("high")]) == (84, "Good")
    assert score_of([mk("critical")]) == (49, "At risk")
    assert score_of([mk("info")]) == (100, "Protected")
    assert score_of([mk("high") | {"ignored": {"reason": "x"}}]) == (100, "Protected")
    assert score_of([mk("medium")] * 30)[0] == 36                       # never flat 0


def test_evaluate_antivirus_variants():
    third = facts(defender__antivirus=False, defender__mode="Passive Mode")
    third["av"]["products"].append({"name": "Bitdefender", "enabled": True, "up_to_date": True,
                                    "is_defender": False})
    c = ev(third)
    assert c["av_active"]["status"] == "pass" and c["av_active"]["value"] == "Bitdefender"
    assert "defender_realtime" not in c                                # Defender is not the active AV
    none = facts(defender__antivirus=False, defender__am_service=False)
    none["av"]["products"] = []
    c = ev(none)
    assert c["av_active"]["status"] == "fail" and c["av_active"]["severity"] == "critical"
    unread = facts()
    unread["av"] = {"defender": None, "prefs": None, "products": None, "error": "not recognized"}
    assert ev(unread)["av_active"]["status"] == "unknown"


def test_tamper_protection_means_manual_only():
    on = ev(facts(defender__realtime=False, defender__tamper=True))["defender_realtime"]
    assert on["status"] == "fail" and on["severity"] == "critical" and on["fix"] is None
    assert on["manual"]["open"] == "defender_settings" and "Tamper Protection" in on["detail"]
    off = ev(facts(defender__realtime=False, defender__tamper=False))["defender_realtime"]
    assert off["fix"]["ops"] == [{"op": "mp_pref", "pref": "DisableRealtimeMonitoring", "value": False}]


def test_policy_managed_settings_have_no_fix():
    f = facts(smartscreen__policy=0, rdp__policy_deny=0, update__no_auto=1)
    c = ev(f)
    assert c["smartscreen_apps"]["managed"] and c["smartscreen_apps"]["fix"] is None
    assert c["remote_desktop"]["managed"] and c["remote_desktop"]["fix"] is None
    assert c["updates_policy"]["managed"] and c["updates_policy"]["severity"] == "high"


def test_laptop_bitlocker_weighs_more():
    assert ev(facts())["bitlocker_os"]["severity"] == "high"                         # chassis 10 = laptop
    assert ev(facts(os__chassis=[3]))["bitlocker_os"]["severity"] == "medium"        # desktop
    home = facts(os__edition_id="Core")
    assert ev(home)["bitlocker_os"]["manual"]["open"] == "device_encryption"


def test_check_op_allow_list():
    for bad in ({"op": "reg_set", "target": "HKLM:\\SOFTWARE\\Evil", "value": 1},
                {"op": "user_enabled", "sid": "S-1-5-21-1-2-3-1001", "enabled": False},
                {"op": "bitlocker", "mount": "C:; Format-Volume", "resume": True},
                {"op": "service_start", "service": "WinDefend", "start": "Disabled"},
                {"op": "mp_pref", "pref": "ExclusionPath", "value": "C:\\"},
                {"op": "exec_policy", "policy": "Bypass; calc"},
                {"op": "rm -rf"}):
        with pytest.raises(BackendError) as e:
            check_op(dict(bad))
        assert e.value.status == 400


# ====================================================================== Windows backend (fake PowerShell)
class FakePS:
    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, script, timeout=8.0, env=None):
        self.calls.append((script, dict(env or {})))
        for key, ans in self.answers.items():
            if key in script:
                return ans(env) if callable(ans) else ans
        return {"ok": True}


def test_windows_backend_collect_and_reg_set_use_env_only():
    fake = FakePS({"Get-MpComputerStatus": dict(default_raw(), ok=True)})
    wb = WindowsPosture(ps=fake, elevated=lambda: True)
    f = wb.collect()
    assert f["os"]["display_version"] == "25H2" and fake.calls[0][0] == PS_COLLECT
    wb.apply({"op": "reg_set", "target": "uac_consent_admin", "value": 5})
    script, env = fake.calls[-1]
    assert script == PS_REG_SET and env["CH_PATH"] == REG_TARGETS["uac_consent_admin"]["path"]
    assert env["CH_NAME"] == "ConsentPromptBehaviorAdmin" and env["CH_VALUE"] == "5" and env["CH_TYPE"] == "DWord"
    evil = "C:\\x'; Remove-Item C:\\ -Recurse; '"
    wb.apply({"op": "mp_exclusion", "kind": "path", "value": evil, "remove": True})
    script, env = fake.calls[-1]
    assert evil not in script and env["CH_VALUE"] == evil and env["CH_REMOVE"] == "1"
    for s in ALL_SCRIPTS.values():
        assert "{" not in s.split("try {", 1)[0]                     # no Python format holes before the body


def test_windows_backend_errors_and_elevation():
    wb = WindowsPosture(ps=FakePS({"Set-MpPreference": {"ok": False, "error": "Access is denied. 0x80070005"}}),
                        elevated=lambda: True)
    with pytest.raises(BackendError) as e:
        wb.apply({"op": "mp_pref", "pref": "PUAProtection", "value": 1})
    assert e.value.status == 403 and "start_cyberhub_admin" in e.value.message
    low = WindowsPosture(ps=FakePS(), elevated=lambda: False)
    with pytest.raises(BackendError) as e:
        low.apply({"op": "reg_set", "target": "wdigest", "value": 0})          # HKLM
    assert e.value.status == 403
    low.apply({"op": "reg_set", "target": "hide_ext", "value": 0})            # HKCU - fine without admin
    low.apply({"op": "mp_scan", "type": "quick"})
    pol = WindowsPosture(ps=FakePS({"Set-ExecutionPolicy": {"ok": True, "now": "Unrestricted"}}),
                         elevated=lambda: False)
    with pytest.raises(BackendError) as e:
        pol.apply({"op": "exec_policy", "policy": "RemoteSigned"})
    assert e.value.status == 409
    dead = WindowsPosture(ps=lambda *a, **k: None, elevated=lambda: True)
    with pytest.raises(BackendError) as e:
        dead.collect()
    assert e.value.status == 502
    opened = []
    WindowsPosture(ps=FakePS(), elevated=lambda: True, opener=opened.append).open_target("core_isolation")
    assert opened == ["windowsdefender://coreisolation"]


def test_windows_update_search_parse():
    fake = FakePS({"CreateUpdateSearcher": {"ok": True, "updates": [
        {"title": "2026-11 Cumulative Update (KB5068111)", "kb": "5068111", "severity": "Critical",
         "downloaded": True, "reboot": 1, "size": 1048576 * 700, "categories": "Security Updates"}]}})
    ups = WindowsPosture(ps=fake, elevated=lambda: True).search_updates()
    assert ups == [{"title": "2026-11 Cumulative Update (KB5068111)", "kb": ["KB5068111"], "severity": "Critical",
                    "downloaded": True, "reboot": True, "size_mb": 700.0, "categories": "Security Updates"}]


@pytest.mark.skipif(not (shutil.which("pwsh") or os.path.exists("/opt/pwsh/pwsh")), reason="pwsh not installed")
def test_powershell_scripts_parse():
    exe = shutil.which("pwsh") or "/opt/pwsh/pwsh"
    check = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($env:SRC,[ref]$t,"
             "[ref]$e);if($e.Count){$e|%{$_.ToString()}}else{'OK'}")
    for name, script in ALL_SCRIPTS.items():
        out = subprocess.run([exe, "-NoProfile", "-Command", check], env=dict(os.environ, SRC=script),
                             capture_output=True, text=True, timeout=60).stdout.strip()
        assert out == "OK", f"{name}: {out}"


# ====================================================================== Linux backend
def _linux_tree(root, *, secure=True, tpm2=True, reboot=True, auto="1", root_login="yes", guest=True):
    (root / "sys/firmware/efi/efivars").mkdir(parents=True)
    (root / "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(
        b"\x06\x00\x00\x00" + (b"\x01" if secure else b"\x00"))
    if tpm2:
        (root / "sys/class/tpm/tpm0").mkdir(parents=True)
        (root / "sys/class/tpm/tpm0/tpm_version_major").write_text("2\n")
    (root / "etc/apt/apt.conf.d").mkdir(parents=True)
    (root / "etc/apt/apt.conf.d/20auto-upgrades").write_text(
        f'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "{auto}";\n')
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text("x")
    if reboot:
        (root / "var/run").mkdir(parents=True)
        (root / "var/run/reboot-required").write_text("*** System restart required ***")
    (root / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text(f"PermitRootLogin {root_login}\nPasswordAuthentication yes\n"
                                              "Match User backup\n  PermitRootLogin no\n")
    (root / "etc/ssh/sshd_config.d/50-cloud.conf").write_text("PasswordAuthentication no\n")
    (root / "etc/lightdm").mkdir(parents=True)
    (root / "etc/lightdm/lightdm.conf").write_text(f"[Seat:*]\nallow-guest={'true' if guest else 'false'}\n")
    (root / "etc/os-release").write_text('PRETTY_NAME="Ubuntu 24.04.3 LTS"\n')


def test_linux_probe(tmp_path):
    _linux_tree(tmp_path)
    lsblk = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "mountpoint": None, "children": [
        {"name": "nvme0n1p1", "type": "part", "mountpoint": "/boot/efi"},
        {"name": "nvme0n1p3", "type": "part", "mountpoint": None, "children": [
            {"name": "dm_crypt-0", "type": "crypt", "mountpoint": None, "children": [
                {"name": "ubuntu--vg-root", "type": "lvm", "mountpoint": "/"}]}]}]}]}
    lp = LinuxPosture(tmp_path, lsblk=lambda: lsblk, sshd_running=lambda: True, elevated=lambda: False)
    f = lp.collect()
    assert f["os"]["name"] == "Ubuntu 24.04.3 LTS"
    assert f["secure_boot"] == {"uefi": True, "enabled": True} and f["tpm"]["version"] == "2.0"
    assert f["bitlocker"]["volumes"][0]["state"] == "on"
    assert f["update"]["pending_reboot"] and f["update"]["auto_updates"] is True
    assert f["ssh"] == {"running": True, "permit_root": "yes", "password_auth": "no"}   # .d file wins
    c = ev(f, now=datetime.now(timezone.utc))
    assert c["ssh_root"]["status"] == "fail" and c["ssh_root"]["severity"] == "high"
    assert c["ssh_passwords"]["status"] == "pass" and c["guest_account"]["status"] == "fail"
    assert c["secure_boot"]["status"] == "pass" and c["bitlocker_os"]["title"].startswith("Disk encryption")
    assert c["updates_reboot"]["status"] == "fail" and c["auto_updates"]["status"] == "pass"
    assert "uac_enabled" not in c and "defender_realtime" not in c
    assert all(x["fix"] is None for x in c.values())                                    # Linux = advice only


def test_linux_probe_plain_disk_no_tpm(tmp_path):
    _linux_tree(tmp_path, secure=False, tpm2=False, reboot=False, auto="0", root_login="no", guest=False)
    lsblk = {"blockdevices": [{"name": "sda", "type": "disk", "children": [
        {"name": "sda1", "type": "part", "mountpoints": ["/"]}]}]}
    f = LinuxPosture(tmp_path, lsblk=lambda: lsblk, sshd_running=lambda: False, elevated=lambda: False).collect()
    c = ev(f, now=datetime.now(timezone.utc))
    assert c["secure_boot"]["status"] == "fail" and c["tpm"]["status"] == "fail"
    assert c["bitlocker_os"]["status"] == "fail" and c["auto_updates"]["status"] == "fail"
    assert "ssh_root" not in c                                                          # sshd not running


def test_pick_backend(monkeypatch):
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "none")
    assert isinstance(pick_backend(), NoPosture)
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "linux")
    assert isinstance(pick_backend(), LinuxPosture)
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "memory")
    assert isinstance(pick_backend(), MemoryPosture)


# ====================================================================== API: overview
def test_status_and_info(c):
    s = c.get("/api/posture/status").json()
    assert s["error"] is None and s["platform"] == "windows" and 0 < s["score"] < 100
    assert [x["id"] for x in s["categories"]] == ["virus", "account", "network", "app", "device", "updates"]
    assert s["grade"] in ("At risk", "Needs attention") and s["totals"]["failed"] > 10
    assert s["top_issues"][0]["severity"] == "high" and s["os"]["display_version"] == "25H2"
    assert s["pending_reboot"] is True
    info = c.get("/api/info").json()
    assert info["build_part"] >= 11 and info["progress_percent"] >= 55 and "posture" in info["available_modules"]


def test_checks_filters(c):
    a = c.get("/api/posture/checks?category=device").json()
    assert {x["category"] for x in a["checks"]} == {"device"}
    f = c.get("/api/posture/checks?status=fail").json()["checks"]
    assert f and all(x["status"] == "fail" for x in f)
    sev = [pmod.SEVERITIES.index(x["severity"]) for x in f]
    assert sev == sorted(sev, reverse=True)                                   # worst first
    assert c.get("/api/posture/checks?category=nope").status_code == 422
    assert c.get("/api/posture/checks/no_such_check").status_code == 404


# ====================================================================== API: fixes
def test_simple_fix_is_verified_recorded_and_logged(c):
    assert chk(c, "guest_account")["status"] == "fail"
    r = c.post("/api/posture/checks/guest_account/fix").json()
    assert r["status"] == "applied" and r["verified"] is True and r["check"]["status"] == "pass"
    assert raw(c)["accounts"]["users"][1]["enabled"] is False
    ch = c.get("/api/posture/changes").json()["items"][0]
    assert ch["check_id"] == "guest_account" and ch["status"] == "applied" and ch["reversible"]
    assert ch["ops"] == [{"op": "user_enabled", "sid": "S-1-5-21-1111111111-2222222222-3333333333-501",
                          "enabled": False}]
    kinds = [e["kind"] for e in c.get("/api/posture/events").json()["items"]]
    assert "fix_applied" in kinds
    acts = c.get("/api/activity?category=posture").json()
    assert any("Guest" in a["title"] for a in acts["items"])
    assert c.post("/api/posture/checks/guest_account/fix").status_code == 409           # already passing


def test_confirm_required(c):
    r = c.post("/api/posture/checks/rdp_nla/fix")
    assert r.status_code == 428 and "Windows 7" in r.json()["detail"]
    assert raw(c)["rdp"]["nla"] == 0                                                     # nothing changed
    r = c.post("/api/posture/checks/rdp_nla/fix", json={"confirm": True})
    assert r.status_code == 200 and raw(c)["rdp"]["nla"] == 1


def test_reboot_flag(c):
    r = c.post("/api/posture/checks/wdigest/fix").json()
    assert r["reboot_required"] and raw(c)["hardening"]["wdigest"] == 0
    assert c.get("/api/posture/status").json()["changes_pending_reboot"] == 1


def test_manual_only_check_has_no_fix(c):
    r = c.post("/api/posture/checks/memory_integrity/fix")
    assert r.status_code == 400 and "steps" in r.json()["detail"]
    m = chk(c, "memory_integrity")["manual"]
    assert m["open"] == "core_isolation" and m["steps"]


def test_admin_only_exclusion_removal_keeps_narrow_ones(c):
    back = as_standard(c)
    r = c.post("/api/posture/checks/defender_exclusions/fix", json={"confirm": True})
    assert r.status_code == 403
    assert c.post("/api/posture/checks/defender_exclusions/fix", json={"confirm": True, "force": True}).status_code == 403
    back()
    r = c.post("/api/posture/checks/defender_exclusions/fix", json={"confirm": True}).json()
    assert r["status"] == "applied"
    assert raw(c)["prefs"]["ex_path"] == [r"D:\Projects\build"]                       # the narrow one stays


def test_tamper_protection_reported_not_hidden(c):
    raw(c)["defender"]["tamper"] = True
    raw(c)["prefs"]["maps"] = 0
    c1 = chk(c, "defender_cloud")
    assert c1["fix"] is None and c1["manual"]["open"] == "defender_settings"
    # a setting Windows silently refuses (Group Policy) -> not_applied + nothing left half-changed
    raw(c)["defender"]["tamper"] = False
    orig = mem(c).apply

    def stubborn(op):
        if op["op"] == "mp_pref":
            mem(c).calls.append("apply:mp_pref")
            return True
        return orig(op)
    mem(c).apply = stubborn
    r = c.post("/api/posture/checks/defender_cloud/fix").json()
    assert r["status"] == "not_applied" and r["verified"] is False and "Group Policy" in r["message"]
    assert c.get("/api/posture/changes").json()["items"][0]["status"] == "not_applied"
    assert "fix_not_applied" in [e["kind"] for e in c.get("/api/posture/events").json()["items"]]


def test_multi_step_fix_rolls_back_on_failure(c):
    raw(c)["hardening"]["ss_timeout"] = "3600"
    raw(c)["hardening"]["ss_active"] = "0"
    before = {k: raw(c)["hardening"][k] for k in ("ss_active", "ss_secure", "ss_timeout")}
    orig = mem(c).apply

    def flaky(op):
        if op["op"] == "reg_set" and op["target"] == "ss_timeout":
            raise BackendError(502, "registry hiccup")
        return orig(op)
    mem(c).apply = flaky
    r = c.post("/api/posture/checks/screen_lock/fix")
    assert r.status_code == 502 and "rolled back" in r.json()["detail"]
    assert {k: raw(c)["hardening"][k] for k in before} == before                      # exactly as it was
    assert c.get("/api/posture/changes").json()["items"][0]["status"] == "failed"


def test_engine_not_elevated(c):
    mem(c).elevated = False
    ps(c).invalidate()
    w = chk(c, "wdigest")
    assert w["fix"]["blocked"] and "start_cyberhub_admin" in w["fix"]["blocked"]
    r = c.post("/api/posture/checks/wdigest/fix")
    assert r.status_code == 403 and raw(c)["hardening"]["wdigest"] == 1
    assert c.post("/api/posture/checks/file_extensions/fix").json()["status"] == "applied"   # HKCU works
    res = c.post("/api/posture/fix-all").json()
    applied = {x["id"] for x in res["applied"]}
    assert {"ps_execution_policy", "autoplay", "smartscreen_store", "defender_scan", "defender_signatures"} <= applied
    reasons = {x["id"]: x["reason"] for x in res["skipped"]}
    assert "engine" in reasons["wdigest"] and "confirmation" in reasons["rdp_nla"]


def test_fix_all_admin_vs_standard_and_score_goes_up(c):
    sev_before = {x["id"]: x["severity"] for x in c.get("/api/posture/checks?status=fail").json()["checks"]}
    back = as_standard(c)
    res = c.post("/api/posture/fix-all", json={"min_severity": "medium"}).json()
    assert res["applied"] and res["score"] > res["score_before"]
    assert all(sev_before[x["id"]] in ("medium", "high", "critical") for x in res["applied"])
    assert "defender_exclusions" not in {x["id"] for x in res["applied"]}           # admin + confirm
    back()
    assert c.post("/api/posture/fix-all", json={"categories": ["bogus"]}).status_code == 422
    res = c.post("/api/posture/fix-all", json={"categories": ["app"]}).json()
    assert {x["id"] for x in res["applied"]} == {"file_extensions", "autoplay", "ps_execution_policy",
                                                  "smartscreen_store"}


def test_updates_paused_service_and_bitlocker_fixes(c):
    future = (datetime.now(timezone.utc) + timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    u = raw(c)["update"]
    u.update(pause_expiry=future, pause_quality_end=future, pause_start="2026-11-01T00:00:00Z", service="Disabled")
    assert chk(c, "updates_paused")["status"] == "fail" and chk(c, "updates_service")["severity"] == "high"
    assert c.post("/api/posture/checks/updates_paused/fix").json()["status"] == "applied"
    assert all(raw(c)["update"][k] is None for k in ("pause_expiry", "pause_quality_end", "pause_start"))
    assert c.post("/api/posture/checks/updates_service/fix").json()["status"] == "applied"
    assert raw(c)["update"]["service"] == "Manual"
    v = raw(c)["bitlocker"]["volumes"][0]
    v.update(status="FullyEncrypted", protection="Off", protectors=["Tpm", "RecoveryPassword"], percent=100)
    assert chk(c, "bitlocker_os")["value"] == "Suspended"
    r = c.post("/api/posture/checks/bitlocker_os/fix").json()
    assert r["status"] == "applied" and raw(c)["bitlocker"]["volumes"][0]["protection"] == "On"


# ====================================================================== API: undo / ignore
def test_revert_is_admin_only_and_restores(c):
    c.post("/api/posture/checks/guest_account/fix")
    c.post("/api/posture/checks/ps_execution_policy/fix")
    items = c.get("/api/posture/changes").json()["items"]
    guest_id = next(i["id"] for i in items if i["check_id"] == "guest_account")
    ps_id = next(i["id"] for i in items if i["check_id"] == "ps_execution_policy")
    back = as_standard(c)
    assert c.post(f"/api/posture/changes/{guest_id}/revert").status_code == 403
    back()
    r = c.post(f"/api/posture/changes/{guest_id}/revert").json()
    assert r["reverted"] == 1 and r["check"]["status"] == "fail" and raw(c)["accounts"]["users"][1]["enabled"]
    assert c.post(f"/api/posture/changes/{guest_id}/revert").status_code == 409
    c.post(f"/api/posture/changes/{ps_id}/revert")
    assert raw(c)["hardening"]["ps_user"] == "Unrestricted"
    c.post("/api/posture/checks/defender_signatures/fix")
    sig = c.get("/api/posture/changes").json()["items"][0]
    assert sig["check_id"] == "defender_signatures" and sig["reversible"] is False
    assert c.post(f"/api/posture/changes/{sig['id']}/revert").status_code == 400
    assert c.post("/api/posture/changes/9999/revert").status_code == 404


def test_revert_registry_value_that_did_not_exist(c):
    assert raw(c)["hardening"]["llmnr"] is None
    c.post("/api/posture/checks/llmnr/fix")
    assert raw(c)["hardening"]["llmnr"] == 0
    cid = c.get("/api/posture/changes").json()["items"][0]["id"]
    c.post(f"/api/posture/changes/{cid}/revert")
    assert raw(c)["hardening"]["llmnr"] is None                                       # deleted again, not set to 1


def test_ignore_and_unignore(c):
    s0 = c.get("/api/posture/status").json()["score"]
    back = as_standard(c)
    assert c.post("/api/posture/checks/bitlocker_os/ignore", json={"reason": "desk at home"}).status_code == 403
    back()
    r = c.post("/api/posture/checks/bitlocker_os/ignore", json={"reason": "desktop at home", "days": 30}).json()
    assert r["ignored"]["reason"] == "desktop at home" and r["ignored"]["until"]
    assert c.get("/api/posture/status").json()["score"] > s0
    assert [x["id"] for x in c.get("/api/posture/checks?status=ignored").json()["checks"]] == ["bitlocker_os"]
    assert "bitlocker_os" not in [x["id"] for x in c.get("/api/posture/checks?status=fail").json()["checks"]]
    assert c.post("/api/posture/checks/secure_boot/ignore").status_code == 409         # passing check
    back = as_standard(c)
    assert c.delete("/api/posture/checks/bitlocker_os/ignore").status_code == 200       # raising = anyone
    back()
    assert c.get("/api/posture/ignored").json()["items"] == []
    ps(c).db.execute("INSERT INTO posture_ignored(check_id, reason, until) VALUES ('wdigest','old','2020-01-01')")
    assert chk(c, "wdigest")["ignored"] is None                                       # expired -> back
    assert ps(c).db.fetchone("SELECT COUNT(*) AS n FROM posture_ignored")["n"] == 0


# ====================================================================== API: guards
def test_builtin_admin_guards(c):
    users = raw(c)["accounts"]["users"]
    users[0]["enabled"] = True                                       # built-in Administrator on
    raw(c)["os"]["user"] = "Administrator"
    r = c.post("/api/posture/checks/builtin_admin/fix", json={"confirm": True})
    assert r.status_code == 409 and "running as" in r.json()["detail"]
    raw(c)["os"]["user"] = "syed"
    raw(c)["accounts"]["admins"] = [r"LAB-PC\Administrator"]           # the only administrator
    r = c.post("/api/posture/checks/builtin_admin/fix", json={"confirm": True})
    assert r.status_code == 409 and "only enabled administrator" in r.json()["detail"]
    raw(c)["accounts"]["admins"] = [r"LAB-PC\Administrator", r"LAB-PC\syed"]
    back = as_standard(c)
    assert c.post("/api/posture/checks/builtin_admin/fix", json={"confirm": True}).status_code == 403
    back()
    assert c.post("/api/posture/checks/builtin_admin/fix", json={"confirm": True}).json()["status"] == "applied"
    assert raw(c)["accounts"]["users"][0]["enabled"] is False


def test_remote_desktop_guards(c):
    raw(c)["os"]["session"] = "RDP-Tcp#3"
    r = c.post("/api/posture/checks/remote_desktop/fix", json={"confirm": True})
    assert r.status_code == 409 and "Remote Desktop yourself" in r.json()["detail"]
    raw(c)["os"]["session"] = "Console"
    mem(c).rdp_connected = 2
    r = c.post("/api/posture/checks/remote_desktop/fix", json={"confirm": True})
    assert r.status_code == 409 and "2 Remote Desktop connection" in r.json()["detail"]
    assert raw(c)["rdp"]["deny"] == 0
    r = c.post("/api/posture/checks/remote_desktop/fix", json={"confirm": True, "force": True})
    assert r.json()["status"] == "applied" and raw(c)["rdp"]["deny"] == 1
    assert "rdp_nla" not in {x["id"] for x in c.get("/api/posture/checks").json()["checks"]}


def test_one_fix_at_a_time(c):
    assert ps(c)._fix_lock.acquire(blocking=False)
    try:
        r = c.post("/api/posture/checks/guest_account/fix")
        assert r.status_code == 409 and "Another fix" in r.json()["detail"]
    finally:
        ps(c)._fix_lock.release()


# ====================================================================== Part 9 integration
def test_firewall_check_and_fix_go_through_part9(c):
    fwm = c.app.state.firewall.backend
    fwm._profiles["public"]["enabled"] = False
    c.app.state.firewall.invalidate()
    f = chk(c, "firewall_on")
    assert f["status"] == "fail" and f["severity"] == "critical" and "Public" in f["value"]
    r = c.post("/api/posture/checks/firewall_on/fix").json()
    assert r["status"] == "applied" and fwm._profiles["public"]["enabled"] is True
    fev = c.get("/api/firewall/events").json()["items"]
    assert any(e["kind"] == "firewall_on" and e["username"] == "syed" for e in fev)   # Part 9's own event
    cid = c.get("/api/posture/changes").json()["items"][0]["id"]
    back = as_standard(c)
    assert c.post(f"/api/posture/changes/{cid}/revert").status_code == 403
    back()
    c.post(f"/api/posture/changes/{cid}/revert")
    assert fwm._profiles["public"]["enabled"] is False


def test_rdp_exposure_uses_part9_verdict(c):
    assert chk(c, "remote_desktop")["severity"] == "low"                       # seeded rule is service-scoped
    c.app.state.firewall.backend.add_rule({"id": "test-rdp", "name": "RDP open", "direction": "in",
                                           "action": "allow", "local_ports": ["3389"], "protocol": "tcp",
                                           "profiles": ["private", "public", "domain"]})
    c.app.state.firewall.invalidate()
    r = chk(c, "remote_desktop")
    assert r["severity"] == "high" and "from any address" in r["detail"]
    assert r["evidence"]["firewall"]["verdict"] == "allowed"


def test_part9_failure_never_breaks_posture(c, monkeypatch):
    def boom():
        raise RuntimeError("firewall exploded")
    monkeypatch.setattr(c.app.state.firewall, "status", boom)
    a = c.get("/api/posture/checks?refresh=true").json()
    fw = next(x for x in a["checks"] if x["id"] == "firewall_on")
    assert fw["status"] == "unknown" and len(a["checks"]) > 30


def test_posture_reads_do_not_touch_other_parts(c):
    fw_calls = list(c.app.state.firewall.backend.calls)
    c.get("/api/posture/status")
    c.post("/api/posture/watch")
    new = c.app.state.firewall.backend.calls[len(fw_calls):]
    assert new and all(x in ("profiles", "rules") for x in new)                # read-only on Part 9
    assert c.get("/api/firewall/events").json()["total"] == 0


# ====================================================================== watch
def test_watch_baseline_regressions_and_exclusions(c):
    w = c.post("/api/posture/watch").json()
    assert w["baseline"] and w["regressions"] == 0
    assert [e["kind"] for e in c.get("/api/posture/events").json()["items"]] == ["baseline"]
    last = c.get("/api/posture/events").json()["last_id"]
    raw(c)["defender"]["realtime"] = False                                      # malware switched it off
    raw(c)["uac"]["enable_lua"] = 0
    raw(c)["prefs"]["ex_path"].append(r"C:\Users\syed\AppData\Local\Temp\x")
    raw(c)["prefs"]["ex_path"].remove(r"D:\Projects\build")
    raw(c)["accounts"]["users"][1]["enabled"] = False                          # Guest fixed outside Cyber Hub
    w = c.post("/api/posture/watch").json()
    assert w["regressions"] == 2 and w["exclusions_added"] == 1 and w["resolved"] >= 1
    evs = {e["kind"]: e for e in c.get(f"/api/posture/events?after_id={last}").json()["items"]}
    reg = [e for e in c.get(f"/api/posture/events?after_id={last}&kind=regression").json()["items"]]
    assert {e["severity"] for e in reg} == {"critical"} and not reg[0]["acknowledged"]
    assert evs["exclusion_added"]["severity"] == "high" and "AppData" in evs["exclusion_added"]["title"]
    assert evs["exclusion_added"]["data"]["risk"]
    assert evs["exclusion_removed"]["severity"] == "info" and evs["resolved"]["severity"] == "info"
    w = c.post("/api/posture/watch").json()                                     # nothing new -> quiet
    assert w["regressions"] == 0 and w["exclusions_added"] == 0


def test_own_fixes_are_not_regressions_and_alerts_can_be_off(c):
    c.post("/api/posture/watch")
    c.post("/api/posture/checks/guest_account/fix")
    cid = c.get("/api/posture/changes").json()["items"][0]["id"]
    c.post(f"/api/posture/changes/{cid}/revert")                                # own undo
    assert c.post("/api/posture/watch").json()["regressions"] == 0
    c.patch("/api/settings", json={"posture_alert_regressions": False})
    raw(c)["defender"]["realtime"] = False
    assert c.post("/api/posture/watch").json()["regressions"] == 1
    assert c.get("/api/posture/events?kind=regression").json()["total"] == 0


def test_watch_settings_are_admin_guarded(c):
    back = as_standard(c)
    assert c.patch("/api/settings", json={"posture_watch_enabled": False}).status_code == 403
    assert c.patch("/api/settings", json={"posture_watch_interval_minutes": 60}).status_code == 200
    back()
    assert c.patch("/api/settings", json={"posture_watch_interval_minutes": 1}).status_code == 422


def test_events_ack_clear_and_summary(c):
    c.post("/api/posture/watch")
    raw(c)["defender"]["realtime"] = False
    c.post("/api/posture/watch")
    e = c.get("/api/posture/events?unacknowledged=true").json()
    assert e["unacknowledged"] >= 1
    assert c.post("/api/posture/events/ack", json={"ids": [e["items"][0]["id"]]}).json()["acknowledged"] == 1
    c.post("/api/posture/events/ack")
    assert c.get("/api/posture/status").json()["unacknowledged_alerts"] == 0
    s = c.get("/api/posture/summary?days=7").json()
    assert len(s["per_day"]) == 7 and s["per_day"][-1]["score"] is not None and s["categories"]
    assert s["events_by_kind"]["regression"] >= 1
    back = as_standard(c)
    assert c.delete("/api/posture/events").status_code == 403
    back()
    assert c.delete("/api/posture/events").json()["deleted"] >= 2
    back = as_standard(c)
    assert c.post("/api/posture/rebaseline").status_code == 403
    back()
    assert c.post("/api/posture/rebaseline").json()["baseline"] is True


def test_posture_loop_runs_and_survives(c):
    calls = {"n": 0}
    svc = ps(c)
    orig = svc.watch_once

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise PostureError(502, "boom")
        return orig()
    svc.watch_once = flaky
    c.app.state.settings_store.update({"posture_watch_interval_minutes": 5})

    async def go():
        t = asyncio.create_task(posture_loop(svc, c.app.state.settings_store, tick=0.01, first_delay=0))
        await asyncio.sleep(0.15)
        t.cancel()
    asyncio.run(go())
    assert calls["n"] == 1                                       # ran straight away, failure did not kill it
    svc.watch_once = orig


# ====================================================================== Defender / updates / accounts / open
def test_defender_endpoints(c):
    d = c.get("/api/posture/defender").json()
    assert d["defender"]["signature_age_days"] == 9 and d["exclusions_readable"]
    risky = [x for x in d["exclusions"] if x["risk"]]
    assert [x["value"] for x in risky] == [r"C:\Users\syed\Downloads"]
    assert any(x["id"] == "defender_exclusions" for x in d["checks"])
    d = c.post("/api/posture/defender/update").json()
    assert d["defender"]["signature_age_days"] == 0
    assert c.post("/api/posture/defender/scan", json={"type": "full"}).json() == {"started": True, "type": "full"}
    assert raw(c)["defender"]["full_age"] == 0
    assert c.post("/api/posture/defender/scan", json={"type": "deep"}).status_code == 422


def test_update_search(c):
    mem(c).search_delay = 0.2
    r = c.post("/api/posture/updates/search").json()
    assert r["state"] == "running"
    assert c.post("/api/posture/updates/search").json()["state"] == "running"             # no second search
    for _ in range(100):
        s = c.get("/api/posture/updates/search").json()
        if s["state"] != "running":
            break
        time.sleep(0.02)
    assert s["state"] == "done" and s["count"] == 2 and s["updates"][0]["kb"] == ["KB5068111"]
    assert mem(c).calls.count("search_updates") == 1
    u = c.get("/api/posture/updates").json()
    assert u["support"]["end"] == "2027-10-12" and u["search"]["count"] == 2
    assert any(x["id"] == "updates_recent" for x in u["checks"])
    assert c.get("/api/posture/events?kind=updates_missing").json()["items"][0]["severity"] == "medium"
    mem(c).search_delay = 0
    c.post("/api/posture/updates/search")                                   # same updates again -> no new alert
    for _ in range(100):
        if c.get("/api/posture/updates/search").json()["state"] != "running":
            break
        time.sleep(0.02)
    assert c.get("/api/posture/events?kind=updates_missing").json()["total"] == 1


def test_accounts_and_open(c):
    a = c.get("/api/posture/accounts").json()
    assert a["current_user"] == "syed" and len(a["users"]) == 5
    assert {x["id"] for x in a["checks"]} >= {"guest_account", "blank_passwords", "uac_enabled", "wdigest"}
    assert c.post("/api/posture/open/core_isolation").json() == {"opened": "core_isolation"}
    assert mem(c).opened == ["core_isolation"]
    assert c.post("/api/posture/open/cmd.exe").status_code == 404


# ====================================================================== unsupported / auth / regression
def test_no_backend(env, monkeypatch):
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "none")
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        s = cl.get("/api/posture/status").json()
        assert s["score"] is None and s["error"]
        assert cl.get("/api/posture/checks").status_code == 501
        assert cl.post("/api/posture/watch").status_code == 501
        assert cl.get("/api/posture/summary").json()["score"] is None
        assert cl.get("/api/firewall/status").status_code == 200


def test_requires_session(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/posture/status").status_code == 401                   # no token
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        assert cl.get("/api/posture/status").status_code == 401                   # no session
        assert cl.post("/api/posture/checks/guest_account/fix").status_code == 401


def test_parts_1_to_10_still_answer(c):
    for path in ("/api/system/info", "/api/monitor/overview", "/api/processes?limit=5", "/api/scan/summary",
                 "/api/quarantine", "/api/realtime/status", "/api/rules/status", "/api/firewall/status",
                 "/api/network/status"):
        assert c.get(path).status_code == 200, path
    assert c.get("/api/health").json()["schema_version"] >= 12


def test_migration_from_part10_database_keeps_data(env):
    cfg = Settings()
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for v, d, sql in MIGRATIONS:
        if v <= 11:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    db.execute("INSERT INTO network_events(kind, title) VALUES ('new_device', 'kept')")
    assert db.schema_version() == 11
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/health").json()["schema_version"] >= 12
        assert cl.app.state.db.fetchone("SELECT title FROM network_events")["title"] == "kept"
        con = sqlite3.connect(str(cfg.db_path))
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        assert {"posture_events", "posture_check_state", "posture_changes", "posture_ignored", "posture_scores",
                "posture_state"} <= tables
