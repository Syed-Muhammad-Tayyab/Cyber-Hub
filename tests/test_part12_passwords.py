"""
Cyber Hub Backend - Part 12 tests: Password Vault & Auditor
Developed by Syed Muhammad Tayyab

Crypto runs for real (scrypt with a low N via CYBERHUB_PV_KDF_N so the suite
stays fast, AES-256-GCM, HKDF, Part 6 device key). Have I Been Pwned is a
fake transport that records every URL, so the tests also prove only five
SHA-1 characters ever leave the PC. The clipboard is the memory backend.
"""
import asyncio
import base64
import hashlib
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import password_tools as tools
from cyberhub.services import password_io as pio
from cyberhub.services import password_vault as pvmod
from cyberhub.services.clipboard import ClipboardManager, MemoryClipboard
from cyberhub.services.password_tools import BreachChecker, ToolError
from cyberhub.services.password_vault import format_recovery, parse_recovery

PW = "Cyb3r!Hub#2026"                          # Cyber Hub sign-in password
MASTER = "Glacier-Mango-Tunnel-Velvet-42"      # vault master password
MASTER2 = "Orbit Pickle Lantern Meadow 7"


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
    monkeypatch.setenv("CYBERHUB_CLIPBOARD_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_PV_KDF_N", "1024")
    return tmp_path


class FakeHIBP:
    """Pwned Passwords range API double. breached = {password: count}."""
    def __init__(self, breached=None, status=200):
        self.breached = dict(breached or {})
        self.status = status
        self.urls: list[str] = []
        self.headers: list[dict] = []
        self.fail: Exception | None = None

    def __call__(self, method, url, headers, data, timeout):
        self.urls.append(url)
        self.headers.append(headers)
        if self.fail:
            raise self.fail
        prefix = url.rsplit("/", 1)[-1]
        lines = ["0" * 35 + ":0", "F" * 35 + ":0"]                                    # padding rows
        for pw, n in self.breached.items():
            h = hashlib.sha1(pw.encode()).hexdigest().upper()
            if h[:5] == prefix:
                lines.append(f"{h[5:]}:{n}")
        lines.append("1234567890ABCDEF1234567890ABCDEF123:7")
        return self.status, "\r\n".join(lines).encode()


def _login(cl, user="syed", role=None):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.app.state.passwords.breach.transport = FakeHIBP()
        yield cl


@pytest.fixture()
def v(c):
    """Signed in with a vault set up and unlocked."""
    r = c.post("/api/passwords/setup", json={"master_password": MASTER, "hint": "fruit tunnel"})
    assert r.status_code == 200, r.text
    c.recovery_key = r.json()["recovery_key"]
    return c


def svc(c) -> pvmod.PasswordVaultService:
    return c.app.state.passwords


def add(c, kind="login", **data):
    data.setdefault("title", "Item")
    r = c.post("/api/passwords/items", json={"type": kind, "data": data})
    assert r.status_code == 200, r.text
    return r.json()


def other_user(c, name="kid", role="standard"):
    c.post("/api/account/users", json={"username": name, "display_name": name, "password": PW, "role": role})
    mine = c.headers["X-CyberHub-Session"]
    r = c.post("/api/account/login", json={"username": name, "password": PW})
    theirs = r.json()["session_token"]

    def switch(to):
        c.headers["X-CyberHub-Session"] = mine if to == "me" else theirs
    return switch


# ====================================================================== generator
def test_generate_password_rules():
    for _ in range(30):
        g = tools.generate("password", length=16)
        p = g["password"]
        assert len(p) == 16 and any(ch.islower() for ch in p) and any(ch.isupper() for ch in p)
        assert any(ch.isdigit() for ch in p) and any(not ch.isalnum() for ch in p)
        assert not set(p) & tools.AMBIGUOUS
    g = tools.generate("password", length=40, symbols=False, upper=False, exclude="abc", min_digits=5)
    assert not set(g["password"]) & set("abcABC!@#") and sum(ch.isdigit() for ch in g["password"]) >= 5
    assert g["character_sets"] == ["digits", "lower"]
    assert g["entropy_bits"] == round(40 * __import__("math").log2(len(set("defghijkmnpqrstuvwxyz23456789"))), 1)
    with pytest.raises(ToolError):
        tools.generate("password", length=4, min_digits=3, min_symbols=3)
    with pytest.raises(ToolError):
        tools.generate("password", lower=False, upper=False, digits=False, symbols=False)
    with pytest.raises(ToolError):
        tools.generate("password", length=200)
    assert len({tools.generate("password")["password"] for _ in range(50)}) == 50


def test_generate_passphrase_and_pin():
    words = tools.wordlist()
    assert len(words) == 7772 and "abacus" in words and "t-shirt" not in words   # hyphenated words skipped
    g = tools.generate("passphrase", words=6, separator=".", capitalize=False, include_number=False)
    parts = g["password"].split(".")
    assert len(parts) == 6 and all(w in words for w in parts) and g["entropy_bits"] == 77.5
    g = tools.generate("passphrase")
    assert len(g["password"].split("-")) == 5 and any(ch.isdigit() for ch in g["password"])
    assert g["password"].split("-")[0][0].isupper()
    for _ in range(50):
        pin = tools.generate("pin", length=6)["password"]
        assert pin.isdigit() and len(pin) == 6 and len(set(pin)) > 1 and pin not in "0123456789"
    with pytest.raises(ToolError):
        tools.generate("pin", length=3)
    with pytest.raises(ToolError):
        tools.generate("emoji")


# ====================================================================== strength
def test_strength_realistic():
    weak = tools.strength("Pakistan@123")
    assert weak["score"] <= 1 and weak["engine"] == "zxcvbn" and weak["warning"]
    assert tools.strength("Lahore@786")["score"] <= 1
    assert tools.strength("password1")["score"] == 0
    assert tools.strength("qwertyuiop")["score"] == 0
    strong = tools.strength("Glacier-Mango-Tunnel-Velvet-42")
    assert strong["score"] == 4 and strong["crack_times"]["offline_fast"]["display"]
    assert tools.strength("xK9#mQ2$vL7!pR4w")["score"] >= 3
    # the user's own name / site make a password weaker
    assert tools.strength("tayyabfuuast26", ["tayyab", "fuuast.edu.pk"])["score"] < \
        tools.strength("tayyabfuuast26")["score"] or tools.strength("tayyabfuuast26", ["tayyab"])["score"] <= 2
    assert tools.strength("")["score"] == 0
    long = tools.strength("Glacier-Mango-Tunnel-Velvet-42-" * 5)                  # > 72 chars is fine
    assert long["score"] == 4 and long["length"] == 155
    s = tools.strength("Rawalpindi2024")
    assert s["score"] <= 1


def test_strength_falls_back_without_zxcvbn(monkeypatch):
    monkeypatch.setattr(tools, "_zxcvbn", None)
    s = tools.strength("Pakistan@123")
    assert s["engine"] == "basic" and s["score"] <= 2 and "crack_times" in s
    assert tools.strength("xK9#mQ2$vL7!pR4w-Tz")["score"] >= 3


# ====================================================================== TOTP (RFC 6238 appendix B)
@pytest.mark.parametrize("t,algo,key,code", [
    (59, "SHA1", b"12345678901234567890", "94287082"),
    (1111111109, "SHA1", b"12345678901234567890", "07081804"),
    (1234567890, "SHA1", b"12345678901234567890", "89005924"),
    (59, "SHA256", b"12345678901234567890123456789012", "46119246"),
    (2000000000, "SHA256", b"12345678901234567890123456789012", "90698825"),
    (59, "SHA512", b"1234567890123456789012345678901234567890123456789012345678901234", "90693936"),
    (20000000000, "SHA512", b"1234567890123456789012345678901234567890123456789012345678901234", "47863826"),
])
def test_totp_rfc6238(t, algo, key, code):
    secret = base64.b32encode(key).decode()
    uri = f"otpauth://totp/Test:me?secret={secret}&digits=8&algorithm={algo}&period=30"
    r = tools.totp(uri, at=t)
    assert r["code"] == code and r["digits"] == 8 and r["issuer"] == "Test" and r["account"] == "me"


def test_totp_parsing():
    secret = base64.b32encode(b"12345678901234567890").decode()
    r = tools.totp(secret.lower()[:8] + " " + secret.lower()[8:], at=59)
    assert r["code"] == "287082" and r["remaining"] == 1 and r["period"] == 30
    for bad in ("not base32!", "otpauth://hotp/x?secret=" + secret, "ABCDEF",
                f"otpauth://totp/x?secret={secret}&digits=5", f"otpauth://totp/x?secret={secret}&algorithm=MD5"):
        with pytest.raises(ToolError):
            tools.totp(bad)


# ====================================================================== Have I Been Pwned
def test_breach_checker_k_anonymity():
    fake = FakeHIBP({"Pakistan@123": 4242})
    b = BreachChecker(transport=fake)
    assert b.check("Pakistan@123") == 4242
    sha = hashlib.sha1(b"Pakistan@123").hexdigest().upper()
    assert fake.urls == [f"https://api.pwnedpasswords.com/range/{sha[:5]}"]           # only 5 chars sent
    assert fake.headers[0]["Add-Padding"] == "true"
    assert sha[5:] not in "".join(fake.urls)
    assert b.check("Pakistan@123") == 4242 and len(fake.urls) == 1                     # cached
    assert b.check("a-truly-unique-passphrase-xyz") == 0
    fake2 = FakeHIBP(status=429)
    with pytest.raises(ToolError) as e:
        BreachChecker(transport=fake2).check("x")
    assert e.value.status == 429
    fake3 = FakeHIBP()
    fake3.fail = OSError("blocked")
    with pytest.raises(ToolError) as e:
        BreachChecker(transport=fake3).check("x")
    assert e.value.status == 502
    with pytest.raises(ToolError):
        b.check_sha1("xyz")


# ====================================================================== import / export formats
CHROME = "name,url,username,password,note\nGitHub,https://github.com/login,syed,gh-Pass-1!,work\n" \
         "Gmail,https://accounts.google.com,syed@gmail.com,Pakistan@123,\n,,,,\n"
FIREFOX = '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed",' \
          '"timePasswordChanged"\n"https://www.facebook.com","syed","fb!Pass99",,"https://www.facebook.com",' \
          '"{1}","1","1","1"\n"chrome://FirefoxAccounts","x","y",,,"{2}","1","1","1"\n'
BITWARDEN = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" \
            'Work,1,login,Jira,,"Team: blue\nPIN: 1234",0,"https://jira.example.com,https://alt.example.com",' \
            "syed,j1ra-Pass,JBSWY3DPEHPK3PXP\n,,note,Wifi codes,home=abc,,0,,,,\n,,card,Visa,,,0,,,,\n"
LASTPASS = "url,username,password,totp,extra,name,grouping,fav\nhttps://upwork.com,syed,up-Pass-7,,,Upwork,Freelance,1\n" \
           "http://sn,,,,secret note body,Bank PIN,Finance,0\n"
ONEPASSWORD = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n" \
              "LinkedIn,https://linkedin.com,syed,li-Pass-3,,false,false,,hello\n"
KEEPASS = '"Account","Login Name","Password","Web Site","Comments"\n"Fiverr","syed","fv-Pass-4","fiverr.com","x"\n'
KEEPASSXC = '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n' \
            '"Root/Dev","VS Code","syed","vs-Pass-5","https://vscode.dev","","","0","",""\n'


def test_csv_formats_detected_and_parsed():
    f, items, skipped = pio.parse_csv("﻿" + CHROME)
    assert f == "chrome" and [i["title"] for i in items] == ["GitHub", "Gmail"] and items[0]["notes"] == "work"
    assert items[0]["urls"] == ["https://github.com/login"] and items[1]["password"] == "Pakistan@123"
    f, items, skipped = pio.parse_csv(FIREFOX)
    assert f == "firefox" and items[0]["title"] == "facebook.com" and skipped[0]["reason"].startswith("Firefox")
    f, items, skipped = pio.parse_csv(BITWARDEN)
    assert f == "bitwarden" and items[0]["folder"] == "Work" and items[0]["favorite"] is True
    assert items[0]["urls"] == ["https://jira.example.com", "https://alt.example.com"]
    assert items[0]["fields"] == [{"name": "Team", "value": "blue", "hidden": False},
                                  {"name": "PIN", "value": "1234", "hidden": False}]
    assert items[0]["totp"] == "JBSWY3DPEHPK3PXP" and items[1]["type"] == "note" and items[1]["notes"] == "home=abc"
    assert "card" in skipped[0]["reason"]
    f, items, _ = pio.parse_csv(LASTPASS)
    assert f == "lastpass" and items[0]["folder"] == "Freelance" and items[1]["type"] == "note"
    assert items[1]["title"] == "Bank PIN" and items[1]["notes"] == "secret note body"
    f, items, _ = pio.parse_csv(ONEPASSWORD)
    assert f == "onepassword" and items[0]["title"] == "LinkedIn"
    f, items, _ = pio.parse_csv(KEEPASS)
    assert f == "keepass" and items[0]["username"] == "syed" and items[0]["urls"] == ["fiverr.com"]
    f, items, _ = pio.parse_csv(KEEPASSXC)
    assert f == "keepassxc" and items[0]["folder"] == "Root/Dev"
    f, items, _ = pio.parse_csv("Website,Email,Password\nexample.com,a@b.c,  spaced pw  \n")
    assert f == "generic" and items[0]["password"] == "  spaced pw  " and items[0]["username"] == "a@b.c"
    for bad in ("", "a,b\n1,2\n", "only,header,password\n"):
        with pytest.raises(ToolError):
            pio.parse_csv(bad)


def test_backup_roundtrip_and_tamper():
    items = [{"type": "login", "payload": {"title": "TitleNeedle-42", "password": "p"}, "created_at": "x"}]
    kdf = {"n": 1024, "r": 8, "p": 1}
    text = pio.encrypt_backup(items, "Backup-Pass-Phrase-1", kdf, "0.12.0")
    doc = json.loads(text)
    assert doc["format"] == "cyberhub-vault" and b"TitleNeedle" not in base64.b64decode(doc["data"])
    assert pio.decrypt_backup(text, "Backup-Pass-Phrase-1")[0]["payload"]["title"] == "TitleNeedle-42"
    with pytest.raises(ToolError) as e:
        pio.decrypt_backup(text, "wrong")
    assert e.value.status == 401
    raw = bytearray(base64.b64decode(doc["data"]))
    raw[5] ^= 1
    doc["data"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ToolError):
        pio.decrypt_backup(json.dumps(doc), "Backup-Pass-Phrase-1")
    with pytest.raises(ToolError):
        pio.decrypt_backup("{}", "x")
    out = pio.to_csv([{"type": "login", "payload": {"title": "T", "username": "u", "password": "=1+1", "urls":
                                                    ["https://a.b"], "notes": "", "fields": []}},
                      {"type": "card", "payload": {"title": "Visa", "number": "4111111111111111", "cvv": "123"}}])
    assert out.splitlines()[0].startswith("folder,favorite,type,name") and "=1+1" in out and "CVV: 123" in out


def test_recovery_key_format():
    raw = bytes(range(20))
    k = format_recovery(raw)
    assert len(k) == 39 and k.count("-") == 7
    assert parse_recovery(k) == raw and parse_recovery(k.lower().replace("-", " ")) == raw
    assert parse_recovery("nope") is None and parse_recovery(k[:-1] + "1") is None


def test_clipboard_manager_wipes_only_our_copy():
    mem = MemoryClipboard()
    cm = ClipboardManager(mem)
    cm.copy("s3cret", clear_after=0)
    assert mem.text == "s3cret" and cm.clear_now() and mem.text is None
    cm.copy("s3cret", clear_after=0)
    mem.copy("user copied something else")
    assert cm.clear_now() is False and mem.text == "user copied something else"
    cm.copy("timed", clear_after=1)
    time.sleep(1.4)
    assert mem.text is None
    cm.copy("on-exit", clear_after=60)
    cm.shutdown()
    assert mem.text is None


# ====================================================================== setup / unlock
def test_status_and_setup_rules(c):
    s = c.get("/api/passwords/status").json()
    assert s["exists"] is False and s["unlocked"] is False and s["strength_engine"] == "zxcvbn"
    assert c.get("/api/passwords/items").status_code == 404
    for bad, why in (("short", "10 characters"), ("Pakistan@123456", "too easy"), ("qwertyuiop123", "too easy")):
        r = c.post("/api/passwords/setup", json={"master_password": bad})
        assert r.status_code == 422, bad
        if why:
            assert why in r.json()["detail"]
    # same as the Cyber Hub sign-in password -> refused
    assert c.post("/api/account/change-password", json={"current_password": PW, "new_password": "Sign-In-Phrase-Mango-77"}).status_code == 200
    r = c.post("/api/passwords/setup", json={"master_password": "Sign-In-Phrase-Mango-77"})
    assert r.status_code == 422 and "different" in r.json()["detail"]
    r = c.post("/api/passwords/setup", json={"master_password": MASTER, "hint": "it is " + MASTER})
    assert r.status_code == 422 and "hint" in r.json()["detail"]
    r = c.post("/api/passwords/setup", json={"master_password": MASTER, "hint": "fruit"})
    assert r.status_code == 200 and parse_recovery(r.json()["recovery_key"])
    st = r.json()["status"]
    assert st["exists"] and st["unlocked"] and st["device_bound"] and st["kdf"]["n"] == 1024
    assert c.post("/api/passwords/setup", json={"master_password": MASTER}).status_code == 409
    assert c.get("/api/passwords/hint").json()["hint"] == "fruit"
    ev = c.get("/api/passwords/events").json()["items"]
    assert ev[0]["kind"] == "vault_created"


def test_lock_unlock_and_brute_force_backoff(v):
    item = add(v, title="GitHub", username="syed", password="gh-Pass-1!")["item"]
    assert v.post("/api/passwords/lock").json()["unlocked"] is False
    r = v.get("/api/passwords/items")
    assert r.status_code == 423 and "Password vault is locked" in r.json()["detail"]
    assert v.get(f"/api/passwords/items/{item['id']}").status_code == 423
    assert v.post("/api/passwords/unlock", json={}).status_code == 422
    for i in range(4):
        assert v.post("/api/passwords/unlock", json={"master_password": "wrong"}).status_code == 401
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 200   # resets
    v.post("/api/passwords/lock")
    for i in range(5):
        assert v.post("/api/passwords/unlock", json={"master_password": "wrong"}).status_code == 401
    r = v.post("/api/passwords/unlock", json={"master_password": MASTER})
    assert r.status_code == 429 and 25 <= int(r.headers["Retry-After"]) <= 31
    st = v.get("/api/passwords/status").json()
    assert st["failed_unlocks"] == 5 and st["locked_until"]
    kinds = [e["kind"] for e in v.get("/api/passwords/events").json()["items"]]
    assert "lockout" in kinds and kinds.count("unlock_failed") >= 4
    v.app.state.db.execute("UPDATE pv_vaults SET locked_until=?", ("2000-01-01T00:00:00.000Z",))
    r = v.post("/api/passwords/unlock", json={"master_password": MASTER})
    assert r.status_code == 200 and r.json()["status"]["failed_unlocks"] == 0
    assert v.get("/api/passwords/items").json()["total"] == 1


def test_vault_follows_cyber_hub_session(v):
    add(v, title="A", password="a-Pass-1!")
    v.post("/api/account/lock")
    v.post("/api/account/unlock", json={"password": PW})
    assert v.get("/api/passwords/items").status_code == 423                           # locked with the app
    v.post("/api/passwords/unlock", json={"master_password": MASTER})
    v.patch("/api/settings", json={"pv_lock_with_session": False})
    v.post("/api/account/lock")
    v.post("/api/account/unlock", json={"password": PW})
    assert v.get("/api/passwords/items").status_code == 200                           # setting respected
    # signing out always locks it
    tok = v.headers["X-CyberHub-Session"]
    v.post("/api/account/logout")
    assert not svc(v)._opens
    v.headers["X-CyberHub-Session"] = tok
    assert v.get("/api/passwords/items").status_code == 401


def test_idle_auto_lock_and_sweep(v):
    o = next(iter(svc(v)._opens.values()))
    o.last_used -= 6 * 60                                                              # default 5 minutes
    assert svc(v).sweep() == 1 and o.alive is False and all(b == 0 for b in o.key)
    assert v.get("/api/passwords/items").status_code == 423
    v.post("/api/passwords/unlock", json={"master_password": MASTER})
    v.patch("/api/settings", json={"pv_auto_lock_minutes": 0})
    next(iter(svc(v)._opens.values())).last_used -= 10_000
    assert svc(v).sweep() == 0
    st = v.get("/api/passwords/status").json()
    assert st["unlocked"] and st["auto_lock_in_seconds"] is None


def test_password_vault_loop_runs_sweep(v):
    o = next(iter(svc(v)._opens.values()))
    o.last_used -= 3600

    async def run():
        t = asyncio.create_task(pvmod.password_vault_loop(svc(v), tick=0.05))
        await asyncio.sleep(0.3)
        t.cancel()
    asyncio.run(run())
    assert not svc(v)._opens


def test_recovery_key_flow(v):
    item = add(v, title="Bank", password="b4nk-Pass!")["item"]
    v.post("/api/passwords/lock")
    r = v.post("/api/passwords/unlock", json={"recovery_key": v.recovery_key})
    assert r.status_code == 422                                                         # needs a new master
    r = v.post("/api/passwords/unlock", json={"recovery_key": "AAAA-BBBB", "new_master_password": MASTER2})
    assert r.status_code == 401
    r = v.post("/api/passwords/unlock", json={"recovery_key": v.recovery_key.lower(), "new_master_password": MASTER2})
    assert r.status_code == 200 and r.json()["recovery_key"] != v.recovery_key
    new_rk = r.json()["recovery_key"]
    assert v.get(f"/api/passwords/items/{item['id']}?reveal=true").json()["item"]["data"]["password"] == "b4nk-Pass!"
    v.post("/api/passwords/lock")
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 401
    assert v.post("/api/passwords/unlock", json={"recovery_key": v.recovery_key,
                                                 "new_master_password": MASTER}).status_code == 401  # retired
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER2}).status_code == 200
    r = v.post("/api/passwords/recovery-key", json={"master_password": MASTER2})
    assert r.status_code == 200 and r.json()["recovery_key"] != new_rk
    kinds = [e["kind"] for e in v.get("/api/passwords/events").json()["items"]]
    assert "recovery_used" in kinds and "recovery_regenerated" in kinds


def test_change_master_password_locks_other_windows(v):
    add(v, title="X", password="x-Pass-1!")
    tok1 = v.headers["X-CyberHub-Session"]
    tok2 = v.post("/api/account/login", json={"username": "syed", "password": PW}).json()["session_token"]
    v.headers["X-CyberHub-Session"] = tok2
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 200
    v.headers["X-CyberHub-Session"] = tok1
    r = v.post("/api/passwords/master-password", json={"current_master_password": "nope",
                                                        "new_master_password": MASTER2})
    assert r.status_code == 401
    r = v.post("/api/passwords/master-password", json={"current_master_password": MASTER,
                                                        "new_master_password": MASTER2, "hint": ""})
    assert r.status_code == 200 and r.json()["status"]["unlocked"] and r.json()["status"]["hint_set"] is False
    assert v.get("/api/passwords/items").json()["total"] == 1
    v.headers["X-CyberHub-Session"] = tok2
    assert v.get("/api/passwords/items").status_code == 423
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 401
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER2}).status_code == 200


def test_device_binding(v):
    add(v, title="Bound", password="bound-Pass-1!")
    v.post("/api/passwords/lock")
    vault = v.app.state.vault
    saved, vault._master, vault.key_error = vault._master, None, "key lost"
    try:
        st = v.get("/api/passwords/status").json()
        assert st["device_bound"] and "recovery key" in st["warning"]
        r = v.post("/api/passwords/unlock", json={"master_password": MASTER})
        assert r.status_code == 503 and "recovery key" in r.json()["detail"]
        assert v.get("/api/passwords/status").json()["failed_unlocks"] == 0           # not a wrong guess
        r = v.post("/api/passwords/unlock", json={"recovery_key": v.recovery_key, "new_master_password": MASTER2})
        assert r.status_code == 200 and r.json()["status"]["device_bound"] is False   # rescued, unbound
    finally:
        vault._master, vault.key_error = saved, None
    v.post("/api/passwords/lock")
    r = v.post("/api/passwords/unlock", json={"master_password": MASTER2})
    assert r.status_code == 200 and r.json()["status"]["device_bound"] is True       # re-bound on unlock


def test_kdf_upgraded_on_unlock(v, monkeypatch):
    v.post("/api/passwords/lock")
    monkeypatch.setenv("CYBERHUB_PV_KDF_N", "2048")
    r = v.post("/api/passwords/unlock", json={"master_password": MASTER})
    assert r.status_code == 200 and r.json()["status"]["kdf"]["n"] == 2048
    v.post("/api/passwords/lock")
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 200


# ====================================================================== items
def test_item_crud_masking_history(v):
    r = add(v, title="GitHub", username="syed", password="gh-Pass-1!", urls=["github.com"], folder="Dev",
            favorite=True, tags=["work", "code"], totp="JBSWY3DPEHPK3PXP",
            fields=[{"name": "Recovery", "value": "abc-def", "hidden": True}, {"name": "Team", "value": "blue"}])
    it = r["item"]
    assert it["urls"] == ["https://github.com"] and it["host"] == "github.com" and it["has_totp"]
    d = v.get(f"/api/passwords/items/{it['id']}").json()["item"]["data"]
    assert d["password"] == pvmod.MASK and d["totp"] == pvmod.MASK
    assert d["fields"][0]["value"] == pvmod.MASK and d["fields"][1]["value"] == "blue"
    full = v.get(f"/api/passwords/items/{it['id']}?reveal=true").json()["item"]["data"]
    assert full["password"] == "gh-Pass-1!" and full["fields"][0]["value"] == "abc-def"
    # sending masked values back keeps them
    r = v.patch(f"/api/passwords/items/{it['id']}", json={"title": "GitHub (work)", "password": pvmod.MASK,
                                                           "fields": d["fields"]})
    assert r.status_code == 200
    full = v.get(f"/api/passwords/items/{it['id']}?reveal=true").json()["item"]["data"]
    assert full["title"] == "GitHub (work)" and full["password"] == "gh-Pass-1!" and full["fields"][0]["value"] == "abc-def"
    assert v.get(f"/api/passwords/items/{it['id']}/history").json()["history"] == []
    for n in range(12):
        assert v.patch(f"/api/passwords/items/{it['id']}", json={"password": f"new-Pass-{n}!"}).status_code == 200
    h = v.get(f"/api/passwords/items/{it['id']}/history").json()["history"]
    assert len(h) == 10 and h[0]["password"] == "new-Pass-10!" and h[-1]["password"] == "new-Pass-1!"
    assert v.patch(f"/api/passwords/items/{it['id']}", json={"type": "note"}).status_code == 422
    assert v.patch(f"/api/passwords/items/{it['id']}", json={"bogus": 1}).status_code == 422
    assert v.patch(f"/api/passwords/items/{it['id']}", json={"password_history": []}).status_code == 422
    assert v.patch(f"/api/passwords/items/{it['id']}", json={"totp": "nope!"}).status_code == 422
    # other types
    card = add(v, "card", title="Meezan Visa", cardholder="SYED", number="4111 1111 1111 1111", exp_month=1,
               exp_year=24, cvv="123")
    assert card["item"]["brand"] == "Visa" and card["item"]["last4"] == "1111" and card["item"]["expired"]
    cd = v.get(f"/api/passwords/items/{card['item']['id']}").json()["item"]["data"]
    assert cd["number"] == "•••• 1111" and cd["cvv"] == pvmod.MASK and cd["exp_year"] == 2024
    assert "Luhn" in add(v, "card", title="Typo", number="4111111111111112")["warnings"][0]
    assert v.post("/api/passwords/items", json={"type": "card", "data": {"title": "x", "number": "12ab"}}).status_code == 422
    assert v.post("/api/passwords/items", json={"type": "card", "data": {"title": "x", "cvv": "12"}}).status_code == 422
    ident = add(v, "identity", title="Me", full_name="Syed Muhammad Tayyab", email="s@example.com",
                national_id="12345-1234567-1")
    assert v.get(f"/api/passwords/items/{ident['item']['id']}").json()["item"]["data"]["national_id"] == pvmod.MASK
    add(v, "note", title="Wi-Fi", notes="home: abc")
    assert v.post("/api/passwords/items", json={"type": "note", "data": {"title": "x", "password": "y"}}).status_code == 422
    assert v.post("/api/passwords/items", json={"type": "login", "data": {}}).status_code == 422
    assert v.post("/api/passwords/items", json={"type": "secret", "data": {"title": "x"}}).status_code == 422
    lst = v.get("/api/passwords/items").json()
    assert lst["total"] == 5 and lst["items"][0]["favorite"]
    assert "password" not in json.dumps(lst["items"][0]).replace("has_password", "").replace("password_changed_at", "")
    assert v.get("/api/passwords/items?type=card").json()["total"] == 2
    assert v.get("/api/passwords/items?q=tayyab").json()["total"] == 1
    assert v.get("/api/passwords/items?folder=Dev").json()["total"] == 1
    assert v.get("/api/passwords/items?favorite=true").json()["total"] == 1
    assert v.get("/api/passwords/items/" + "0" * 32).status_code == 404


def test_trash_restore_and_purge(v):
    a = add(v, title="A", password="a-Pass-1!")["item"]["id"]
    b = add(v, title="B", password="b-Pass-1!")["item"]["id"]
    assert v.delete(f"/api/passwords/items/{a}").json()["permanent"] is False
    assert v.get("/api/passwords/items").json()["total"] == 1
    assert v.get("/api/passwords/items?trash=true").json()["items"][0]["id"] == a
    assert v.patch(f"/api/passwords/items/{a}", json={"title": "Z"}).status_code == 409
    assert v.post(f"/api/passwords/items/{b}/restore").status_code == 409
    assert v.post(f"/api/passwords/items/{a}/restore").status_code == 200
    v.delete(f"/api/passwords/items/{a}")
    assert v.get("/api/passwords/status").json()["trash"] == 1
    assert v.delete("/api/passwords/trash").json()["deleted"] == 1
    v.delete(f"/api/passwords/items/{b}")
    v.app.state.db.execute("UPDATE pv_items SET deleted_at='2020-01-01T00:00:00.000Z' WHERE id=?", (b,))
    assert svc(v).purge_trash() == 1
    assert v.get("/api/passwords/items?trash=true").json()["total"] == 0
    c2 = add(v, title="C", password="c-Pass-1!")["item"]["id"]
    assert v.delete(f"/api/passwords/items/{c2}?permanent=true").json()["permanent"] is True
    assert v.app.state.db.fetchone("SELECT COUNT(*) AS n FROM pv_items")["n"] == 0


def test_totp_copy_and_folders(v):
    it = add(v, title="Google", username="syed@gmail.com", password="g-Pass-1!", totp="JBSWY3DPEHPK3PXP",
             folder="Mail")["item"]
    t = v.get(f"/api/passwords/items/{it['id']}/totp").json()
    assert len(t["code"]) == 6 and 1 <= t["remaining"] <= 30
    assert t["code"] == tools.totp("JBSWY3DPEHPK3PXP")["code"]
    clip = svc(v).clipboard.backend
    r = v.post(f"/api/passwords/items/{it['id']}/copy", json={"field": "password"}).json()
    assert r["copied"] and r["clears_in"] == 30 and clip.text == "g-Pass-1!"
    v.post(f"/api/passwords/items/{it['id']}/copy", json={"field": "username"})
    assert clip.text == "syed@gmail.com" and svc(v).clipboard._pending
    v.post(f"/api/passwords/items/{it['id']}/copy", json={"field": "totp"})
    assert clip.text == t["code"] or len(clip.text) == 6
    assert v.post("/api/passwords/clipboard/clear").json()["cleared"] and clip.text is None
    assert v.post(f"/api/passwords/items/{it['id']}/copy", json={"field": "cvv"}).status_code == 422
    note = add(v, "note", title="N")["item"]
    assert v.get(f"/api/passwords/items/{note['id']}/totp").status_code == 404
    assert v.post(f"/api/passwords/items/{note['id']}/copy", json={"field": "notes"}).status_code == 404
    add(v, title="Outlook", password="o-Pass-1!", folder="Mail")
    f = v.get("/api/passwords/folders").json()["folders"]
    assert {x["name"]: x["count"] for x in f} == {"": 1, "Mail": 2}
    assert v.post("/api/passwords/folders/rename", json={"old": "Mail", "new": "E-mail"}).json()["renamed"] == 2
    assert v.post("/api/passwords/folders/rename", json={"old": "Nope", "new": "x"}).status_code == 404
    assert v.get("/api/passwords/items?folder=E-mail").json()["total"] == 2


def test_no_clipboard_answers_501(env, monkeypatch):
    monkeypatch.setenv("CYBERHUB_CLIPBOARD_BACKEND", "none")
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.post("/api/passwords/setup", json={"master_password": MASTER})
        it = add(cl, title="A", password="a-Pass-1!")["item"]
        assert cl.get("/api/passwords/status").json()["clipboard"]["available"] is False
        assert cl.post(f"/api/passwords/items/{it['id']}/copy").status_code == 501


# ====================================================================== zero knowledge + tampering
def test_database_holds_no_vault_content(v):
    add(v, title="SecretBankTitle", username="hidden.user@example.org", password="Zq9-Unique-Secret!",
        urls=["https://my-private-bank.example"], notes="NoteNeedle")
    add(v, "card", title="CardTitleNeedle", number="5555555555554444", cvv="987")
    v.get("/api/passwords/audit")
    v.post("/api/passwords/lock")
    v.app.state.db.execute("PRAGMA wal_checkpoint(FULL)")
    blob = b""
    for p in v.app.state.settings.data_dir.glob("cyberhub.db*"):
        blob += p.read_bytes()
    for needle in ("SecretBankTitle", "hidden.user", "Zq9-Unique-Secret", "my-private-bank", "NoteNeedle",
                   "CardTitleNeedle", "5555555555554444", MASTER, "Glacier"):
        assert needle.encode() not in blob, needle
    for r in v.app.state.activity.list(limit=500)["items"]:
        assert "SecretBank" not in json.dumps(r)
    logs = "".join(p.read_text(errors="ignore") for p in v.app.state.settings.log_dir.glob("*"))
    assert "Zq9-Unique-Secret" not in logs and MASTER not in logs


def test_tampered_or_swapped_items_are_flagged(v):
    a = add(v, title="A", password="a-Pass-1!")["item"]["id"]
    b = add(v, title="B", password="b-Pass-1!")["item"]["id"]
    db = v.app.state.db
    rb = db.fetchone("SELECT blob FROM pv_items WHERE id=?", (b,))
    db.execute("UPDATE pv_items SET blob=? WHERE id=?", (rb["blob"], a))                # swap b's blob into a
    db.execute("UPDATE pv_items SET type='note' WHERE id=?", (b,))                      # retype b
    v.post("/api/passwords/lock")
    r = v.post("/api/passwords/unlock", json={"master_password": MASTER})
    assert r.status_code == 200 and r.json()["damaged_items"] == 2
    items = {i["id"]: i for i in v.get("/api/passwords/items").json()["items"]}
    assert items[a]["damaged"] and items[b]["damaged"] and items[a]["title"] == "(damaged item)"
    assert v.patch(f"/api/passwords/items/{a}", json={"title": "x"}).status_code == 409
    assert v.post(f"/api/passwords/items/{a}/copy").status_code == 409
    assert v.delete(f"/api/passwords/items/{a}").json()["permanent"] is True
    assert any(e["kind"] == "damaged_items" for e in v.get("/api/passwords/events").json()["items"])
    # a tampered wrapped key just fails like a wrong password - never a crash
    db.execute("UPDATE pv_vaults SET wrapped_pw=?", (base64.b64encode(b"x" * 40).decode(),))
    v.post("/api/passwords/lock")
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 401


def test_each_user_has_a_private_vault(v):
    mine = add(v, title="Mine", password="m-Pass-1!")["item"]["id"]
    switch = other_user(v, "admin2", role="admin")
    switch("them")
    assert v.get("/api/passwords/status").json()["exists"] is False
    assert v.get("/api/passwords/items").status_code == 404
    v.post("/api/passwords/setup", json={"master_password": MASTER2})
    assert v.get("/api/passwords/items").json()["total"] == 0
    assert v.get(f"/api/passwords/items/{mine}").status_code == 404
    assert v.delete(f"/api/passwords/items/{mine}?permanent=true").status_code == 404
    assert v.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 401  # their own vault
    assert v.get("/api/passwords/events").json()["items"][0]["kind"] in ("unlock_failed", "vault_created")
    switch("me")
    assert v.get("/api/passwords/items").json()["total"] == 1
    assert all(e["kind"] != "unlock_failed" for e in v.get("/api/passwords/events").json()["items"])


def test_deleting_vault_and_user_cascade(v):
    add(v, title="A", password="a-Pass-1!")
    r = v.post("/api/passwords/vault/delete", json={"account_password": "wrong"})
    assert r.status_code == 401
    r = v.post("/api/passwords/vault/delete", json={"account_password": PW})
    assert r.status_code == 428
    r = v.post("/api/passwords/vault/delete", json={"account_password": PW, "confirm": True})
    assert r.json() == {"deleted": True, "items": 1}
    assert v.get("/api/passwords/status").json()["exists"] is False and not svc(v)._opens
    # removing a Cyber Hub user removes their vault (foreign keys) and closes it
    switch = other_user(v, "kid")
    switch("them")
    v.post("/api/passwords/setup", json={"master_password": MASTER2})
    add(v, title="Kid's", password="k-Pass-1!")
    kid_id = v.get("/api/account/me").json()["user"]["id"]
    switch("me")
    assert v.delete(f"/api/account/users/{kid_id}").status_code == 200
    db = v.app.state.db
    assert db.fetchone("SELECT COUNT(*) AS n FROM pv_items")["n"] == 0
    assert db.fetchone("SELECT COUNT(*) AS n FROM pv_vaults")["n"] == 0
    assert not [o for o in svc(v)._opens.values() if o.user_id == kid_id]


# ====================================================================== audit + breaches
def test_audit_finds_every_issue(v):
    reused = add(v, title="Shop A", username="syed", password="Shared-Pass-Phrase-9!", urls=["shop-a.pk"])["item"]["id"]
    add(v, title="Shop B", username="syed", password="Shared-Pass-Phrase-9!", urls=["shop-b.pk"])
    weak = add(v, title="Forum", username="syed", password="Lahore@786", urls=["forum.pk"])["item"]["id"]
    insecure = add(v, title="Old site", username="me", password="Unique-Long-Words-Here-1", urls=["http://old.example.com"])["item"]["id"]
    add(v, title="Dup 1", username="ali", password="Dup-One-Strong-Pass-11", urls=["dup.pk"])
    add(v, title="Dup 2", username="ali", password="Dup-Two-Strong-Pass-22", urls=["https://www.dup.pk/login"])
    add(v, title="Empty", username="nopass", urls=["empty.pk"])
    add(v, "card", title="Old card", number="4111111111111111", exp_month=2, exp_year=2023)
    old = add(v, title="Ancient", username="a", password="Ancient-Strong-Pass-33", urls=["ancient.pk"])["item"]["id"]
    o = next(iter(svc(v)._opens.values()))
    o.items[old]["payload"]["password_changed_at"] = "2023-01-01T00:00:00.000Z"
    a = v.get("/api/passwords/audit").json()
    c = a["counts"]
    assert c["reused"] == 2 and c["weak"] == 1 and c["insecure_url"] == 1 and c["duplicate"] == 2
    assert c["empty_password"] == 1 and c["expired_card"] == 1 and c["old"] == 1 and c["breached"] == 0
    assert a["score"] <= 84 and a["grade"] in ("Needs attention", "At risk") and a["unchecked"] == 7
    assert a["reused_groups"][0]["count"] == 2 and reused in a["reused_groups"][0]["item_ids"]
    assert a["issues"][0]["severity"] == "high" and a["strength_distribution"][1] >= 1
    kinds = {(i["item_id"], i["kind"]) for i in a["issues"]}
    assert (weak, "weak") in kinds and (insecure, "insecure_url") in kinds
    assert v.get("/api/passwords/items?issue=reused").json()["total"] == 2
    st = v.get("/api/passwords/status").json()["audit"]
    assert st["score"] == a["score"] and "issues" not in st                            # stored: counts only
    assert v.app.state.db.fetchone("SELECT COUNT(*) AS n FROM pv_scores")["n"] == 1
    v.get("/api/passwords/audit")
    assert v.app.state.db.fetchone("SELECT COUNT(*) AS n FROM pv_scores")["n"] == 1    # throttled
    assert svc(v).health(v.get("/api/account/me").json()["user"]["id"])["score"] == a["score"]


def test_breach_check_job(v):
    fake = FakeHIBP({"Pakistan@123": 120000})
    svc(v).breach.transport = fake
    bad = add(v, title="Gmail", username="syed", password="Pakistan@123")["item"]["id"]
    add(v, title="Twin", username="syed2", password="Pakistan@123")
    good = add(v, title="GitHub", username="syed", password="Unique-Long-Words-Here-1")["item"]["id"]
    assert fake.urls == []                                                                 # manual mode
    job = v.post("/api/passwords/audit/breaches").json()
    assert job["total"] == 2                                                               # 2 unique passwords
    for _ in range(100):
        job = v.get("/api/passwords/audit/breaches").json()
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "done" and job["found"] == 1 and job["items_found"] == 2
    assert len(fake.urls) == 2 and all(len(u.rsplit("/", 1)[-1]) == 5 for u in fake.urls)
    items = {i["id"]: i for i in v.get("/api/passwords/items").json()["items"]}
    assert items[bad]["breached"] == 120000 and items[good]["breached"] == 0
    a = v.get("/api/passwords/audit").json()
    assert a["counts"]["breached"] == 2 and a["score"] <= 49 and a["unchecked"] == 0 and a["breach_checked_at"]
    ev = [e for e in v.get("/api/passwords/events").json()["items"] if e["kind"] == "breach_found"]
    assert len(ev) == 1 and ev[0]["severity"] == "high" and bad in ev[0]["data"]["item_ids"]
    assert "Gmail" not in json.dumps(ev)                                                   # no titles in events
    # changing the password makes the old result stale
    v.patch(f"/api/passwords/items/{bad}", json={"password": "Brand-New-Strong-Pass-5"})
    assert v.get("/api/passwords/items").json()["items"][0]["breached"] in (None, 0)
    # re-check does not raise the same alert twice
    job = v.post("/api/passwords/audit/breaches").json()
    for _ in range(100):
        if v.get("/api/passwords/audit/breaches").json()["state"] != "running":
            break
        time.sleep(0.05)
    assert len([e for e in v.get("/api/passwords/events").json()["items"] if e["kind"] == "breach_found"]) == 1


def test_breach_modes_and_errors(v):
    fake = FakeHIBP({"Pakistan@123": 5})
    svc(v).breach.transport = fake
    v.patch("/api/settings", json={"pv_breach_check": "off"})
    assert v.post("/api/passwords/audit/breaches").status_code == 403
    r = v.post("/api/passwords/check", json={"password": "Pakistan@123", "breach": True}).json()
    assert r["breach"]["checked"] is False and fake.urls == []
    v.patch("/api/settings", json={"pv_breach_check": "auto"})
    it = add(v, title="Auto", password="Pakistan@123")["item"]["id"]
    for _ in range(100):
        if v.get("/api/passwords/audit/breaches").json()["state"] == "done":
            break
        time.sleep(0.05)
    assert len(fake.urls) == 1 and v.get(f"/api/passwords/items/{it}").json()["item"]["breached"] == 5
    v.patch("/api/settings", json={"pv_breach_check": "manual"})
    r = v.post("/api/passwords/check", json={"password": "Pakistan@123", "breach": True,
                                             "user_inputs": ["pakistan"]}).json()
    assert r["breach"] == {"checked": True, "count": 5, "found": True} and r["strength"]["score"] <= 1
    fake.fail = OSError("offline")
    svc(v).breach._cache.clear()
    r = v.post("/api/passwords/check", json={"password": "Other-Unique-Pass-1", "breach": True}).json()
    assert r["breach"]["checked"] is False and "Have I Been Pwned" in r["breach"]["error"]
    job = v.post("/api/passwords/audit/breaches").json()
    for _ in range(100):
        job = v.get("/api/passwords/audit/breaches").json()
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "failed" and job["error"]


def test_generate_and_check_endpoints(c):
    r = c.post("/api/passwords/generate", json={"mode": "password", "length": 24}).json()
    assert len(r["password"]) == 24 and r["strength"]["score"] == 4
    r = c.post("/api/passwords/generate", json={"mode": "passphrase", "words": 4, "separator": " "}).json()
    assert len(r["password"].split(" ")) == 4
    assert c.post("/api/passwords/generate", json={"mode": "pin"}).json()["password"].isdigit()
    assert c.post("/api/passwords/generate", json={"length": 2}).status_code == 422
    r = c.post("/api/passwords/check", json={"password": "syed2026"}).json()
    assert r["strength"]["score"] <= 1 and r["breach"] is None                            # no vault needed


# ====================================================================== import / export
def test_import_csv_dedupe_and_delete_source(v, tmp_path):
    r = v.post("/api/passwords/import", json={"content": CHROME}).json()
    assert r["format"] == "chrome" and r["imported"] == 2 and r["duplicates"] == 0
    r = v.post("/api/passwords/import", json={"content": CHROME}).json()
    assert r["imported"] == 0 and r["duplicates"] == 2
    r = v.post("/api/passwords/import", json={"content": BITWARDEN, "folder": "Imported"}).json()
    assert r["format"] == "bitwarden" and r["imported"] == 2 and r["skipped_count"] == 1
    assert v.get("/api/passwords/items?folder=Imported").json()["total"] == 2
    bad_totp = "name,url,username,password,totp\nX,https://x.pk,me,x-Pass-1!,not-a-secret!\n"
    r = v.post("/api/passwords/import", json={"content": bad_totp}).json()
    assert r["imported"] == 1 and "2FA" in r["notes"][0]["reason"]
    f = tmp_path / "export.csv"
    f.write_text(LASTPASS, encoding="utf-8")
    r = v.post("/api/passwords/import", json={"path": str(f), "delete_source": True}).json()
    assert r["imported"] == 2 and r["source_deleted"] and not f.exists()
    assert v.post("/api/passwords/import", json={"content": "a,b\n1,2\n"}).status_code == 422
    assert v.post("/api/passwords/import", json={"content": CHROME, "path": "x"}).status_code == 422
    assert v.post("/api/passwords/import", json={"path": str(tmp_path / "nope.csv")}).status_code == 404
    assert v.post("/api/passwords/import", json={"content": CHROME, "format": "word"}).status_code == 422
    assert v.get("/api/passwords/items").json()["total"] == 7
    assert any(e["kind"] == "imported" for e in v.get("/api/passwords/events").json()["items"])


def test_export_backup_roundtrip_to_another_vault(v, tmp_path):
    add(v, title="GitHub", username="syed", password="gh-Pass-1!", totp="JBSWY3DPEHPK3PXP")
    it = add(v, title="Hist", username="h", password="old-Pass-1!")["item"]["id"]
    v.patch(f"/api/passwords/items/{it}", json={"password": "new-Pass-2!"})
    add(v, "card", title="Visa", number="4111111111111111", cvv="123")
    r = v.post("/api/passwords/export", json={"format": "csv", "master_password": MASTER})
    assert r.status_code == 428
    r = v.post("/api/passwords/export", json={"format": "csv", "master_password": "wrong", "confirm": True})
    assert r.status_code == 401
    r = v.post("/api/passwords/export", json={"format": "csv", "master_password": MASTER, "confirm": True}).json()
    assert r["count"] == 3 and "gh-Pass-1!" in r["content"] and "CVV: 123" in r["content"]
    assert v.post("/api/passwords/export", json={"format": "chvault", "master_password": MASTER,
                                                 "export_password": "short"}).status_code == 422
    assert v.post("/api/passwords/export", json={"format": "chvault", "master_password": MASTER,
                                                 "export_password": "Pakistan@12345"}).status_code == 422
    r = v.post("/api/passwords/export", json={"format": "chvault", "master_password": MASTER,
                                              "export_password": "Backup Lemon Kettle 2026", "path": str(tmp_path)}).json()
    path = r["path"]
    assert path.endswith(".chvault") and "gh-Pass-1!" not in open(path).read()
    assert v.post("/api/passwords/export", json={"format": "chvault", "master_password": MASTER,
                                                 "export_password": "Backup Lemon Kettle 2026",
                                                 "path": path}).status_code == 409
    kinds = [e["kind"] for e in v.get("/api/passwords/events").json()["items"]]
    assert "exported_plaintext" in kinds and "exported" in kinds
    # restore into a different user's vault
    switch = other_user(v, "laptop2")
    switch("them")
    v.post("/api/passwords/setup", json={"master_password": MASTER2})
    assert v.post("/api/passwords/import", json={"path": path}).status_code == 422          # needs the password
    assert v.post("/api/passwords/import", json={"path": path, "password": "wrong"}).status_code == 401
    r = v.post("/api/passwords/import", json={"path": path, "password": "Backup Lemon Kettle 2026"}).json()
    assert r["format"] == "chvault" and r["imported"] == 3
    items = {i["title"]: i for i in v.get("/api/passwords/items").json()["items"]}
    h = v.get(f"/api/passwords/items/{items['Hist']['id']}/history").json()["history"]
    assert h[0]["password"] == "old-Pass-1!"
    assert v.get(f"/api/passwords/items/{items['GitHub']['id']}/totp").status_code == 200


# ====================================================================== events / graphs / settings / platform
def test_events_ack_summary(v):
    add(v, title="A", password="Lahore@786")
    v.get("/api/passwords/audit")
    v.post("/api/passwords/lock")
    for _ in range(3):
        v.post("/api/passwords/unlock", json={"master_password": "wrong"})
    ev = v.get("/api/passwords/events?unacknowledged=true").json()
    assert ev["unacknowledged"] >= 1 and ev["items"][0]["severity"] == "medium"
    last = ev["last_id"]
    assert v.get(f"/api/passwords/events?after_id={last}").json()["total"] == 0
    assert v.post("/api/passwords/events/ack", json={"ids": [last]}).json()["acknowledged"] == 1
    v.post("/api/passwords/events/ack")
    assert v.get("/api/passwords/status").json()["unread_alerts"] == 0
    s = v.get("/api/passwords/summary?days=7").json()
    assert len(s["per_day"]) == 7 and s["per_day"][-1]["score"] is not None
    assert s["items_by_type"]["login"] == 1 and s["audit"]["counts"]["weak"] == 1
    assert s["events_by_kind"]["unlock_failed"] == 3
    assert v.delete("/api/passwords/events").json()["deleted"] >= 4


def test_settings_guarded_and_validated(v):
    switch = other_user(v)
    switch("them")
    r = v.patch("/api/settings", json={"pv_auto_lock_minutes": 240})
    assert r.status_code == 403
    assert v.patch("/api/settings", json={"pv_breach_check": "auto"}).status_code == 200      # own privacy choice
    switch("me")
    assert v.patch("/api/settings", json={"pv_breach_check": "always"}).status_code == 422
    assert v.patch("/api/settings", json={"pv_clipboard_clear_seconds": 9999}).status_code == 422
    assert v.patch("/api/settings", json={"pv_clipboard_clear_seconds": 10}).status_code == 200
    it = add(v, title="A", password="a-Pass-1!")["item"]
    assert v.post(f"/api/passwords/items/{it['id']}/copy").json()["clears_in"] == 10


def test_requires_token_and_session(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/passwords/status").status_code == 401
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        assert cl.get("/api/passwords/status").status_code == 401
        assert cl.post("/api/passwords/generate").status_code == 401


def test_info_and_earlier_parts_still_answer(v):
    info = v.get("/api/info").json()
    assert info["build_part"] >= 12 and info["progress_percent"] >= 60 and "passwords" in info["available_modules"]
    assert v.get("/api/health").json()["schema_version"] >= 13
    for path in ("/api/system/info", "/api/monitor/overview", "/api/processes?limit=5", "/api/scan/summary",
                 "/api/quarantine", "/api/realtime/status", "/api/rules/status", "/api/firewall/status",
                 "/api/network/status", "/api/posture/status", "/api/account/me"):
        assert v.get(path).status_code == 200, path
    # Part 6 quarantine vault is untouched by the sub-key Part 12 derives from it
    vault = v.app.state.vault
    assert vault.derive_subkey("password-vault-v1") != vault.derive_subkey("other") and vault.available
    assert any(r["category"] == "passwords" for r in v.app.state.activity.list(limit=50)["items"])


def test_migration_from_part11_database_keeps_data(env):
    cfg = Settings()
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for ver, d, sql in MIGRATIONS:
        if ver <= 12:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db.execute("INSERT INTO posture_events(kind, title) VALUES ('baseline', 'kept')")
    assert db.schema_version() == 12
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0]   # 13+ (later parts add more)
        assert cl.app.state.db.fetchone("SELECT title FROM posture_events")["title"] == "kept"
        con = sqlite3.connect(str(cfg.db_path))
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        assert {"pv_vaults", "pv_items", "pv_breach", "pv_events", "pv_scores"} <= tables


def test_shutdown_drops_keys_and_clipboard(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.post("/api/passwords/setup", json={"master_password": MASTER})
        it = add(cl, title="A", password="a-Pass-1!")["item"]
        cl.post(f"/api/passwords/items/{it['id']}/copy")
        pv = cl.app.state.passwords
        o = next(iter(pv._opens.values()))
    assert not pv._opens and o.alive is False and pv.clipboard.backend.text is None
