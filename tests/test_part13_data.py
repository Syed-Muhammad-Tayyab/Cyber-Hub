"""
Cyber Hub Backend - Part 13 tests: Data Protection
Developed by Syed Muhammad Tayyab

Encryption runs for real (scrypt with a low N via CYBERHUB_DP_KDF_N, AES-256-GCM,
Part 6 device key). The privacy cleaner works on a fake home folder
(CYBERHUB_CLEANER_HOME) in both the Linux and the Windows layout. The finder
searches a temp "Documents" folder (CYBERHUB_FINDER_DEFAULT_DIRS).
"""
import io
import os
import sqlite3
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import file_crypto as fc
from cyberhub.services import privacy_cleaner as pc
from cyberhub.services import sensitive_finder as sf
from cyberhub.services import shredder as sh
from cyberhub.services.data_protection import norm

PW = "Cyb3r!Hub#2026"
FILE_PW = "Lantern-Velvet-Orbit-93"
MASTER = "Glacier-Mango-Tunnel-Velvet-42"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
OLD = time.time() - 3 * 86400


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched", "work", "docs", "home"):
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
    monkeypatch.setenv("CYBERHUB_DP_KDF_N", "1024")
    monkeypatch.setenv("CYBERHUB_CLEANER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CYBERHUB_FINDER_DEFAULT_DIRS", str(tmp_path / "docs"))
    monkeypatch.delenv("CYBERHUB_CLEANER_LAYOUT", raising=False)
    return tmp_path


def _login(cl, user="syed"):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        yield cl


def svc(c):
    return c.app.state.data_protection


def done(c, r, ok=(200,)):
    assert r.status_code in ok, r.text
    j = svc(c).wait(r.json()["id"], 60)
    assert j["status"] != "running"
    return c.get(f"/api/data/jobs/{j['id']}").json()


def write(p, data=b"", mtime=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    if mtime:
        os.utime(p, (mtime, mtime))
    return p


def card_number(prefix="453914880343646"):
    for d in "0123456789":
        if sf.luhn(prefix + d):
            return prefix + d


# ====================================================================== file format
@pytest.mark.parametrize("size", [0, 1, fc.CHUNK - 1, fc.CHUNK, fc.CHUNK + 1, int(2.5 * fc.CHUNK)])
def test_chx_roundtrip_sizes(tmp_path, monkeypatch, size):
    monkeypatch.setenv("CYBERHUB_DP_KDF_N", "1024")
    data = os.urandom(size)
    src = write(tmp_path / "report.pdf", data)
    keys = fc.KeySource(fc.MODE_PASSWORD, password=FILE_PW)
    enc = fc.encrypt_file(str(src), str(tmp_path / "x.chx"), keys)
    out = []
    res = fc.decrypt_stream(str(tmp_path / "x.chx"), fc.KeySource(fc.MODE_PASSWORD, password=FILE_PW), out.append)
    assert b"".join(out) == data and res["sha256"] == enc["sha256"] and res["meta"]["name"] == "report.pdf"
    info = fc.inspect(str(tmp_path / "x.chx"))
    assert info["mode"] == "password" and info["needs_password"] and "name" not in info
    assert fc.inspect(str(tmp_path / "x.chx"), keys)["size"] == size
    raw = (tmp_path / "x.chx").read_bytes()
    assert b"report.pdf" not in raw and (size < 64 or data[:64] not in raw)


def test_chx_wrong_key_and_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DP_KDF_N", "1024")
    src = write(tmp_path / "a.bin", os.urandom(3 * fc.CHUNK + 10))
    keys = fc.KeySource(fc.MODE_PASSWORD, password=FILE_PW)
    p = tmp_path / "a.chx"
    fc.encrypt_file(str(src), str(p), keys)
    with pytest.raises(fc.WrongKey, match="Wrong password"):
        fc.decrypt_stream(str(p), fc.KeySource(fc.MODE_PASSWORD, password="nope-nope-nope"))
    with pytest.raises(fc.WrongKey):
        fc.decrypt_stream(str(p), fc.KeySource(fc.MODE_DEVICE, device_key=os.urandom(32)))
    good = p.read_bytes()
    blk = fc.CHUNK + fc.TAG
    start = fc.HEADER_LEN + int.from_bytes(good[52:56], "big")
    for bad in (good[:start + 100] + bytes([good[start + 100] ^ 1]) + good[start + 101:],   # flipped bit
                good[:-10],                                                                    # truncated
                good[:start] + good[start + blk:start + 2 * blk] + good[start:start + blk] + good[start + 2 * blk:],
                good[:start + 3 * blk],                                                        # last chunk dropped
                good[:20] + bytes([good[20] ^ 1]) + good[21:]):                                # header salt edited
        p.write_bytes(bad)
        with pytest.raises(fc.CryptoError):
            fc.decrypt_stream(str(p), keys)
    p.write_bytes(b"PK\x03\x04 not ours")
    with pytest.raises(fc.CryptoError, match="Not a Cyber Hub"):
        fc.inspect(str(p))


def test_chx_keys_per_file_and_scrypt_once(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DP_KDF_N", "1024")
    keys = fc.KeySource(fc.MODE_PASSWORD, password=FILE_PW)
    for n in ("a", "b"):
        fc.encrypt_file(str(write(tmp_path / n, b"same content" * 100)), str(tmp_path / f"{n}.chx"), keys)
    a, b = (tmp_path / "a.chx").read_bytes(), (tmp_path / "b.chx").read_bytes()
    assert a[9:25] == b[9:25] and a[25:41] != b[25:41] and a[fc.HEADER_LEN:] != b[fc.HEADER_LEN:]
    assert len(keys._cache) == 1                                       # one scrypt for the whole job
    keys.wipe()
    assert keys.password is None and not keys._cache


def test_safe_name():
    assert fc.safe_name("../../evil.exe", "x") == "evil.exe"
    assert fc.safe_name("C:\\Users\\a\\doc.txt", "x") == "doc.txt"
    assert fc.safe_name("con.txt", "x") == "_con.txt"
    assert fc.safe_name("", "fallback") == "fallback"
    assert fc.safe_name("a\x00b|c", "fb") == "fb"


# ====================================================================== encrypt / decrypt API
def test_encrypt_then_decrypt_file(c):
    w = c.env / "work"
    data = os.urandom(300_000)
    f = write(w / "salary slip.pdf", data, mtime=OLD)
    j = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))
    assert j["status"] == "done" and j["result"]["summary"]["encrypted"] == 1
    it = j["result"]["items"][0]
    assert it["original"] == "shredded" and not f.exists() and it["output"].endswith("salary slip.pdf.chx")
    assert fc.is_chx(it["output"])
    enc = c.get("/api/data/encrypted").json()["items"]
    assert enc[0]["path"] == it["output"] and enc[0]["exists"] and enc[0]["mode"] == "password"
    j2 = done(c, c.post("/api/data/decrypt", json={"paths": [it["output"]], "password": FILE_PW}))
    assert j2["result"]["summary"]["decrypted"] == 1
    assert f.read_bytes() == data and abs(f.stat().st_mtime - OLD) < 2 and not os.path.exists(it["output"])
    assert c.get("/api/data/encrypted?status=decrypted").json()["total"] == 1
    kinds = {e["kind"] for e in c.get("/api/data/events").json()["items"]}
    assert {"encrypted", "decrypted"} <= kinds
    assert any(a["category"] == "data" for a in c.app.state.activity.list(limit=50)["items"])
    # the password never reaches the database
    raw = (c.env / "data" / "cyberhub.db").read_bytes()
    assert FILE_PW.encode() not in raw


def test_password_rules(c):
    f = write(c.env / "work" / "a.txt", b"x")
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "password": "short"})
    assert r.status_code == 422 and "8 characters" in r.json()["detail"]
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "password": "password1"})
    assert r.status_code == 422 and "allow_weak" in r.json()["detail"]
    assert c.post("/api/data/encrypt", json={"paths": [str(f)]}).status_code == 422
    j = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": "password1", "allow_weak": True,
                                                  "delete_original": "keep"}))
    assert j["result"]["summary"]["encrypted"] == 1 and f.exists()


def test_folder_hidden_names_destination_and_conflicts(c):
    w = c.env / "work" / "Project"
    files = {"a.txt": b"alpha", "sub/b.docx": os.urandom(5000), "sub/deep/c.bin": os.urandom(1_200_000)}
    for k, v in files.items():
        write(w / k, v)
    j = done(c, c.post("/api/data/encrypt", json={"paths": [str(w)], "password": FILE_PW, "hide_names": True,
                                                  "delete_original": "delete"}))
    assert j["result"]["summary"] == {"encrypted": 3, "skipped": 0, "failed": 0, "originals_kept": 0}
    outs = sorted(p.name for p in w.rglob("*") if p.is_file())
    assert len(outs) == 3 and all(n.endswith(".chx") and len(n) == 20 for n in outs)
    assert c.get("/api/data/encrypted").json()["items"][0]["source_path"] is None
    dest = c.env / "work" / "restored"
    dest.mkdir()
    write(dest / "a.txt", b"already here")
    j = done(c, c.post("/api/data/decrypt", json={"paths": [str(w)], "password": FILE_PW, "destination": str(dest),
                                                  "delete_encrypted": False}))
    assert j["result"]["summary"]["decrypted"] == 3
    names = sorted(p.name for p in dest.iterdir())
    assert names == ["a (2).txt", "a.txt", "b.docx", "c.bin"]
    assert (dest / "a (2).txt").read_bytes() == b"alpha" and (dest / "c.bin").read_bytes() == files["sub/deep/c.bin"]
    j = done(c, c.post("/api/data/decrypt", json={"paths": [str(w)], "password": FILE_PW, "destination": str(dest),
                                                  "conflict": "skip"}))
    assert j["result"]["summary"]["skipped"] == 3


def test_device_mode(c):
    f = write(c.env / "work" / "cnic-scan.jpg", os.urandom(4000))
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "mode": "device", "save_to_vault": True})
    assert r.status_code == 422
    j = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "mode": "device"}))
    out = j["result"]["items"][0]["output"]
    info = c.post("/api/data/inspect", json={"path": out}).json()
    assert info["mode"] == "device" and not info["needs_password"] and info["name"] == "cnic-scan.jpg"
    assert c.post("/api/data/verify", json={"path": out}).json()["ok"]
    j = done(c, c.post("/api/data/decrypt", json={"paths": [out]}))
    assert j["result"]["summary"]["decrypted"] == 1 and f.exists()
    assert c.get("/api/data/status").json()["features"]["device_mode"]


def test_wrong_password_and_verify(c):
    f = write(c.env / "work" / "x.txt", b"secret text " * 100)
    out = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))["result"]["items"][0]["output"]
    j = done(c, c.post("/api/data/decrypt", json={"paths": [out], "password": "Wrong-Pass-123!"}))
    assert j["result"]["summary"]["wrong_password"] == 1 and os.path.exists(out) and not f.exists()
    assert any(e["kind"] == "decrypt_failed" for e in c.get("/api/data/events").json()["items"])
    assert c.post("/api/data/verify", json={"path": out, "password": "Wrong-Pass-123!"}).status_code == 401
    assert c.post("/api/data/inspect", json={"path": out, "password": FILE_PW}).json()["name"] == "x.txt"
    raw = bytearray(open(out, "rb").read())
    raw[-5] ^= 0xFF
    open(out, "wb").write(raw)
    v = c.post("/api/data/verify", json={"path": out, "password": FILE_PW}).json()
    assert v["ok"] is False and "integrity" in v["error"]
    j = done(c, c.post("/api/data/decrypt", json={"paths": [out], "password": FILE_PW}))
    assert j["result"]["summary"]["failed"] == 1 and not f.exists()
    assert not [p for p in (c.env / "work").iterdir() if p.name.endswith(".chdec")]


def test_save_password_to_vault(c):
    f = write(c.env / "work" / "bank.xlsx", b"PK...")
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW, "save_to_vault": True})
    assert r.status_code == 404 and f.exists()                                   # no vault yet - nothing touched
    c.post("/api/passwords/setup", json={"master_password": MASTER})
    c.post("/api/passwords/lock")
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW, "save_to_vault": True})
    assert r.status_code == 423 and f.exists() and not os.path.exists(str(f) + ".chx")
    c.post("/api/passwords/unlock", json={"master_password": MASTER})
    done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW, "save_to_vault": True}))
    items = c.get("/api/passwords/items?folder=Encrypted%20files").json()["items"]
    assert len(items) == 1 and "bank.xlsx" in items[0]["title"]
    full = c.get(f"/api/passwords/items/{items[0]['id']}?reveal=true").json()["item"]
    assert full["data"]["password"] == FILE_PW


def test_path_guards(c):
    data = c.env / "data" / "cyberhub.db"
    app_file = os.path.abspath(__file__)
    for p, code in ((str(data), 403), (app_file, 403), (os.path.expanduser("~"), 403), ("/", 403),
                    ("/usr/bin/env", 403), (str(c.env / "nope.txt"), 404), ("", 422)):
        r = c.post("/api/data/encrypt", json={"paths": [p], "password": FILE_PW})
        assert r.status_code == code, (p, r.text)
        r = c.post("/api/data/shred", json={"paths": [p], "confirm": True})
        assert r.status_code == (code if p else 422), (p, r.text)


def test_overlapping_jobs_refused_and_limits(c):
    w = c.env / "work" / "busy"
    write(w / "a.txt", b"a")
    s = svc(c)

    class CU:
        user = {"id": 1, "username": "syed", "role": "admin"}
    j = s._claim("shred", CU(), [norm(str(w))], {})
    r = c.post("/api/data/encrypt", json={"paths": [str(w / "a.txt")], "password": FILE_PW})
    assert r.status_code == 409 and "already working" in r.json()["detail"]
    j2 = s._claim("x", CU(), ["::a"], {})
    j3 = s._claim("x", CU(), ["::b"], {})
    r = c.post("/api/data/encrypt", json={"paths": [str(c.env / "work")], "password": FILE_PW})
    assert r.status_code == 429
    for x in (j, j2, j3):
        x.status = "done"
    assert c.post("/api/data/jobs/nope/cancel").status_code == 404


def test_cancel_keeps_every_file_whole(c):
    w = c.env / "work" / "many"
    originals = {f"f{i}.bin": os.urandom(150_000) for i in range(40)}
    for k, v in originals.items():
        write(w / k, v)
    r = c.post("/api/data/encrypt", json={"paths": [str(w)], "password": FILE_PW})
    c.post(f"/api/data/jobs/{r.json()['id']}/cancel")
    j = done(c, r)
    assert j["status"] in ("cancelled", "done")
    for k, v in originals.items():
        plain, enc = w / k, w / (k + ".chx")
        assert plain.exists() or enc.exists(), k                     # never neither
        if plain.exists():
            assert plain.read_bytes() == v
    assert not [p for p in w.iterdir() if p.suffix in (".chpart", ".shred")]


def test_nothing_to_encrypt_and_running_program(c, monkeypatch):
    f = write(c.env / "work" / "tool.exe", b"MZ" + os.urandom(100))
    s = svc(c)
    monkeypatch.setattr(s, "_running_exes", lambda: {norm(str(f))})
    j = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))
    assert j["result"]["summary"]["skipped"] == 1 and f.exists()
    monkeypatch.setattr(s, "_running_exes", lambda: set())
    out = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))["result"]["items"][0]["output"]
    j = done(c, c.post("/api/data/encrypt", json={"paths": [out], "password": FILE_PW}))
    assert j["status"] == "failed" and "already encrypted" in j["error"]
    assert any(e["kind"] == "job_failed" for e in c.get("/api/data/events").json()["items"])


def test_decrypted_threat_is_scanned(c):
    f = write(c.env / "work" / "eicar.com", EICAR)
    out = done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))["result"]["items"][0]["output"]
    j = done(c, c.post("/api/data/decrypt", json={"paths": [out], "password": FILE_PW}))
    assert j["result"]["summary"]["threats"] == 1 and j["result"]["items"][0]["threats"]
    assert any(e["kind"] == "decrypted_threat" and e["severity"] == "high"
               for e in c.get("/api/data/events").json()["items"])


def test_realtime_is_told_about_our_writes(c):
    rt = c.app.state.realtime
    c.app.state.settings_store.update({"rtp_burst_threshold": 5})
    w = c.env / "watched"
    files = [write(w / f"doc{i}.txt", b"x" * 100) for i in range(8)]
    done(c, c.post("/api/data/encrypt", json={"paths": [str(w)], "password": FILE_PW}))
    for f in files:
        assert rt._suppression(str(f)) is False and rt._suppression(str(f) + ".chx") is False
    assert rt._ignored(str(w / "x.chx.chpart")) and rt._ignored(str(w / "abc.shred"))
    before = len(rt._bursts.get(str(w), []))
    for f in files:
        rt._on_fs_event(str(f) + ".chx", "created", str(w), "folder", False)
    assert len(rt._bursts.get(str(w), [])) == before and not rt._pending
    rt._on_fs_event(str(w / "stranger.exe"), "created", str(w), "folder", False)
    assert len(rt._bursts.get(str(w), [])) == before + 1 and rt._pending          # normal events still count
    done(c, c.post("/api/data/decrypt", json={"paths": [str(w)], "password": FILE_PW}))
    assert rt._suppression(str(files[0])) is True                                  # decrypted = still scanned


def test_interrupted_job_recovery(env):
    tmpfile = write(env / "work" / "x.txt.chx.chpart", b"half")
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.app.state.db.execute("INSERT INTO dp_jobs(id, kind, status, created_at, temp) VALUES "
                                "('abc', 'encrypt', 'running', '2026-01-01T00:00:00Z', ?)", (str(tmpfile),))
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        r = cl.app.state.db.fetchone("SELECT status, error FROM dp_jobs WHERE id='abc'")
        assert r["status"] == "interrupted" and "untouched" in r["error"] and not tmpfile.exists()


# ====================================================================== shredder
def test_shred_file_overwrites_before_delete(tmp_path):
    f = write(tmp_path / "secret.txt", b"TOP-SECRET" * 300_000)
    calls = []

    def stop(n):
        calls.append(n)
        if len(calls) == 1:
            raise RuntimeError("stop after first block")
    with pytest.raises(RuntimeError):
        sh.shred_file(str(f), "zero", checkpoint=stop)
    data = f.read_bytes()
    assert data[:sh.BLOCK] == b"\x00" * sh.BLOCK and b"TOP-SECRET" in data[sh.BLOCK:]   # really overwritten in place
    r = sh.shred_file(str(f), "dod3", verify=True)
    assert r == {"result": "shredded", "bytes": 3_000_000, "passes": 3, "verified": True}
    assert not list(tmp_path.iterdir())
    with pytest.raises(sh.ShredError) as e:
        sh.shred_file(str(f))
    assert e.value.code == "missing"
    assert sh.media_type(str(tmp_path)) in ("ssd", "hdd", "unknown")


def test_shred_links_and_hardlinks(tmp_path):
    outside = write(tmp_path / "outside" / "keep.txt", b"keep me")
    d = tmp_path / "victim"
    write(d / "a.txt", b"a")
    os.symlink(outside, d / "link.txt")
    os.symlink(tmp_path / "outside", d / "dirlink")
    os.link(d / "a.txt", tmp_path / "hard.txt")
    with pytest.raises(sh.ShredError) as e:
        sh.shred_file(str(d / "a.txt"))
    assert e.value.code == "hardlinked"
    assert sh.shred_file(str(d / "link.txt"))["result"] == "link_removed"
    assert outside.read_bytes() == b"keep me"
    kinds = [k for k, _, _ in sh.iter_tree(str(d))]
    assert kinds.count("link") == 1 and kinds[-1] == "dir"


def test_shred_api(c):
    w = c.env / "work" / "old-cv"
    write(w / "cv.docx", os.urandom(20000))
    write(w / "photos" / "p1.jpg", os.urandom(30000))
    outside = write(c.env / "work" / "outside.txt", b"stay")
    os.symlink(outside, w / "photos" / "ln")
    p = c.post("/api/data/shred/preview", json={"paths": [str(w)]}).json()
    assert p["files"] == 2 and p["links"] == 1 and p["bytes"] == 50000 and p["irreversible"] and p["method"] == "random"
    r = c.post("/api/data/shred", json={"paths": [str(w)]})
    assert r.status_code == 428 and "confirm" in r.json()["detail"]
    assert c.post("/api/data/shred", json={"paths": [str(w)], "method": "bogus", "confirm": True}).status_code == 422
    j = done(c, c.post("/api/data/shred", json={"paths": [str(w)], "confirm": True, "method": "dod3"}))
    s = j["result"]["summary"]
    assert s["shredded"] == 2 and s["links_removed"] == 1 and s["folders_removed"] == 2 and not w.exists()
    assert outside.read_bytes() == b"stay" and all(i["verified"] for i in j["result"]["items"])
    sm = c.get("/api/data/summary?days=7").json()
    assert sm["per_day"][-1]["shredded_files"] == 2 and sm["per_day"][-1]["shredded_bytes"] == 50000
    hl = write(c.env / "work" / "h1.txt", b"h")
    os.link(hl, c.env / "work" / "h2.txt")
    j = done(c, c.post("/api/data/shred", json={"paths": [str(hl)], "confirm": True}))
    assert j["result"]["summary"]["skipped"] == 1 and hl.exists()
    j = done(c, c.post("/api/data/shred", json={"paths": [str(hl)], "confirm": True, "allow_hardlinks": True}))
    assert j["result"]["summary"]["shredded"] == 1 and not hl.exists()


# ====================================================================== privacy cleaner
def _firefox_places(path):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                                 last_visit_date INTEGER, foreign_count INTEGER DEFAULT 0);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
        CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, fk INTEGER);
        CREATE TABLE moz_inputhistory (place_id INTEGER, input TEXT);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER);
        INSERT INTO moz_places VALUES (1, 'https://bank.example/', 'Bank', 5, 1, 1);
        INSERT INTO moz_places VALUES (2, 'https://secret.example/', 'Secret', 9, 1, 0);
        INSERT INTO moz_bookmarks VALUES (1, 1);
        INSERT INTO moz_historyvisits VALUES (1, 1, 1), (2, 2, 1), (3, 2, 2);
        INSERT INTO moz_inputhistory VALUES (2, 'sec');
        INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
        INSERT INTO moz_annos VALUES (1, 2, 1);
    """)
    con.commit()
    con.close()


def make_linux_home(h):
    write(h / "tmp" / "old-installer.tmp", b"o" * 1000, mtime=OLD)
    write(h / "tmp" / "deep" / "old2.log", b"o" * 500, mtime=OLD)
    os.utime(h / "tmp" / "deep", (OLD, OLD))
    write(h / "tmp" / "running-now.tmp", b"n" * 700)
    write(h / ".local" / "share" / "Trash" / "files" / "deleted.doc", b"d" * 300)
    write(h / ".local" / "share" / "Trash" / "info" / "deleted.doc.trashinfo", b"[Trash Info]")
    write(h / ".cache" / "thumbnails" / "large" / "t.png", b"t" * 200)
    write(h / ".local" / "share" / "recently-used.xbel", b"<xbel/>")
    prof = h / ".config" / "google-chrome" / "Default"
    write(prof / "Preferences", b"{}")
    write(prof / "Cache" / "Cache_Data" / "f_000001", b"c" * 4000)
    write(prof / "Code Cache" / "js" / "x", b"c" * 1000)
    write(prof / "History", b"h" * 100)
    write(prof / "Bookmarks", b"{keep}")
    write(prof / "Network" / "Cookies", b"k" * 50)
    write(h / ".cache" / "google-chrome" / "Default" / "Cache" / "y", b"c" * 2000)
    ff = h / ".mozilla" / "firefox"
    write(ff / "profiles.ini", b"[Profile0]\nName=default\nIsRelative=1\nPath=abc.default-release\n")
    write(ff / "abc.default-release" / "prefs.js", b"// prefs")
    _firefox_places(ff / "abc.default-release" / "places.sqlite")
    write(ff / "abc.default-release" / "cookies.sqlite", b"cookies")
    write(h / ".cache" / "mozilla" / "firefox" / "abc.default-release" / "cache2" / "entries" / "e1", b"e" * 3000)


def test_cleaner_analyze_and_clean_linux(c):
    h = c.env / "home"
    make_linux_home(h)
    outside = write(c.env / "work" / "important.txt", b"never touch")
    os.symlink(outside, h / "tmp" / "evil-link")
    os.utime(h / "tmp" / "evil-link", (OLD, OLD), follow_symlinks=False)
    svc(c).cleaner.process_names = lambda: set()
    j = done(c, c.post("/api/data/cleaner/analyze"))
    rep = c.get("/api/data/cleaner/report").json()
    cats = {x["id"]: x for x in rep["categories"]}
    assert j["status"] == "done" and rep["ts"]
    assert {"temp", "recycle_bin", "thumbnails", "recent", "chrome_cache", "chrome_history", "chrome_cookies",
            "firefox_cache", "firefox_history", "firefox_cookies"} <= set(cats)
    assert cats["temp"]["files"] == 3 and cats["temp"]["bytes"] == 1500           # young file + link size excluded
    assert cats["chrome_cache"]["bytes"] == 7000 and cats["chrome_cookies"]["needs_confirm"]
    assert cats["firefox_cache"]["bytes"] == 3000 and cats["chrome_cache"]["profiles"] == ["Default"]
    r = c.post("/api/data/cleaner/clean", json={"categories": ["temp", "chrome_cookies"]})
    assert r.status_code == 428 and "Signs you out" in r.json()["detail"]
    assert c.post("/api/data/cleaner/clean", json={"categories": ["nope"]}).status_code == 422
    j = done(c, c.post("/api/data/cleaner/clean", json={"categories": ["temp", "chrome_cache", "chrome_history",
                                                                       "chrome_cookies", "firefox_cache",
                                                                       "firefox_history", "thumbnails", "recent"],
                                                        "confirm": True}))
    res = {x["id"]: x for x in j["result"]["categories"]}
    assert all(x["status"] == "done" for x in res.values()), res
    assert (h / "tmp" / "running-now.tmp").exists() and not (h / "tmp" / "old-installer.tmp").exists()
    assert not (h / "tmp" / "deep").exists() and not os.path.lexists(h / "tmp" / "evil-link")
    assert outside.read_bytes() == b"never touch"
    prof = h / ".config" / "google-chrome" / "Default"
    assert (prof / "Cache").is_dir() and not list((prof / "Cache").rglob("f_*")) and (prof / "Bookmarks").exists()
    assert not (prof / "History").exists() and not (prof / "Network" / "Cookies").exists()
    assert (prof / "Preferences").exists() and not (h / ".local" / "share" / "recently-used.xbel").exists()
    con = sqlite3.connect(h / ".mozilla" / "firefox" / "abc.default-release" / "places.sqlite")
    assert con.execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone()[0] == 0
    assert [r[0] for r in con.execute("SELECT url FROM moz_places")] == ["https://bank.example/"]     # bookmark kept
    assert con.execute("SELECT COUNT(*) FROM moz_annos").fetchone()[0] == 0
    con.close()
    assert (h / ".mozilla" / "firefox" / "abc.default-release" / "cookies.sqlite").exists()
    rep = c.get("/api/data/cleaner/report").json()
    assert {x["id"]: x for x in rep["categories"]}["temp"]["bytes"] == 0
    assert any(e["kind"] == "cleaned" for e in c.get("/api/data/events").json()["items"])
    assert any(a["category"] == "privacy" for a in c.app.state.activity.list(limit=50)["items"])


def test_cleaner_skips_running_browser(c):
    h = c.env / "home"
    make_linux_home(h)
    svc(c).cleaner.process_names = lambda: {"chrome", "python"}
    j = done(c, c.post("/api/data/cleaner/analyze"))
    cats = {x["id"]: x for x in j["result"]["categories"]}
    assert cats["chrome_cache"]["browser_running"] and "Close Google Chrome" in cats["chrome_cache"]["note"]
    assert not cats["firefox_cache"]["browser_running"]
    j = done(c, c.post("/api/data/cleaner/clean", json={"categories": ["chrome_cache", "firefox_cache"]}))
    res = {x["id"]: x for x in j["result"]["categories"]}
    assert res["chrome_cache"]["status"] == "skipped" and res["firefox_cache"]["status"] == "done"
    assert (h / ".config" / "google-chrome" / "Default" / "Cache" / "Cache_Data" / "f_000001").exists()


def test_cleaner_windows_layout(env, monkeypatch):
    monkeypatch.setenv("CYBERHUB_CLEANER_LAYOUT", "windows")
    h = env / "home"
    local, roaming = h / "AppData" / "Local", h / "AppData" / "Roaming"
    write(local / "Temp" / "setup.tmp", b"x" * 100, mtime=OLD)
    write(roaming / "Microsoft" / "Windows" / "Recent" / "salary.xlsx.lnk", b"l")
    write(roaming / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations" / "a.automaticDestinations-ms", b"a")
    write(local / "Microsoft" / "Windows" / "Explorer" / "thumbcache_256.db", b"t" * 10)
    write(local / "Microsoft" / "Windows" / "Explorer" / "other.db", b"keep")
    write(local / "CrashDumps" / "app.exe.123.dmp", b"d" * 50)
    write(local / "Microsoft" / "Edge" / "User Data" / "Default" / "Preferences", b"{}")
    write(local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache" / "Cache_Data" / "data_1", b"c" * 64)
    write(local / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "Preferences", b"{}")
    write(local / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "History", b"h")
    write(h / "RecycleBin" / "$R123.docx", b"r" * 5)
    cl = pc.PrivacyCleaner(process_names=lambda: set())
    cats = {x["id"]: x for x in cl.analyze(24)}
    assert {"temp", "recycle_bin", "thumbnails", "recent", "error_reports", "dns_cache", "edge_cache",
            "edge_history", "edge_cookies"} <= set(cats)
    assert cats["recent"]["files"] == 2 and cats["thumbnails"]["files"] == 1 and cats["error_reports"]["bytes"] == 50
    assert cats["edge_history"]["profiles"] == ["Default", "Profile 1"] and cats["dns_cache"]["action_only"]
    res = {x["id"]: x for x in cl.clean(["recent", "thumbnails", "edge_history", "recycle_bin"], 24)}
    assert res["recent"]["files"] == 2 and res["thumbnails"]["files"] == 1 and res["recycle_bin"]["files"] == 1
    assert (local / "Microsoft" / "Windows" / "Explorer" / "other.db").exists()
    assert not (local / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "History").exists()


def test_cleaner_never_leaves_its_root_or_touches_own_folders(tmp_path):
    root = tmp_path / "Temp"
    own = write(root / "CyberHubData" / "cyberhub.db", b"db", mtime=OLD)
    write(root / "junk.tmp", b"j", mtime=OLD)
    t = pc.Target(str(root), contents=True)
    cl = pc.PrivacyCleaner(exclude=[str(root / "CyberHubData")])
    assert [os.path.basename(p) for p, _, _ in cl._files(t)] == ["junk.tmp"]
    assert list(pc.iter_target_files(pc.Target(str(tmp_path / "missing"), contents=True))) == []
    assert own.exists()


# ====================================================================== sensitive-file finder
def _docx(path, text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", f"<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p>"
                                        "</w:body></w:document>")
    write(path, buf.getvalue())


def make_docs(d):
    card = card_number()
    write(d / "cards.txt", f"My card: {card[:4]} {card[4:8]} {card[8:12]} {card[12:]}\nexp 09/29")
    _docx(d / "family" / "cnic list.docx", "Abbu CNIC 35202-1234567-1 and Ammi 61101-7654321-2")
    write(d / "keys" / "id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n")
    write(d / "chrome passwords.csv", "name,url,username,password\nfb,https://facebook.com,syed,Lahore@786\n")
    write(d / "project" / ".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=${DB_PASS}\n")
    write(d / "notes.md", "wifi password: Sunflower2024\nIBAN PK36SCBL0000001123456702\n")
    write(d / "clean.txt", "Nothing to see here. Order #1234 5678 9012 3456 shipped.")
    write(d / "test-cards.txt", "Stripe test card 4242 4242 4242 4242")
    write(d / "photo.jpg", os.urandom(5000))
    return card


def test_finder_finds_and_masks(c):
    d = c.env / "docs"
    card = make_docs(d)
    j = done(c, c.post("/api/data/finder/scan", json={}))
    assert j["status"] == "done" and j["result"]["stats"]["with_findings"] == 7
    items = {i["name"]: i for i in c.get("/api/data/finder/findings").json()["items"]}
    assert set(items) == {"cards.txt", "cnic list.docx", "id_rsa", "chrome passwords.csv", ".env", "notes.md",
                          "test-cards.txt"}
    t = lambda n: {x["type"]: x for x in items[n]["types"]}
    assert t("cards.txt")["credit_card"]["samples"] == [f"Visa •••• •••• •••• {card[-4:]}"]
    assert t("cnic list.docx")["cnic"]["count"] == 2 and t("cnic list.docx")["cnic"]["samples"][0] == "35•••-•••••••-1"
    assert items["id_rsa"]["severity"] == "critical" and items["chrome passwords.csv"]["severity"] == "critical"
    assert "password" not in t("chrome passwords.csv")                       # one finding, not two
    assert t(".env")["api_key"]["kinds"] == ["AWS access key"] and "password" not in t(".env")
    assert set(t("notes.md")) == {"password", "iban"} and t("notes.md")["iban"]["samples"] == ["PK36 •••• •••• 6702"]
    assert items["test-cards.txt"]["severity"] == "low"
    assert items["cards.txt"]["actions"] == ["encrypt", "shred", "ignore"] and t("cards.txt")["credit_card"]["advice"]
    raw = (c.env / "data" / "cyberhub.db").read_bytes()
    for secret in (card, "1234567", "Sunflower2024", "Lahore@786", "AKIAIOSFODNN7EXAMPLE", "0000001123456702"):
        assert secret.encode() not in raw, secret
    h = c.get("/api/data/health").json()
    assert h["score"] <= 49 and h["by_severity"]["critical"] == 2 and h["searched"]
    assert any(e["kind"] == "sensitive_found" and e["severity"] == "high" for e in c.get("/api/data/events").json()["items"])
    assert c.get("/api/data/finder/findings?severity=critical").json()["total"] == 2
    assert c.get("/api/data/finder/findings?type=cnic").json()["total"] == 1
    assert c.get("/api/data/finder/findings?q=cnic%20list").json()["total"] == 1
    sm = c.get("/api/data/summary").json()
    assert {x["type"] for x in sm["findings_by_type"]} >= {"credit_card", "cnic", "private_key", "api_key"}
    assert sm["score_history"] and sm["findings_by_severity"]["critical"] == 2


def test_finder_lifecycle_ignore_change_remove(c):
    d = c.env / "docs"
    make_docs(d)
    done(c, c.post("/api/data/finder/scan", json={}))
    items = {i["name"]: i for i in c.get("/api/data/finder/findings").json()["items"]}
    fid = items["notes.md"]["id"]
    assert c.post(f"/api/data/finder/findings/{fid}/ignore", json={"note": "my own wifi"}).json()["status"] == "ignored"
    assert c.post(f"/api/data/finder/findings/{fid}/ignore", json={}).status_code == 409
    done(c, c.post("/api/data/finder/scan", json={}))
    assert c.get(f"/api/data/finder/findings/{fid}").json()["status"] == "ignored"
    write(d / "notes.md", "wifi password: Sunflower2025!\n")
    done(c, c.post("/api/data/finder/scan", json={}))
    assert c.get(f"/api/data/finder/findings/{fid}").json()["status"] == "open"            # changed -> back
    (d / "cards.txt").unlink()
    write(d / "test-cards.txt", "no numbers any more")
    done(c, c.post("/api/data/finder/scan", json={}))
    st = {i["name"]: i for i in c.get("/api/data/finder/findings?status=resolved").json()["items"]}
    assert st["cards.txt"]["note"] == "File removed" and "No longer" in st["test-cards.txt"]["note"]
    assert c.post(f"/api/data/finder/findings/{fid}/unignore").status_code == 409


def test_finding_actions_encrypt_and_shred(c):
    d = c.env / "docs"
    make_docs(d)
    done(c, c.post("/api/data/finder/scan", json={}))
    before = c.get("/api/data/health").json()["score"]
    items = {i["name"]: i for i in c.get("/api/data/finder/findings").json()["items"]}
    j = done(c, c.post(f"/api/data/finder/findings/{items['id_rsa']['id']}/encrypt", json={"password": FILE_PW}))
    assert j["result"]["summary"]["encrypted"] == 1
    assert c.get(f"/api/data/finder/findings/{items['id_rsa']['id']}").json()["status"] == "encrypted"
    fid = items["chrome passwords.csv"]["id"]
    assert c.post(f"/api/data/finder/findings/{fid}/shred", json={}).status_code == 428
    done(c, c.post(f"/api/data/finder/findings/{fid}/shred", json={"confirm": True}))
    assert c.get(f"/api/data/finder/findings/{fid}").json()["status"] == "shredded"
    assert not (d / "chrome passwords.csv").exists()
    after = c.get("/api/data/health").json()
    assert after["by_severity"]["critical"] == 0 and after["score"] > before
    assert c.post(f"/api/data/finder/findings/{fid}/shred", json={"confirm": True}).status_code == 409
    done(c, c.post("/api/data/finder/scan", json={}))                                       # .chx never re-flagged
    assert all(not i["name"].endswith(".chx") for i in c.get("/api/data/finder/findings?status=all").json()["items"])


def test_finder_settings_and_custom_paths(c):
    extra = c.env / "work" / "uni"
    write(extra / "fees.txt", "CNIC 37405-1111111-3")
    r = c.patch("/api/settings", json={"dp_finder_paths": [str(extra)], "dp_finder_default_folders": False})
    assert r.status_code == 200
    roots = c.get("/api/data/finder/roots").json()["roots"]
    assert [x["path"] for x in roots] == [str(extra)]
    j = done(c, c.post("/api/data/finder/scan", json={}))
    assert j["result"]["stats"]["with_findings"] == 1
    assert c.post("/api/data/finder/scan", json={"types": ["nope"]}).status_code == 422
    j = done(c, c.post("/api/data/finder/scan", json={"paths": [str(extra)], "types": ["credit_card"]}))
    assert j["result"]["stats"]["with_findings"] == 0
    assert c.patch("/api/settings", json={"dp_finder_types": ["cnic", "bogus"]}).status_code == 422
    assert c.patch("/api/settings", json={"dp_shred_method": "gutmann"}).status_code == 422
    assert c.patch("/api/settings", json={"dp_cleaner_temp_min_age_hours": 9999}).status_code == 422


def test_detectors_avoid_false_positives():
    T = set(sf.DETECTORS)
    assert sf.analyze_text("password: ****\npassword = ${DB_PASS}\npwd=None\npassword: <password>", T) == {}
    assert sf.analyze_text("Invoice 1234 5678 9012 3456 and phone 0300 1234567", T) == {}
    assert sf.analyze_text("IBAN PK36SCBL0000001123456701", T) == {}                     # bad checksum
    assert sf.analyze_text("id 35202-1234567-1-9 or 85202-1234567-1", T) == {}
    assert "ssn" in sf.analyze_text("SSN: 123-45-6789", T) and sf.analyze_text("call 123-45-6789", T) == {}
    many = "\n".join(f"student{i}@fuuast.edu.pk 0300-12345{i:02d}" for i in range(12))
    f = sf.analyze_text(many, T)
    assert set(f) == {"contacts"} and f["contacts"]["samples"] == ["12 e-mail addresses", "12 mobile numbers"]
    f = sf.analyze_text("token ghp_" + "a" * 36 + " and sk_live_" + "b" * 24, T)
    assert f["api_key"]["severity"] == "critical" and set(f["api_key"]["kinds"]) == {"GitHub token", "Stripe live key"}
    assert sf.mask_card("4111111111111111") == "•••• •••• •••• 1111"


def test_finder_extraction_formats(tmp_path):
    T = set(sf.DETECTORS)
    pdf = (b"%PDF-1.4\n1 0 obj <<>> stream\nBT (CNIC: 35202-1234567-1) Tj ET\nendstream\n%%EOF")
    import zlib
    pdfz = b"%PDF-1.4\n2 0 obj <</Filter /FlateDecode>> stream\n" + zlib.compress(b"BT (Card 4111 1111 1111 1111) Tj ET") \
           + b"\nendstream\n%%EOF"
    write(tmp_path / "a.pdf", pdf)
    write(tmp_path / "b.pdf", pdfz)
    write(tmp_path / "c.txt", "password: Hunter2xyz".encode("utf-16"))
    write(tmp_path / "wallet.dat", os.urandom(100))
    write(tmp_path / "cert.pfx", os.urandom(100))
    write(tmp_path / "bin", b"\x00\x01" * 100)
    assert "cnic" in sf.analyze_file(str(tmp_path / "a.pdf"), T, 10**6)[0]
    assert "credit_card" in sf.analyze_file(str(tmp_path / "b.pdf"), T, 10**6)[0]
    assert "password" in sf.analyze_file(str(tmp_path / "c.txt"), T, 10**6)[0]
    assert sf.analyze_file(str(tmp_path / "wallet.dat"), T, 10**6)[0]["crypto_wallet"]["severity"] == "high"
    assert "private_key" in sf.analyze_file(str(tmp_path / "cert.pfx"), T, 10**6)[0]
    assert sf.analyze_file(str(tmp_path / "bin"), T, 10**6)[0] == {}
    assert not sf.candidate("x.chx") and not sf.candidate("movie.mp4") and sf.candidate("x.docx")
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", b"0" * (70 * 1024 * 1024))
    write(tmp_path / "bomb.docx", bomb.getvalue())
    assert sf.analyze_file(str(tmp_path / "bomb.docx"), T, 10**8)[0] == {}               # skipped, not expanded


# ====================================================================== dashboard / jobs / events / integration
def test_status_jobs_events_and_stream(c):
    st = c.get("/api/data/status").json()
    assert st["features"]["encryption"] and st["shredder"]["method"] == "random" and "dod3" in st["shredder"]["methods"]
    assert [t["id"] for t in st["finder"]["types"]][:2] == ["private_key", "password_export"]
    assert st["health"]["score"] == 100 and not st["health"]["searched"]
    f = write(c.env / "work" / "s.txt", b"x")
    r = c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW})
    with c.websocket_connect(f"/api/data/stream?token={c.headers['X-CyberHub-Token']}"
                             f"&session={c.headers['X-CyberHub-Session']}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "data" and "jobs" in msg
    done(c, r)
    jobs = c.get("/api/data/jobs").json()
    assert jobs["history"][0]["kind"] == "encrypt" and jobs["history"][0]["status"] == "done"
    assert c.get("/api/data/jobs?kind=shred").json()["history"] == []
    ev = c.get("/api/data/events").json()
    assert ev["unacknowledged"] >= 1
    assert c.post("/api/data/events/ack", json={}).json()["acknowledged"] >= 1
    assert c.get("/api/data/events?unacknowledged=true").json()["items"] == []
    assert c.delete("/api/data/events").json()["deleted"] >= 1
    with pytest.raises(Exception):
        with c.websocket_connect("/api/data/stream?token=bad&session=x") as ws:
            ws.receive_json()
    del c.headers["X-CyberHub-Session"]
    assert c.get("/api/data/status").status_code == 401


def test_other_users_cannot_see_my_jobs_or_findings(c):
    d = c.env / "docs"
    make_docs(d)
    job = done(c, c.post("/api/data/finder/scan", json={}))
    r = c.post("/api/account/users", json={"username": "guest", "display_name": "Guest", "password": "Gu3st!Pass#2026",
                                           "role": "standard"})
    assert r.status_code == 201, r.text
    c2 = TestClient(c.app)                                            # same running app, second user
    if True:
        c2.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
        c2.headers["X-CyberHub-Session"] = c2.post("/api/account/login", json={
            "username": "guest", "password": "Gu3st!Pass#2026"}).json()["session_token"]
        assert c2.get("/api/data/finder/findings").json()["total"] == 0
        assert c2.get(f"/api/data/jobs/{job['id']}").status_code == 404
        fid = c.get("/api/data/finder/findings").json()["items"][0]["id"]
        assert c2.post(f"/api/data/finder/findings/{fid}/ignore", json={}).status_code == 404


def test_earlier_parts_still_work_and_info(c):
    f = write(c.env / "work" / "a.txt", b"x")
    done(c, c.post("/api/data/encrypt", json={"paths": [str(f)], "password": FILE_PW}))
    for path in ("/api/firewall/status", "/api/network/status", "/api/posture/status", "/api/passwords/status",
                 "/api/realtime/status", "/api/quarantine", "/api/scan/jobs", "/api/account/me", "/api/rules/status"):
        assert c.get(path).status_code == 200, path
    info = c.get("/api/info").json()
    assert "data" in info["available_modules"] and info["progress_percent"] >= 65 and info["build_part"] >= 13
    assert c.app.state.vault.available and c.get("/api/quarantine/stats").status_code == 200


def test_migration_from_part12_database_keeps_data(env):
    cfg = Settings()
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for ver, d, sql in MIGRATIONS:
        if ver <= 13:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db.execute("INSERT INTO posture_events(kind, title) VALUES ('baseline', 'kept')")
    assert db.schema_version() == 13
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 14   # later parts add more
        assert cl.app.state.db.fetchone("SELECT title FROM posture_events")["title"] == "kept"
        tables = {r["name"] for r in cl.app.state.db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"dp_jobs", "dp_encrypted", "dp_findings", "dp_events", "dp_daily", "dp_scores", "dp_state"} <= tables


def test_shutdown_cancels_running_jobs(env):
    w = env / "work" / "big"
    for i in range(30):
        write(w / f"f{i}.bin", os.urandom(200_000))
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        r = cl.post("/api/data/encrypt", json={"paths": [str(w)], "password": FILE_PW})
        jid = r.json()["id"]
        dp = cl.app.state.data_protection
    j = dp._jobs[jid]
    assert j.status in ("cancelled", "done") and j.thread is not None and not j.thread.is_alive()
    for i in range(30):
        assert (w / f"f{i}.bin").exists() or (w / f"f{i}.bin.chx").exists()


def test_encrypting_from_the_panel_also_closes_the_finding(c):
    d = c.env / "docs"
    write(d / "notes.txt", "CNIC 35202-1234567-1\npassword: Sunflower2024\n")
    write(d / "old.csv", "name,url,username,password\nx,https://x.pk,me,Lahore@786\n")
    done(c, c.post("/api/data/finder/scan", json={}))
    assert c.get("/api/data/health").json()["open_findings"] == 2
    done(c, c.post("/api/data/encrypt", json={"paths": [str(d / "notes.txt")], "password": FILE_PW}))
    done(c, c.post("/api/data/shred", json={"paths": [str(d)], "confirm": True}))              # whole folder
    st = {i["name"]: i["status"] for i in c.get("/api/data/finder/findings?status=all").json()["items"]}
    assert st == {"notes.txt": "encrypted", "old.csv": "shredded"}
    h = c.get("/api/data/health").json()
    assert h["open_findings"] == 0 and h["score"] == 100
