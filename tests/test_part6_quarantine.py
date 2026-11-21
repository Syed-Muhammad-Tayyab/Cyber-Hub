"""
Cyber Hub Backend - Part 6 tests: Quarantine & Threat History
Developed by Syed Muhammad Tayyab

The EICAR test string is assembled at runtime so this file never trips a real antivirus.
"""
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services.malware_db import EICAR
from cyberhub.services.platform_tools import CACHE
from cyberhub.services.vault import CHUNK, KeyProtector, Vault, VaultError

PW = "Cyb3r!Hub#2026"
BAD = b"pretend this is ransomware"
BAD_SHA = hashlib.sha256(BAD).hexdigest()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    return tmp_path


def _client(env):
    CACHE.clear()
    return TestClient(create_app(Settings(), start_workers=False))


def _login(cl):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": "syed", "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with _client(env) as cl:
        _login(cl)
        cl.post("/api/scan/signatures", json={"hash": BAD_SHA, "name": "Ransom.Test", "severity": "critical"})
        yield cl
    CACHE.clear()


def make_zip(entries: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return b.getvalue()


@pytest.fixture()
def sample(env):
    d = env / "sample"
    d.mkdir()
    (d / "eicar.com").write_bytes(EICAR)
    (d / "ransom.exe").write_bytes(BAD)
    (d / "clean.txt").write_text("nothing to see here")
    (d / "bundle.zip").write_bytes(make_zip({"a.txt": b"hi", "x/eicar.com": EICAR, "y/bad.exe": BAD}))
    os.utime(d / "ransom.exe", (1_600_000_000, 1_600_000_000))
    return d


def scan(c, *paths):
    jid = c.post("/api/scan/custom", json={"paths": [str(p) for p in paths]}).json()["id"]
    end = time.time() + 30
    while time.time() < end:
        j = c.get(f"/api/scan/jobs/{jid}").json()
        if j["status"] in ("completed", "cancelled", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError("scan stuck")


def det_for(c, path, status="active"):
    items = c.get(f"/api/threats?status={status}&limit=500").json()["items"]
    return [d for d in items if d["path"] == str(path)]


def standard_user(c):
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    return {"X-CyberHub-Session": c.post("/api/account/login", json={"username": "kid", "password": PW}).json()["session_token"]}


# ================================================================== vault crypto
@pytest.mark.parametrize("size", [0, 1, 1000, CHUNK, CHUNK + 1, 2 * CHUNK + 12345])
def test_vault_roundtrip(tmp_path, size):
    v = Vault(tmp_path)
    src = tmp_path / "f.bin"
    data = os.urandom(size)
    src.write_bytes(data)
    qid, key = "a" * 32, os.urandom(32)
    r = v.encrypt_file(str(src), qid, key)
    assert r["sha256"] == hashlib.sha256(data).hexdigest() and r["size"] == size
    blob = v.path_for(qid).read_bytes()
    assert blob[:4] == b"CHQV" and (size < 16 or data[:16] not in blob)
    out = tmp_path / "out.bin"
    v.decrypt_to(qid, key, str(out), r["sha256"])
    assert out.read_bytes() == data
    assert not list(tmp_path.glob("*.chrestore")) and not list(v.dir.glob("*.part"))


def test_vault_detects_tampering(tmp_path):
    v = Vault(tmp_path)
    src = tmp_path / "f.bin"
    data = os.urandom(2 * CHUNK + 100)
    src.write_bytes(data)
    qid, key = "b" * 32, os.urandom(32)
    sha = v.encrypt_file(str(src), qid, key)["sha256"]
    p = v.path_for(qid)
    good = p.read_bytes()
    out = tmp_path / "out.bin"

    def bad(blob, k=key, item=qid):
        v.path_for(item).write_bytes(blob)
        with pytest.raises(VaultError):
            v.decrypt_to(item, k, str(out), sha)
        assert not out.exists()

    flipped = bytearray(good); flipped[CHUNK + 50] ^= 1
    bad(bytes(flipped))                                            # one bit changed
    bad(good[:16 + CHUNK + 16])                                    # truncated at a chunk boundary
    bad(good, k=os.urandom(32))                                    # wrong key
    v.path_for("c" * 32).write_bytes(good)                         # same file under another id (aad)
    with pytest.raises(VaultError):
        list(v.decrypt_chunks("c" * 32, key))
    p.write_bytes(good)
    assert v.verify(qid, key, sha)["ok"]
    with pytest.raises(VaultError):
        v.path_for("../x")


def test_vault_key_persistence_and_wrapping(tmp_path):
    v1 = Vault(tmp_path)
    assert v1.available and v1.key_protection == "file"
    wrapped = v1.wrap_key(b"k" * 32, "d" * 32)
    v2 = Vault(tmp_path)                                           # same key after restart
    assert v2.unwrap_key(wrapped, "d" * 32) == b"k" * 32
    with pytest.raises(VaultError):
        v2.unwrap_key(wrapped, "e" * 32)                           # bound to its item id
    with pytest.raises(VaultError):
        v2.unwrap_key(None, "d" * 32)
    if os.name == "posix":
        assert oct(os.stat(tmp_path / "vault.key").st_mode & 0o777) == "0o600"
    # damaged key file is reported, never silently replaced
    (tmp_path / "vault.key").write_text("garbage")
    v3 = Vault(tmp_path)
    assert not v3.available and "damaged" in v3.key_error
    assert (tmp_path / "vault.key").read_text() == "garbage"


def test_vault_sealed_key(tmp_path):
    xor = lambda b: bytes(x ^ 0x5A for x in b)
    prot = KeyProtector("dpapi", xor, xor)                          # stand-in for Windows DPAPI
    v1 = Vault(tmp_path, prot)
    meta = json.loads((tmp_path / "vault.key").read_text())
    assert meta["protection"] == "dpapi"
    w = v1.wrap_key(b"z" * 32, "f" * 32)
    assert Vault(tmp_path, prot).unwrap_key(w, "f" * 32) == b"z" * 32
    assert not Vault(tmp_path).available                            # plain protector can't open a sealed key


# ================================================================== quarantine / restore
def test_quarantine_and_restore_flow(c, sample, env):
    scan(c, sample)
    d = det_for(c, sample / "ransom.exe")[0]
    assert d["actions"] == ["quarantine", "remove", "allow", "dismiss"]
    r = c.post(f"/api/threats/{d['id']}/quarantine")
    assert r.status_code == 200, r.text
    item = r.json()
    assert item["status"] == "quarantined" and item["threat_name"] == "Ransom.Test" and item["severity"] == "critical"
    assert item["sha256"] == BAD_SHA and item["original_state"] == "removed" and d["id"] in item["detections"]
    assert not (sample / "ransom.exe").exists()
    vf = env / "data" / "quarantine" / f"{item['id']}.chq"
    assert vf.exists() and BAD not in vf.read_bytes()
    assert "wrapped_key" not in item
    assert c.post(f"/api/threats/{d['id']}/quarantine").status_code == 409

    det = c.get(f"/api/threats/{d['id']}").json()
    assert det["status"] == "quarantined" and det["quarantine_item"]["id"] == item["id"]
    assert [e["action"] for e in det["events"]] == ["detected", "quarantined"] and det["actions"] == ["restore", "delete"]

    assert c.post(f"/api/quarantine/{item['id']}/verify").json()["ok"]
    rs = c.post(f"/api/quarantine/{item['id']}/rescan").json()
    assert rs["still_detected"] and rs["detections"][0]["threat_name"] == "Ransom.Test"

    lst = c.get("/api/quarantine").json()
    assert lst["total"] == 1 and "expires_at" in lst["items"][0]
    st = c.get("/api/quarantine/stats").json()
    assert st["items"] == 1 and st["by_severity"]["critical"] == 1 and st["vault"]["files"] == 1

    r = c.post(f"/api/quarantine/{item['id']}/restore", json={}).json()
    assert r["restored_path"] == str(sample / "ransom.exe") and not r["allowed"] and r["warning"]
    assert (sample / "ransom.exe").read_bytes() == BAD
    assert int(os.stat(sample / "ransom.exe").st_mtime) == 1_600_000_000
    assert not vf.exists()
    assert c.get(f"/api/threats/{d['id']}").json()["status"] == "restored"
    assert c.post(f"/api/quarantine/{item['id']}/restore", json={}).status_code == 409
    assert det_for(c, sample / "ransom.exe", "restored")
    db = c.app.state.db
    assert db.fetchone("SELECT wrapped_key FROM quarantine_items WHERE id=?", (item["id"],))["wrapped_key"] is None

    scan(c, sample / "ransom.exe")                                 # not allowed -> detected again
    assert det_for(c, sample / "ransom.exe")


def test_restore_with_allow_and_unallow(c, sample):
    scan(c, sample / "ransom.exe")
    d = det_for(c, sample / "ransom.exe")[0]
    q = c.post(f"/api/threats/{d['id']}/quarantine").json()
    r = c.post(f"/api/quarantine/{q['id']}/restore", json={"allow": True}).json()
    assert r["allowed"] and r["allowed_entry"]["value"] == BAD_SHA and r["warning"] is None
    assert c.get(f"/api/threats/{d['id']}").json()["status"] == "allowed"
    j = scan(c, sample / "ransom.exe")
    assert j["threats_found"] == 0
    allowed = c.get("/api/threats/allowed").json()["items"]
    assert allowed[0]["hits"] >= 1
    assert c.post("/api/scan/self-test").json()["passed"]
    ev = c.get(f"/api/threats/{d['id']}").json()["events"]
    assert [e["action"] for e in ev] == ["detected", "quarantined", "restored", "allowed"]
    assert c.delete(f"/api/threats/allowed/{allowed[0]['id']}").status_code == 200
    assert scan(c, sample / "ransom.exe")["threats_found"] == 1


def test_restore_conflicts_and_destination(c, sample, env):
    p = sample / "ransom.exe"
    q = c.post("/api/quarantine", json={"path": str(p)}).json()
    assert q["threat_name"] == "Ransom.Test" and q["source"] == "manual"   # identified by scanning it
    p.write_text("a new file took its place")
    assert c.post(f"/api/quarantine/{q['id']}/restore", json={"conflict": "fail"}).status_code == 409
    r = c.post(f"/api/quarantine/{q['id']}/restore", json={"conflict": "rename"}).json()
    assert r["restored_path"] == str(sample / "ransom (restored).exe") and p.read_text().startswith("a new")

    q2 = c.post("/api/quarantine", json={"path": str(sample / "ransom (restored).exe")}).json()
    out = env / "restore-here"; out.mkdir()
    assert c.post(f"/api/quarantine/{q2['id']}/restore", json={"destination": str(env / 'nope')}).status_code == 404
    r = c.post(f"/api/quarantine/{q2['id']}/restore", json={"destination": str(out)}).json()
    assert (out / "ransom (restored).exe").read_bytes() == BAD

    q3 = c.post("/api/quarantine", json={"path": str(out / "ransom (restored).exe")}).json()
    (out / "ransom (restored).exe").write_text("x")
    r = c.post(f"/api/quarantine/{q3['id']}/restore", json={"conflict": "overwrite"}).json()
    assert (out / "ransom (restored).exe").read_bytes() == BAD


def test_restore_recreates_folder(c, env):
    d = env / "deep" / "er"; d.mkdir(parents=True)
    (d / "x.exe").write_bytes(BAD)
    q = c.post("/api/quarantine", json={"path": str(d / "x.exe")}).json()
    shutil.rmtree(env / "deep")
    c.post(f"/api/quarantine/{q['id']}/restore", json={})
    assert (d / "x.exe").read_bytes() == BAD


def test_delete_and_remove(c, sample, env):
    scan(c, sample)
    d = det_for(c, sample / "ransom.exe")[0]
    q = c.post(f"/api/threats/{d['id']}/quarantine").json()
    r = c.delete(f"/api/quarantine/{q['id']}").json()
    assert r["status"] == "deleted" and not r["can_restore"]
    assert not (env / "data" / "quarantine" / f"{q['id']}.chq").exists()
    assert c.post(f"/api/quarantine/{q['id']}/restore", json={}).status_code == 409
    assert c.delete(f"/api/quarantine/{q['id']}").status_code == 409
    assert c.get(f"/api/threats/{d['id']}").json()["status"] == "removed"

    e = det_for(c, sample / "eicar.com")[0]
    r = c.post(f"/api/threats/{e['id']}/remove")
    assert r.status_code == 200 and r.json()["status"] == "deleted"
    assert not (sample / "eicar.com").exists()
    assert [x["action"] for x in c.get(f"/api/threats/{e['id']}").json()["events"]] == ["detected", "quarantined", "removed"]
    assert c.get("/api/quarantine?status=deleted").json()["total"] == 2
    assert c.get("/api/scan/summary").json()["active_threats"] == 2      # zip members still active


def test_archive_quarantined_as_one_item(c, sample):
    scan(c, sample / "bundle.zip")
    dets = det_for(c, sample / "bundle.zip")
    assert len(dets) == 2 and {d["archive_member"] for d in dets} == {"x/eicar.com", "y/bad.exe"}
    q = c.post(f"/api/threats/{dets[0]['id']}/quarantine").json()
    assert sorted(q["detections"]) == sorted(d["id"] for d in dets)
    assert not det_for(c, sample / "bundle.zip")
    assert len(det_for(c, sample / "bundle.zip", "quarantined")) == 2
    det = c.get(f"/api/quarantine/{q['id']}").json()
    assert len(det["detections"]) == 2 and len(det["events"]) == 2
    assert c.post(f"/api/quarantine/{q['id']}/rescan").json()["still_detected"]
    c.post(f"/api/quarantine/{q['id']}/restore", json={})
    assert zipfile.ZipFile(sample / "bundle.zip").read("y/bad.exe") == BAD


def test_quarantine_guards(c, env, sample):
    assert c.post("/api/quarantine", json={"path": str(env / "missing.exe")}).status_code == 404
    assert c.post("/api/quarantine", json={"path": str(sample)}).status_code == 422          # a folder
    assert c.post("/api/quarantine", json={"path": str(env / "data" / "cyberhub.db")}).status_code == 403
    assert c.post("/api/quarantine", json={"path": str(env / "data" / "vault.key")}).status_code == 403
    import cyberhub
    own = os.path.join(os.path.dirname(cyberhub.__file__), "config.py")
    assert c.post("/api/quarantine", json={"path": own}).status_code == 403
    if os.name == "posix":
        os.symlink(sample / "clean.txt", sample / "link.txt")
        assert c.post("/api/quarantine", json={"path": str(sample / "link.txt")}).status_code == 422
        if os.path.isfile("/etc/hostname"):
            assert c.post("/api/quarantine", json={"path": "/etc/hostname"}).status_code == 409
    h = standard_user(c)
    assert c.post("/api/quarantine", headers=h, json={"path": str(sample / "clean.txt"), "force": True}).status_code == 403
    q = c.post("/api/quarantine", headers=h, json={"path": str(sample / "clean.txt"), "note": "looked odd"})
    assert q.status_code == 201
    q = q.json()
    assert q["threat_name"] == "Manually quarantined file" and q["severity"] == "medium" and q["note"] == "looked odd"
    assert q["quarantined_by"] == "kid"
    assert c.post(f"/api/quarantine/{q['id']}/restore", headers=h, json={}).status_code == 403   # admin only
    assert c.post("/api/quarantine/purge", headers=h, json={}).status_code == 403
    assert c.delete("/api/threats/history", headers=h).status_code == 403
    assert c.post("/api/threats/allowed", headers=h, json={"threat_name": "x"}).status_code == 403
    r = c.post("/api/threats/actions", headers=h, json={"action": "allow"})
    assert r.status_code == 403
    assert c.post(f"/api/quarantine/{q['id']}/verify", headers=h).json()["ok"]
    assert c.get("/api/quarantine/stats", headers={"X-CyberHub-Session": ""}).status_code == 401


@pytest.mark.skipif(os.name != "posix" or not shutil.which("sleep"), reason="needs a standalone 'sleep' binary")
def test_quarantine_stops_running_program(c, env):
    exe = env / "evil_sleeper"
    shutil.copy2(shutil.which("sleep"), exe)
    p = subprocess.Popen([str(exe), "60"])
    time.sleep(0.4)
    assert p.poll() is None
    try:
        q = c.post("/api/quarantine", json={"path": str(exe), "threat_name": "Trojan.Sleeper"}).json()
        assert [s["pid"] for s in q["stopped_processes"]] == [p.pid]
        assert p.wait(5) is not None and not exe.exists()
        r = c.post(f"/api/quarantine/{q['id']}/restore", json={}).json()
        assert os.access(r["restored_path"], os.X_OK)              # permissions come back too
    finally:
        if p.poll() is None:
            p.kill()


def test_auto_quarantine_policy(c, sample):
    assert c.patch("/api/settings", json={"scan_auto_quarantine": "sometimes"}).status_code == 422
    c.patch("/api/settings", json={"scan_auto_quarantine": "high"})
    j = scan(c, sample)
    assert j["threats_found"] == 4
    assert not (sample / "ransom.exe").exists() and not (sample / "bundle.zip").exists()   # critical inside
    assert (sample / "eicar.com").exists()                                                  # low: left alone
    items = c.get("/api/quarantine").json()["items"]
    assert {i["source"] for i in items} == {"auto"} and len(items) == 2
    assert c.get("/api/scan/summary").json()["active_threats"] == 1
    c.patch("/api/settings", json={"scan_auto_quarantine": "all"})
    r = c.post("/api/scan/file", json={"path": str(sample / "eicar.com")}).json()
    assert r["detections"][0]["status"] == "quarantined" and not (sample / "eicar.com").exists()
    acts = [a["title"] for a in c.get("/api/activity?category=threat").json()["items"]]
    assert any(t.startswith("Quarantined:") for t in acts)


def test_retention_and_size_limit(c, env):
    for i in range(3):
        (env / f"f{i}.bin").write_bytes(BAD + bytes([i]))
    ids = [c.post("/api/quarantine", json={"path": str(env / f"f{i}.bin")}).json()["id"] for i in range(3)]
    db, q = c.app.state.db, c.app.state.quarantine
    db.execute("UPDATE quarantine_items SET quarantined_at='2020-01-01T00:00:00.00Z' WHERE id=?", (ids[0],))
    assert q.enforce_limits() == 1
    assert c.get(f"/api/quarantine/{ids[0]}").json()["status"] == "deleted"
    c.patch("/api/settings", json={"quarantine_retention_days": 0})          # keep forever
    db.execute("UPDATE quarantine_items SET quarantined_at='2020-01-02T00:00:00.00Z' WHERE id=?", (ids[1],))
    assert q.enforce_limits() == 0
    c.patch("/api/settings", json={"quarantine_max_mb": 64})
    db.execute("UPDATE quarantine_items SET stored_size=? WHERE status='quarantined'", (40 * 1024 * 1024,))
    assert q.enforce_limits() == 1                                            # 80 MB > 64 MB: oldest goes
    assert c.get(f"/api/quarantine/{ids[1]}").json()["status"] == "deleted"
    assert c.get(f"/api/quarantine/{ids[2]}").json()["status"] == "quarantined"
    ev = c.get(f"/api/quarantine/{ids[1]}").json()["events"]
    assert ev[-1]["action"] == "purged" and ev[-1]["username"] == "size limit"
    assert c.post("/api/quarantine/purge", json={}).json()["deleted"] == 1
    assert c.get("/api/quarantine/stats").json()["items"] == 0


def test_tampered_item_cannot_be_restored(c, sample, env):
    q = c.post("/api/quarantine", json={"path": str(sample / "ransom.exe")}).json()
    vf = env / "data" / "quarantine" / f"{q['id']}.chq"
    b = bytearray(vf.read_bytes()); b[-5] ^= 0xFF; vf.write_bytes(bytes(b))
    v = c.post(f"/api/quarantine/{q['id']}/verify").json()
    assert not v["ok"] and "integrity" in v["message"]
    r = c.post(f"/api/quarantine/{q['id']}/restore", json={})
    assert r.status_code == 500 and not (sample / "ransom.exe").exists()
    assert not [f for f in os.listdir(sample) if f.endswith(".chrestore")]


def test_rescan_after_signature_removed(c, sample):
    q = c.post("/api/quarantine", json={"path": str(sample / "ransom.exe")}).json()
    c.delete(f"/api/scan/signatures/{BAD_SHA}")
    r = c.post(f"/api/quarantine/{q['id']}/rescan").json()
    assert not r["still_detected"] and "false alarm" in r["advice"]


def test_vault_check(c, sample, env):
    qdir = env / "data" / "quarantine"
    a = c.post("/api/quarantine", json={"path": str(sample / "ransom.exe")}).json()
    (qdir / f"{a['id']}.chq").unlink()
    (qdir / ("9" * 32 + ".chq")).write_bytes(b"orphan")
    (qdir / ("8" * 32 + ".part")).write_bytes(b"half")
    # an engine crash between "encrypted" and "original removed": original still there -> rolled back
    db = c.app.state.db
    db.execute("INSERT INTO quarantine_items(id, original_path, file_name, size, sha256, md5, threat_name, severity, "
               "original_state, quarantined_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
               ("7" * 32, str(sample / "clean.txt"), "clean.txt", 1, "x", "y", "t", "low", "removing", "syed"))
    r = c.post("/api/quarantine/vault/check").json()
    assert r == {"missing_items": 1, "orphan_files_removed": 1, "temp_files_removed": 1, "unfinished_rolled_back": 1}
    assert c.get(f"/api/quarantine/{a['id']}").json()["status"] == "missing"
    assert c.get("/api/quarantine/" + "7" * 32).status_code == 404
    assert c.delete(f"/api/quarantine/{a['id']}").json()["status"] == "deleted"


# ================================================================== threat history
def test_history_summary_export_bulk(c, sample):
    scan(c, sample)
    s = c.get("/api/threats/summary").json()
    assert s["active_threats"] == 4 and s["active_by_severity"]["critical"] == 2
    assert s["by_day"][-1]["detected"] == 4 and s["recommendation"].startswith("Quarantine")
    assert s["top_threats"][0]["n"] == 2 and s["top_locations"][0]["folder"] == str(sample)

    assert c.get("/api/threats?severity=critical").json()["total"] == 2
    assert c.get("/api/threats?search=bundle").json()["total"] == 2
    assert c.get(f"/api/threats?search={BAD_SHA}").json()["total"] == 2      # file + zip member
    assert c.get("/api/threats?days=1").json()["total"] == 4
    assert c.get("/api/threats?status=bogus").status_code == 422

    e = det_for(c, sample / "eicar.com")[0]
    a = c.post(f"/api/threats/{e['id']}/allow", json={"note": "lab file"}).json()
    zm = [d for d in det_for(c, sample / "bundle.zip", "allowed") if d["archive_member"] == "x/eicar.com"][0]
    assert a["created"] and sorted(a["detections_allowed"]) == sorted([e["id"], zm["id"]])   # same SHA-256 inside the zip
    assert c.post(f"/api/threats/{e['id']}/allow").json()["created"] is False

    r = c.post("/api/threats/actions", json={"action": "quarantine"}).json()      # "Start actions"
    assert r["requested"] == 2 and r["succeeded"] == 2 and r["failed"] == 0
    s = c.get("/api/threats/summary").json()
    assert s["active_threats"] == 0 and s["by_status"]["quarantined"] == 2 and s["by_status"]["allowed"] == 2
    assert s["handled_percent"] == 100.0
    assert s["by_day"][-1]["quarantined"] == 2 and s["by_day"][-1]["allowed"] == 2
    assert s["quarantine"]["items"] == 2 and s["recommendation"] == "No action needed"
    r = c.post("/api/threats/actions", json={"action": "dismiss", "ids": [e["id"], 99999]}).json()
    assert r["failed"] == 2 and {x["status"] for x in r["results"]} == {404, 409}

    csv_ = c.get("/api/threats/export.csv")
    assert csv_.headers["content-type"].startswith("text/csv")
    lines = csv_.text.strip().splitlines()
    assert lines[0].startswith("id,detected_at,threat_name") and len(lines) == 5

    for q in c.get("/api/quarantine").json()["items"]:
        c.delete(f"/api/quarantine/{q['id']}")
    r = c.delete("/api/threats/history").json()
    assert r["detections_deleted"] == 4 and r["quarantine_records_deleted"] == 2
    assert c.get("/api/threats?status=all").json()["total"] == 0
    assert c.get("/api/threats/allowed").json()["items"]                          # allow list survives


def test_csv_formula_injection_guard(c, env):
    (env / "x.exe").write_bytes(BAD)
    scan(c, env / "x.exe")
    db = c.app.state.db
    db.execute("UPDATE scan_detections SET threat_name='=HYPERLINK(\"x\")'")
    text = c.get("/api/threats/export.csv").text
    assert "'=HYPERLINK" in text


def test_allowed_by_threat_name(c, sample):
    assert c.post("/api/threats/allowed", json={}).status_code == 422
    assert c.post("/api/threats/allowed", json={"sha256": "z" * 64}).status_code == 422
    e = c.post("/api/threats/allowed", json={"threat_name": "EICAR-Test-File (not a virus)"})
    assert e.status_code == 201
    j = scan(c, sample)
    assert j["threats_found"] == 2                                   # only Ransom.Test (file + zip member)
    assert c.post("/api/scan/self-test").json()["passed"]          # self-test ignores the allow list
    assert c.get("/api/threats/allowed").json()["items"][0]["hits"] >= 2


def test_websocket_events(c, sample):
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    scan(c, sample / "ransom.exe")
    d = det_for(c, sample / "ransom.exe")[0]
    with c.websocket_connect(f"/api/scan/stream?token={tok}&session={ses}") as ws:
        assert ws.receive_json()["hello"]
        c.post(f"/api/threats/{d['id']}/quarantine")
        types = []
        for _ in range(4):
            types += [e["type"] for e in ws.receive_json()["events"]]
            if "quarantined" in types:
                break
        assert "quarantined" in types


def test_quarantine_without_vault_key(env, sample):
    (env / "data").mkdir(parents=True, exist_ok=True)
    (env / "data" / "vault.key").write_text("{broken")
    with _client(env) as cl:
        _login(cl)
        r = cl.post("/api/quarantine", json={"path": str(sample / "ransom.exe")})
        assert r.status_code == 503 and (sample / "ransom.exe").exists()
        assert cl.get("/api/quarantine/stats").json()["vault"]["available"] is False


def test_persists_across_restart(env, sample):
    with _client(env) as cl:
        _login(cl)
        qid = cl.post("/api/quarantine", json={"path": str(sample / "ransom.exe")}).json()["id"]
    with _client(env) as cl:
        _login(cl)
        cl.post(f"/api/quarantine/{qid}/restore", json={})
        assert (sample / "ransom.exe").read_bytes() == BAD


# ================================================================== schema / info
def test_migration_from_v6_backfills_history(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)")
    for v, d, sql in MIGRATIONS[:6]:
        con.executescript(sql)
        con.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    con.execute("INSERT INTO scan_detections(path, threat_name, severity, method, status, status_changed_at, status_by) "
                "VALUES ('/x', 'T', 'low', 'hash', 'dismissed', '2026-01-02T00:00:00Z', 'syed')")
    con.commit(); con.close()
    db = Database(path)
    assert db.migrate() >= 7
    ev = db.fetchall("SELECT action, username FROM threat_events ORDER BY id")
    assert ev == [{"action": "detected", "username": None}, {"action": "dismissed", "username": "syed"}]
    names = {r["name"] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"quarantine_items", "allowed_threats", "threat_events"} <= names
    db.close()


def test_info_reports_part6(c):
    j = c.get("/api/info").json()
    assert j["build_part"] >= 6 and j["progress_percent"] >= 30 and "quarantine" in j["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 7
    s = c.get("/api/settings").json()
    assert s["scan_auto_quarantine"] == "off" and s["quarantine_retention_days"] == 30
